use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sandbox_guard_core::{default_staging_base, garbage_collect};
use serde::Serialize;
use uuid::Uuid;

use crate::setup::{SetupPaths, validate_existing_path_components, validate_lima_instance};
use crate::{UninstallArgs, current_uid};

const REPORT_SCHEMA: u32 = 2;
const CONFIRMATION_PHRASE: &str = "DELETE GUARD STATE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PlanStatus {
    Present,
    Missing,
    Removed,
    SkippedActive,
    Declined,
    RefusedUnsafe,
    Error,
}

impl PlanStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::Removed => "removed",
            Self::SkippedActive => "skipped-active",
            Self::Declined => "declined",
            Self::RefusedUnsafe => "refused-unsafe",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct PlanItem {
    id: String,
    path: PathBuf,
    kind: String,
    status: PlanStatus,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate_of: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ManualStep {
    id: String,
    detail: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    commands: Vec<String>,
    requires: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct UninstallReport {
    schema: u32,
    mode: String,
    platform: String,
    plan_is_safe: bool,
    removal_completed: bool,
    stages_removed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    items: Vec<PlanItem>,
    manual_steps: Vec<ManualStep>,
}

impl UninstallReport {
    fn finish(mut self) -> Self {
        self.plan_is_safe = self
            .items
            .iter()
            .all(|item| matches!(item.status, PlanStatus::Present | PlanStatus::Missing));
        self
    }

    fn exit_code(&self) -> i32 {
        if self
            .items
            .iter()
            .any(|item| item.status == PlanStatus::Error)
        {
            3
        } else if self.mode == "remove" {
            i32::from(!self.removal_completed)
        } else if self.plan_is_safe {
            0
        } else {
            1
        }
    }
}

pub(super) fn uninstall_command(args: UninstallArgs) -> Result<i32> {
    validate_lima_instance(&args.lima_instance)?;
    let paths = SetupPaths::discover()?;
    let mut report = build_plan(
        &paths.home,
        &paths.data,
        &paths.config,
        &args.lima_instance,
        env::consts::OS,
    )?;
    if args.remove {
        report.mode = "remove".to_owned();
        if !report.plan_is_safe {
            report.message = Some(
                "removal refused because one or more Guard-owned roots failed validation"
                    .to_owned(),
            );
        } else if args.yes || confirm_removal(args.json)? {
            execute_removal(
                &mut report,
                &paths.home,
                &paths.data,
                &paths.config,
                &default_staging_base(),
            )?;
        } else {
            for item in &mut report.items {
                if item.status == PlanStatus::Present {
                    item.status = PlanStatus::Declined;
                }
            }
            report.message = Some("removal was not confirmed; nothing was deleted".to_owned());
        }
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_human(&report);
    }
    Ok(report.exit_code())
}

fn build_plan(
    home: &Path,
    data: &Path,
    config: &Path,
    lima_instance: &str,
    platform: &str,
) -> Result<UninstallReport> {
    validate_lima_instance(lima_instance)?;
    let data_item = inspect_root(
        "state.data",
        data,
        home,
        "Guard audits, bounded event index, pending changes, verified tools, installed signed profiles, remembered egress decisions, and Grok session snapshots",
        None,
    );
    let config_duplicate = (config == data).then(|| "state.data".to_owned());
    let config_item = inspect_root(
        "state.config",
        config,
        home,
        "Guard user policy and configuration",
        config_duplicate,
    );

    let mut manual_steps = Vec::new();
    if let Ok(executable) = env::current_exe() {
        let helper = executable.with_file_name("guard-helper");
        let mut commands = vec![format!("rm -- {}", shell_path(&executable))];
        if helper.is_file() {
            commands.push(format!("rm -- {}", shell_path(&helper)));
        }
        manual_steps.push(ManualStep {
            id: "installed-binaries".to_owned(),
            detail: "Remove installed binaries manually after Guard state removal; this plan never deletes the running executable. If guard-helper is not beside guard, locate it with `command -v guard-helper`."
                .to_owned(),
            commands,
            requires: vec!["confirmation".to_owned()],
        });
    }
    if platform == "macos" {
        manual_steps.push(ManualStep {
            id: "lima-instance".to_owned(),
            detail: "Inspect the dedicated VM before deleting it. Guard cannot prove that it contains no unrelated user data."
                .to_owned(),
            commands: vec![format!("limactl delete {lima_instance}")],
            requires: vec!["confirmation".to_owned()],
        });
    }
    manual_steps.push(ManualStep {
        id: "stale-stages".to_owned(),
        detail: "Inspect and remove unlocked stale stages through Guard's advisory-lock-aware garbage collector."
            .to_owned(),
        commands: vec!["guard gc --dry-run".to_owned(), "guard gc".to_owned()],
        requires: vec!["confirmation".to_owned()],
    });
    manual_steps.push(ManualStep {
        id: "vendor-state".to_owned(),
        detail: "Host vendor state such as ~/.grok is outside Guard ownership and is never included in removal."
            .to_owned(),
        commands: Vec::new(),
        requires: Vec::new(),
    });

    Ok(UninstallReport {
        schema: REPORT_SCHEMA,
        mode: "dry-run".to_owned(),
        platform: format!("{}-{}", platform, env::consts::ARCH),
        plan_is_safe: false,
        removal_completed: false,
        stages_removed: 0,
        message: None,
        items: vec![data_item, config_item],
        manual_steps,
    }
    .finish())
}

fn confirm_removal(json: bool) -> Result<bool> {
    if json || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Ok(false);
    }
    print!("Type {CONFIRMATION_PHRASE:?} to remove the validated Guard-owned state: ");
    io::stdout()
        .flush()
        .context("flush uninstall confirmation")?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0 {
        return Ok(false);
    }
    Ok(answer.trim_end_matches(['\r', '\n']) == CONFIRMATION_PHRASE)
}

fn execute_removal(
    report: &mut UninstallReport,
    home: &Path,
    data: &Path,
    config: &Path,
    staging_base: &Path,
) -> Result<()> {
    let stage_report = match garbage_collect(staging_base, Duration::ZERO, true) {
        Ok(report) => report,
        Err(error) => {
            mark_present_items(report, PlanStatus::Error);
            report.message = Some(format!(
                "could not inspect active Guard stages; nothing was deleted: {error}"
            ));
            return Ok(());
        }
    };
    if !stage_report.active.is_empty() {
        mark_present_items(report, PlanStatus::SkippedActive);
        report.message = Some(format!(
            "{} active Guard stage(s) are locked; nothing was deleted",
            stage_report.active.len()
        ));
        return Ok(());
    }

    let mut unique = Vec::new();
    let mut seen = BTreeSet::new();
    for path in [data, config] {
        if !seen.insert(path.to_path_buf()) {
            continue;
        }
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                mark_path_items(report, path, PlanStatus::Error);
                report.message = Some(format!(
                    "could not reinspect a removal root; nothing was deleted: {error}"
                ));
                return Ok(());
            }
        }
        match ValidatedRoot::open(path, home) {
            Ok(root) => unique.push(root),
            Err(error) => {
                mark_path_items(report, path, PlanStatus::RefusedUnsafe);
                report.message = Some(format!(
                    "removal root changed or failed revalidation; nothing was deleted: {error:#}"
                ));
                return Ok(());
            }
        }
    }

    let _decision_lock = match acquire_existing_decision_lock(&data.join("egress-decisions.lock")) {
        Ok(ExistingLock::Acquired(lock)) => Some(lock),
        Ok(ExistingLock::Missing) => None,
        Ok(ExistingLock::Busy) => {
            mark_present_items(report, PlanStatus::SkippedActive);
            report.message =
                Some("remembered egress decisions are in use; nothing was deleted".to_owned());
            return Ok(());
        }
        Err(error) => {
            mark_present_items(report, PlanStatus::Error);
            report.message = Some(format!(
                "could not validate the egress decision lock; nothing was deleted: {error:#}"
            ));
            return Ok(());
        }
    };

    let mut renamed = Vec::new();
    for root in &unique {
        match root.rename_to_tombstone() {
            Ok(tombstone) => renamed.push(tombstone),
            Err(error) => {
                let rollback = rollback_tombstones(&renamed);
                mark_present_items(report, PlanStatus::Error);
                report.message = Some(match rollback {
                    Ok(()) => format!(
                        "could not atomically isolate every removal root; prior renames were rolled back: {error:#}"
                    ),
                    Err(rollback) => format!(
                        "could not isolate every removal root and rollback was incomplete: {error:#}; rollback: {rollback:#}"
                    ),
                });
                return Ok(());
            }
        }
    }

    let mut failures = Vec::new();
    for tombstone in &renamed {
        if let Err(error) = fs::remove_dir_all(&tombstone.tombstone) {
            failures.push(format!("{}: {error}", tombstone.tombstone.display()));
            mark_path_items(report, &tombstone.original, PlanStatus::Error);
        } else {
            mark_path_items(report, &tombstone.original, PlanStatus::Removed);
        }
    }
    if failures.is_empty() {
        report.removal_completed = true;
        report.message = Some(if renamed.is_empty() {
            "no Guard-owned state roots were present".to_owned()
        } else {
            format!("removed {} unique Guard-owned state root(s)", renamed.len())
        });
    } else {
        report.message = Some(format!(
            "state roots were isolated, but {} tombstone cleanup(s) failed: {}",
            failures.len(),
            failures.join("; ")
        ));
    }
    Ok(())
}

fn mark_present_items(report: &mut UninstallReport, status: PlanStatus) {
    for item in &mut report.items {
        if item.status == PlanStatus::Present {
            item.status = status;
        }
    }
}

fn mark_path_items(report: &mut UninstallReport, path: &Path, status: PlanStatus) {
    for item in &mut report.items {
        if item.path == path && item.status == PlanStatus::Present {
            item.status = status;
        }
    }
}

enum ExistingLock {
    Missing,
    Acquired(File),
    Busy,
}

fn acquire_existing_decision_lock(path: &Path) -> Result<ExistingLock> {
    let lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ExistingLock::Missing);
        }
        Err(error) => return Err(error).context("open existing egress decision lock"),
    };
    let metadata = lock.metadata().context("inspect egress decision lock")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() != 0
    {
        bail!("egress decision lock is not a private singly linked empty regular file");
    }
    // SAFETY: flock receives a valid owned descriptor and does not retain pointers.
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(ExistingLock::Acquired(lock));
    }
    let error = std::io::Error::last_os_error();
    if error
        .raw_os_error()
        .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
    {
        Ok(ExistingLock::Busy)
    } else {
        Err(error).context("lock existing egress decision store")
    }
}

struct ValidatedRoot {
    path: PathBuf,
    device: u64,
    inode: u64,
    _directory: File,
}

impl ValidatedRoot {
    fn open(path: &Path, home: &Path) -> Result<Self> {
        validate_existing_path_components(path, home)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open removal root {}", path.display()))?;
        let metadata = directory
            .metadata()
            .with_context(|| format!("inspect opened removal root {}", path.display()))?;
        if !metadata.is_dir()
            || metadata.uid() != current_uid()
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("opened removal root is not a private owner-controlled directory");
        }
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            _directory: directory,
        })
    }

    fn rename_to_tombstone(&self) -> Result<RenamedRoot> {
        let parent = self
            .path
            .parent()
            .context("removal root has no parent directory")?;
        let tombstone = parent.join(format!(
            ".sandbox-guard-remove-{}",
            Uuid::new_v4().as_simple()
        ));
        if fs::symlink_metadata(&tombstone).is_ok() {
            bail!("fresh removal tombstone unexpectedly exists");
        }
        fs::rename(&self.path, &tombstone).with_context(|| {
            format!(
                "rename removal root {} to private tombstone",
                self.path.display()
            )
        })?;
        let metadata = fs::symlink_metadata(&tombstone)
            .with_context(|| format!("inspect removal tombstone {}", tombstone.display()))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != current_uid()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            let _ = fs::rename(&tombstone, &self.path);
            bail!("removal tombstone identity did not match the validated root");
        }
        Ok(RenamedRoot {
            original: self.path.clone(),
            tombstone,
        })
    }
}

struct RenamedRoot {
    original: PathBuf,
    tombstone: PathBuf,
}

fn rollback_tombstones(renamed: &[RenamedRoot]) -> Result<()> {
    for root in renamed.iter().rev() {
        if fs::symlink_metadata(&root.original).is_ok() {
            bail!(
                "cannot restore {} because the original path was recreated",
                root.original.display()
            );
        }
        fs::rename(&root.tombstone, &root.original).with_context(|| {
            format!(
                "restore removal root {} from tombstone",
                root.original.display()
            )
        })?;
    }
    Ok(())
}

fn inspect_root(
    id: &str,
    path: &Path,
    home: &Path,
    contents: &str,
    duplicate_of: Option<String>,
) -> PlanItem {
    let base = |status, detail| PlanItem {
        id: id.to_owned(),
        path: path.to_path_buf(),
        kind: "guard-owned-directory".to_owned(),
        status,
        detail,
        duplicate_of: duplicate_of.clone(),
    };
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return base(PlanStatus::Missing, "nothing to remove".to_owned());
        }
        Err(error) => {
            return base(
                PlanStatus::Error,
                format!("could not inspect removal root: {error}"),
            );
        }
        Ok(metadata)
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != current_uid() =>
        {
            return base(
                PlanStatus::RefusedUnsafe,
                "path is not an owner-controlled, non-symlink directory".to_owned(),
            );
        }
        Ok(metadata) if metadata.permissions().mode() & 0o077 != 0 => {
            return base(
                PlanStatus::RefusedUnsafe,
                format!(
                    "directory mode {:o} is broader than owner-only; run guard setup before removal",
                    metadata.permissions().mode() & 0o777
                ),
            );
        }
        Ok(_) => {}
    }

    if let Err(error) = validate_existing_path_components(path, home) {
        return base(PlanStatus::RefusedUnsafe, error.to_string());
    }
    let directory = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(directory) => directory,
        Err(error) => {
            let status = if error
                .raw_os_error()
                .is_some_and(|code| code == libc::ELOOP || code == libc::ENOTDIR)
            {
                PlanStatus::RefusedUnsafe
            } else {
                PlanStatus::Error
            };
            return base(
                status,
                format!("could not safely open removal root: {error}"),
            );
        }
    };
    let metadata = match directory.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return base(
                PlanStatus::Error,
                format!("could not inspect opened removal root: {error}"),
            );
        }
    };
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return base(
            PlanStatus::RefusedUnsafe,
            "opened removal root failed owner, type, or mode revalidation".to_owned(),
        );
    }
    // This fd proves only the dry-run plan. A deletion engine must re-open and revalidate the
    // root at act time; `plan_is_safe` is never authorization or a durable capability.
    base(PlanStatus::Present, contents.to_owned())
}

fn render_human(report: &UninstallReport) {
    println!("platform: {}", report.platform);
    if report.mode == "dry-run" {
        println!("mode: dry-run (this command never deletes files)");
    } else {
        println!("mode: confirmed removal");
    }
    for item in &report.items {
        let duplicate = item
            .duplicate_of
            .as_ref()
            .map(|id| format!("; same path as {id}"))
            .unwrap_or_default();
        println!(
            "[{}] {}: {} [{}{}]",
            item.status.as_str(),
            item.id,
            item.detail,
            item.path.display(),
            duplicate
        );
    }
    println!("manual steps (never executed by this command):");
    for step in &report.manual_steps {
        println!("- {}: {}", step.id, step.detail);
        for command in &step.commands {
            println!("    {command}");
        }
    }
    if let Some(message) = &report.message {
        println!("uninstall: {message}");
    } else if report.mode == "dry-run" && report.plan_is_safe {
        println!("uninstall plan: safe roots identified; no files were deleted");
    } else if report.mode == "dry-run" {
        println!("uninstall plan: refused or incomplete; no files were deleted");
    }
}

fn shell_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::symlink;

    #[test]
    fn dry_run_identifies_only_guard_roots_and_changes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let data = home.join("data/sandbox-guard");
        let config = home.join("config/sandbox-guard");
        fs::create_dir_all(data.join("audit")).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::write(data.join("audit/run.json"), b"audit").unwrap();
        fs::write(config.join("policy.toml"), b"policy").unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        let sibling = home.join("keep-me");
        fs::write(&sibling, b"canary").unwrap();

        let report = build_plan(&home, &data, &config, "sandbox-guard", "linux").unwrap();
        assert!(report.plan_is_safe);
        assert_eq!(report.exit_code(), 0);
        assert!(data.join("audit/run.json").is_file());
        assert!(config.join("policy.toml").is_file());
        assert_eq!(fs::read(&sibling).unwrap(), b"canary");
    }

    #[test]
    fn symlinked_root_is_refused_without_inspecting_or_touching_target() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let target = home.join("target");
        let data = home.join("data");
        let config = home.join("config");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(target.join("secret"), b"untouched").unwrap();
        symlink(&target, &data).unwrap();

        let report = build_plan(&home, &data, &config, "sandbox-guard", "linux").unwrap();
        let item = report
            .items
            .iter()
            .find(|item| item.id == "state.data")
            .unwrap();
        assert_eq!(item.status, PlanStatus::RefusedUnsafe);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(fs::read(target.join("secret")).unwrap(), b"untouched");
    }

    #[test]
    fn broadly_accessible_root_is_refused_until_setup_secures_it() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let data = home.join("data");
        let config = home.join("config");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();

        let report = build_plan(&home, &data, &config, "sandbox-guard", "linux").unwrap();
        let data = report
            .items
            .iter()
            .find(|item| item.id == "state.data")
            .unwrap();
        assert_eq!(data.status, PlanStatus::RefusedUnsafe);
        assert!(data.detail.contains("run guard setup"));
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn coincident_macos_roots_are_reported_as_one_physical_target() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let root = home.join("Library/Application Support/com.xbtoshi.sandbox-guard");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let report = build_plan(&home, &root, &root, "sandbox-guard", "macos").unwrap();
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.items[1].duplicate_of.as_deref(), Some("state.data"));
        assert_eq!(
            report
                .items
                .iter()
                .map(|item| &item.path)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            1
        );
    }

    #[test]
    fn json_schema_and_exit_mapping_are_stable() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();
        let report = build_plan(
            &home,
            &home.join("missing-data"),
            &home.join("missing-config"),
            "sandbox-guard",
            "linux",
        )
        .unwrap();
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema"], 2);
        assert_eq!(json["mode"], "dry-run");
        assert_eq!(json["plan_is_safe"], true);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn confirmed_engine_removes_only_validated_roots() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let data = home.join("data/sandbox-guard");
        let config = home.join("config/sandbox-guard");
        let staging = temp.path().join("staging");
        fs::create_dir_all(data.join("audit")).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(data.join("audit/run.json"), b"audit").unwrap();
        fs::write(config.join("policy.toml"), b"policy").unwrap();
        let canary = home.join("keep-me");
        fs::write(&canary, b"untouched").unwrap();

        let mut report = build_plan(&home, &data, &config, "sandbox-guard", "linux").unwrap();
        report.mode = "remove".to_owned();
        execute_removal(&mut report, &home, &data, &config, &staging).unwrap();

        assert!(report.removal_completed);
        assert_eq!(report.exit_code(), 0);
        assert!(!data.exists());
        assert!(!config.exists());
        assert_eq!(fs::read(&canary).unwrap(), b"untouched");
        assert!(
            report
                .items
                .iter()
                .all(|item| item.status == PlanStatus::Removed)
        );
    }

    #[test]
    fn active_stage_blocks_every_state_root_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let data = home.join("data");
        let config = home.join("config");
        let staging = temp.path().join("staging");
        let active = staging.join("sandbox-guard-active");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&active).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(active.join(".lock"))
            .unwrap();
        // SAFETY: flock receives the live test file descriptor.
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

        let mut report = build_plan(&home, &data, &config, "sandbox-guard", "linux").unwrap();
        report.mode = "remove".to_owned();
        execute_removal(&mut report, &home, &data, &config, &staging).unwrap();

        assert!(!report.removal_completed);
        assert_eq!(report.exit_code(), 1);
        assert!(data.is_dir());
        assert!(config.is_dir());
        assert!(
            report
                .items
                .iter()
                .all(|item| item.status == PlanStatus::SkippedActive)
        );
    }

    #[test]
    fn busy_decision_lock_blocks_every_state_root_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let data = home.join("data");
        let config = home.join("config");
        let staging = temp.path().join("staging");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(data.join("egress-decisions.lock"))
            .unwrap();
        // SAFETY: flock receives the live test file descriptor.
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

        let mut report = build_plan(&home, &data, &config, "sandbox-guard", "linux").unwrap();
        report.mode = "remove".to_owned();
        execute_removal(&mut report, &home, &data, &config, &staging).unwrap();

        assert!(!report.removal_completed);
        assert_eq!(report.exit_code(), 1);
        assert!(data.is_dir());
        assert!(config.is_dir());
    }

    #[test]
    fn revalidation_failure_aborts_before_any_root_is_renamed() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let data = home.join("data");
        let config = home.join("config");
        let outside = home.join("outside");
        let staging = temp.path().join("staging");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(data.join("keep"), b"data").unwrap();
        fs::write(outside.join("keep"), b"outside").unwrap();

        let mut report = build_plan(&home, &data, &config, "sandbox-guard", "linux").unwrap();
        fs::remove_dir(&config).unwrap();
        symlink(&outside, &config).unwrap();
        report.mode = "remove".to_owned();
        execute_removal(&mut report, &home, &data, &config, &staging).unwrap();

        assert!(!report.removal_completed);
        assert!(data.join("keep").is_file());
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"outside");
        assert!(
            fs::symlink_metadata(&config)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn second_root_rename_failure_rolls_back_the_first_root() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let data_parent = home.join("data-parent");
        let config_parent = home.join("config-parent");
        let data = data_parent.join("sandbox-guard");
        let config = config_parent.join("sandbox-guard");
        let staging = temp.path().join("staging");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(data.join("keep"), b"data").unwrap();
        fs::write(config.join("keep"), b"config").unwrap();

        let mut report = build_plan(&home, &data, &config, "sandbox-guard", "linux").unwrap();
        report.mode = "remove".to_owned();
        fs::set_permissions(&config_parent, fs::Permissions::from_mode(0o500)).unwrap();
        execute_removal(&mut report, &home, &data, &config, &staging).unwrap();
        fs::set_permissions(&config_parent, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(!report.removal_completed);
        assert_eq!(report.exit_code(), 3);
        assert_eq!(fs::read(data.join("keep")).unwrap(), b"data");
        assert_eq!(fs::read(config.join("keep")).unwrap(), b"config");
        assert!(
            report
                .message
                .as_deref()
                .is_some_and(|message| message.contains("prior renames were rolled back"))
        );
        assert!(fs::read_dir(&data_parent).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".sandbox-guard-remove-")
        }));
    }
}
