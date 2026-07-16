use std::env;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

use crate::setup::{SetupPaths, validate_existing_path_components, validate_lima_instance};
use crate::{UninstallArgs, current_uid};

const REPORT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PlanStatus {
    Present,
    Missing,
    RefusedUnsafe,
    Error,
}

impl PlanStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
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
    let report = build_plan(
        &paths.home,
        &paths.data,
        &paths.config,
        &args.lima_instance,
        env::consts::OS,
    )?;
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
        "Guard audits, pending changes, verified tools, remembered egress decisions, and Grok session snapshots",
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
        items: vec![data_item, config_item],
        manual_steps,
    }
    .finish())
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
    println!("mode: dry-run (this command never deletes files)");
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
    if report.plan_is_safe {
        println!("uninstall plan: safe roots identified; no files were deleted");
    } else {
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
        assert_eq!(json["schema"], 1);
        assert_eq!(json["mode"], "dry-run");
        assert_eq!(json["plan_is_safe"], true);
        assert_eq!(report.exit_code(), 0);
    }
}
