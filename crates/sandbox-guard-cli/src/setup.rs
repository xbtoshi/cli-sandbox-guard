use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use directories::{BaseDirs, ProjectDirs};
use sandbox_guard_core::CompiledPolicy;
use sandbox_guard_runner::BackendKind;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use crate::{SetupArgs, current_uid};

const REPORT_SCHEMA: u32 = 1;
const DEFAULT_GUEST_HELPER: &str = "/usr/local/bin/guard-helper";
/// Fixed absolute bubblewrap path the runtime invokes at the clean-environment boundary; the guest
/// diagnostic requires this exact executable.
const GUEST_BWRAP: &str = "/usr/bin/bwrap";
const GUEST_TEST: &str = "/usr/bin/test";
const GUEST_SUDO: &str = "/usr/bin/sudo";
const GUEST_ENV: &str = "/usr/bin/env";
const GUEST_APT_GET: &str = "/usr/bin/apt-get";
const GUEST_FINDMNT: &str = "/usr/bin/findmnt";
const GUEST_INSTALL: &str = "/usr/bin/install";
const GUEST_MV: &str = "/usr/bin/mv";
const GUEST_RM: &str = "/usr/bin/rm";
const GUEST_SHA256SUM: &str = "/usr/bin/sha256sum";
const GUEST_STAT: &str = "/usr/bin/stat";
const GUEST_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";
const MAX_GUEST_HELPER_BYTES: u64 = 128 * 1024 * 1024;
const GUEST_PACKAGE_EXECUTABLES: &[(&str, &str)] = &[
    ("bubblewrap", GUEST_BWRAP),
    ("git", "/usr/bin/git"),
    ("rsync", "/usr/bin/rsync"),
    ("findmnt", GUEST_FINDMNT),
];
const GUEST_PACKAGE_NAMES: &[&str] = &[
    "bubblewrap",
    "git",
    "ca-certificates",
    "rsync",
    "util-linux",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CheckStatus {
    Ok,
    Missing,
    Mismatch,
    Misconfigured,
    Unsafe,
    Unverifiable,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RepairKind {
    Auto,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Repair {
    kind: RepairKind,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    requires: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    commands: Vec<String>,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct SetupCheck {
    id: String,
    component: String,
    required: bool,
    status: CheckStatus,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair: Option<Repair>,
}

#[derive(Debug, Clone, Serialize)]
struct SetupReport {
    schema: u32,
    platform: String,
    backend: BackendKind,
    ready: bool,
    checks: Vec<SetupCheck>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actions_taken: Vec<String>,
}

impl SetupReport {
    fn finish(mut self) -> Self {
        self.ready = self
            .checks
            .iter()
            .filter(|check| check.required)
            .all(|check| check.status == CheckStatus::Ok);
        self
    }

    fn exit_code(&self) -> i32 {
        if self
            .checks
            .iter()
            .any(|check| check.required && check.status == CheckStatus::Error)
        {
            3
        } else if self.ready {
            0
        } else {
            1
        }
    }
}

impl CheckStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::Mismatch => "mismatch",
            Self::Misconfigured => "misconfigured",
            Self::Unsafe => "unsafe",
            Self::Unverifiable => "unverifiable",
            Self::Error => "error",
        }
    }
}

impl RepairKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct SetupPaths {
    pub(super) home: PathBuf,
    pub(super) data: PathBuf,
    pub(super) config: PathBuf,
    audit: PathBuf,
    events: PathBuf,
    pending_changes: PathBuf,
    tools: PathBuf,
}

impl SetupPaths {
    pub(super) fn discover() -> Result<Self> {
        let base =
            BaseDirs::new().ok_or_else(|| anyhow!("could not determine the home directory"))?;
        let project = ProjectDirs::from("com", "xbtoshi", "sandbox-guard")
            .ok_or_else(|| anyhow!("could not determine Guard state directories"))?;
        let data = project.data_local_dir().to_path_buf();
        let config = project.config_dir().to_path_buf();
        Ok(Self {
            home: base.home_dir().to_path_buf(),
            audit: data.join("audit"),
            events: data.join("events"),
            pending_changes: data.join("pending-changes"),
            tools: data.join("tools"),
            data,
            config,
        })
    }

    fn private_directories(&self) -> [(&'static str, &Path); 6] {
        [
            ("state.data.private", &self.data),
            ("state.config.private", &self.config),
            ("state.audit.private", &self.audit),
            ("state.events.private", &self.events),
            ("state.pending-changes.private", &self.pending_changes),
            ("state.tools.private", &self.tools),
        ]
    }
}

#[derive(Debug, Clone)]
struct ProbeOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct GuestHelperSnapshot {
    path: PathBuf,
    _private_directory: Option<TempDir>,
    _home_anchor: Option<File>,
}

trait SetupProbes {
    fn which(&self, name: &str) -> Option<PathBuf>;
    fn host_helper_path(&self) -> Option<PathBuf>;
    fn output(&self, program: &Path, args: &[OsString]) -> std::io::Result<ProbeOutput>;
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
    fn openat2_available(&self) -> std::result::Result<bool, String>;
    fn snapshot_guest_helper(
        &self,
        artifact: &Path,
        expected_sha256: &[u8; 32],
    ) -> Result<GuestHelperSnapshot>;
    fn guest_helper_temp_path(&self) -> String;
}

struct SystemProbes;

impl SetupProbes for SystemProbes {
    fn which(&self, name: &str) -> Option<PathBuf> {
        which::which(name).ok()
    }

    fn host_helper_path(&self) -> Option<PathBuf> {
        env::current_exe()
            .ok()
            .map(|path| path.with_file_name("guard-helper"))
            .filter(|path| path.is_file())
            .or_else(|| self.which("guard-helper"))
    }

    fn output(&self, program: &Path, args: &[OsString]) -> std::io::Result<ProbeOutput> {
        Command::new(program)
            .args(args)
            .output()
            .map(|output| ProbeOutput {
                success: output.status.success(),
                stdout: output.stdout,
                stderr: output.stderr,
            })
    }

    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        fs::read_to_string(path)
    }

    fn openat2_available(&self) -> std::result::Result<bool, String> {
        probe_openat2()
    }

    fn snapshot_guest_helper(
        &self,
        artifact: &Path,
        expected_sha256: &[u8; 32],
    ) -> Result<GuestHelperSnapshot> {
        let base = BaseDirs::new().ok_or_else(|| anyhow!("could not determine HOME"))?;
        create_guest_helper_snapshot_in(artifact, expected_sha256, base.home_dir())
    }

    fn guest_helper_temp_path(&self) -> String {
        format!("/tmp/guard-helper.{}", Uuid::new_v4().simple())
    }
}

pub(super) fn setup_command(args: SetupArgs) -> Result<i32> {
    validate_lima_instance(&args.lima_instance)?;
    let backend: BackendKind = args.backend.into();
    let backend = backend.resolve()?;
    let paths = SetupPaths::discover()?;
    let probes = SystemProbes;

    // The only VM-creating path. It resolves the backend and confirms before any external
    // mutation, is fully independent of the diagnostic classification below, and never starts,
    // reconfigures, or deletes an instance.
    let mut actions = Vec::new();
    if args.create_instance {
        if let Some(action) =
            run_create_instance(&probes, backend, &args.lima_instance, args.yes, args.json)?
        {
            actions.push(action);
        }
    } else if args.start_instance {
        if let Some(action) =
            run_start_instance(&probes, backend, &args.lima_instance, args.yes, args.json)?
        {
            actions.push(action);
        }
    } else if args.install_guest_packages {
        if let Some(action) =
            run_install_guest_packages(&probes, backend, &args.lima_instance, args.yes, args.json)?
        {
            actions.push(action);
        }
    } else if let Some(artifact) = args.install_guest_helper.as_deref() {
        let checksum = args
            .guest_helper_sha256
            .as_deref()
            .expect("clap requires the helper checksum with the artifact");
        if let Some(action) = run_install_guest_helper(
            &probes,
            backend,
            &args.lima_instance,
            artifact,
            checksum,
            args.yes,
            args.json,
        )? {
            actions.push(action);
        }
    }

    let initial = diagnose(&probes, backend, &args.lima_instance, &paths)?;
    if !args.check {
        actions.extend(apply_safe_repairs(&initial, &paths)?);
    }
    let mut report = if actions.is_empty() {
        initial
    } else {
        diagnose(&probes, backend, &args.lima_instance, &paths)?
    };
    report.actions_taken = actions;
    report = report.finish();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_human(&report, args.check);
    }
    Ok(report.exit_code())
}

/// Resolve the mutating create-instance request into an optional recorded action.
///
/// Returns `Ok(None)` when the instance already exists (a no-op that never prompts or mutates),
/// and `Ok(Some(action))` after a confirmed, verified creation. Every abort path — wrong backend,
/// `--json` without `--yes`, declined confirmation, ambiguous presence, or create failure returns
/// an error before mutation. An unsafe post-condition fails closed while leaving the newly created
/// instance for explicit manual inspection; Guard never guesses that it is safe to delete.
fn run_create_instance(
    probes: &dyn SetupProbes,
    backend: BackendKind,
    instance: &str,
    assume_yes: bool,
    json: bool,
) -> Result<Option<String>> {
    if json && !assume_yes {
        bail!(
            "--create-instance with --json requires --yes so machine-readable output is never mixed with an interactive prompt"
        );
    }
    validate_instance_action_target("--create-instance", backend, std::env::consts::OS)?;
    create_lima_instance(probes, instance, assume_yes)
}

fn validate_instance_action_target(
    action: &str,
    backend: BackendKind,
    host_os: &str,
) -> Result<()> {
    if host_os != "macos" {
        bail!("{action} is only supported on a macOS host; detected {host_os:?}");
    }
    if backend != BackendKind::MacosLima {
        bail!(
            "{action} is only supported on the macOS Lima backend; the resolved backend is {}",
            backend_label(backend)
        );
    }
    Ok(())
}

/// Resolve the mutating start-instance request into an optional recorded action.
///
/// Returns `Ok(None)` when the instance is already running. Like creation, startup is supported
/// only by the macOS Lima backend and machine-readable mode requires explicit non-interactive
/// confirmation. The instance is re-inspected independently before and after the one allowed
/// lifecycle command.
fn run_start_instance(
    probes: &dyn SetupProbes,
    backend: BackendKind,
    instance: &str,
    assume_yes: bool,
    json: bool,
) -> Result<Option<String>> {
    if json && !assume_yes {
        bail!(
            "--start-instance with --json requires --yes so machine-readable output is never mixed with an interactive prompt"
        );
    }
    validate_instance_action_target("--start-instance", backend, std::env::consts::OS)?;
    start_lima_instance(probes, instance, assume_yes)
}

/// Resolve the explicit guest-package installation request.
///
/// Machine-readable mode requires `--yes`, and only the macOS Lima backend may reach the guest.
/// The action independently verifies a running mountless instance before invoking guest sudo.
fn run_install_guest_packages(
    probes: &dyn SetupProbes,
    backend: BackendKind,
    instance: &str,
    assume_yes: bool,
    json: bool,
) -> Result<Option<String>> {
    if json && !assume_yes {
        bail!(
            "--install-guest-packages with --json requires --yes so machine-readable output is never mixed with an interactive prompt"
        );
    }
    validate_instance_action_target("--install-guest-packages", backend, std::env::consts::OS)?;
    install_lima_guest_packages(probes, instance, assume_yes)
}

fn run_install_guest_helper(
    probes: &dyn SetupProbes,
    backend: BackendKind,
    instance: &str,
    artifact: &Path,
    checksum: &str,
    assume_yes: bool,
    json: bool,
) -> Result<Option<String>> {
    if json && !assume_yes {
        bail!(
            "--install-guest-helper with --json requires --yes so machine-readable output is never mixed with an interactive prompt"
        );
    }
    validate_instance_action_target("--install-guest-helper", backend, std::env::consts::OS)?;
    install_lima_guest_helper(probes, instance, artifact, checksum, assume_yes)
}

fn parse_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("guest helper SHA-256 must be exactly 64 hexadecimal characters");
    }
    let decoded = hex::decode(value).context("decode guest helper SHA-256")?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("guest helper SHA-256 must decode to exactly 32 bytes"))
}

fn create_guest_helper_snapshot_in(
    artifact: &Path,
    expected_sha256: &[u8; 32],
    home: &Path,
) -> Result<GuestHelperSnapshot> {
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(artifact)
        .with_context(|| {
            format!(
                "open guest helper artifact without following symlinks: {}",
                safe_path_for_error(artifact)
            )
        })?;
    let before = source
        .metadata()
        .context("inspect opened guest helper artifact")?;
    validate_guest_helper_artifact_metadata(&before)?;

    let home_anchor = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(home)
        .context("open HOME as a real directory without following symlinks")?;
    let home_metadata = home_anchor
        .metadata()
        .context("inspect opened HOME anchor")?;
    let home_path_metadata = fs::symlink_metadata(home).context("inspect HOME anchor path")?;
    if !home_metadata.is_dir()
        || home_metadata.uid() != current_uid()
        || !home_path_metadata.is_dir()
        || home_path_metadata.file_type().is_symlink()
        || home_path_metadata.uid() != current_uid()
        || home_metadata.dev() != home_path_metadata.dev()
        || home_metadata.ino() != home_path_metadata.ino()
    {
        bail!("HOME is not a stable, real current-user-owned directory anchor");
    }

    let private_directory = tempfile::Builder::new()
        .prefix(".sandbox-guard-helper-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(home)
        .context("create private guest helper snapshot directory")?;
    let private_metadata = fs::symlink_metadata(private_directory.path())
        .context("verify private guest helper snapshot directory")?;
    if !private_metadata.is_dir()
        || private_metadata.file_type().is_symlink()
        || private_metadata.uid() != current_uid()
        || private_metadata.permissions().mode() & 0o777 != 0o700
    {
        bail!("guest helper snapshot directory is not an owner-private real directory");
    }
    let snapshot_path = private_directory.path().join("artifact");
    let mut snapshot = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&snapshot_path)
        .context("create private guest helper snapshot")?;
    let mut hasher = Sha256::new();
    let mut header = Vec::with_capacity(64);
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .context("read guest helper artifact")?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("guest helper artifact size overflow"))?;
        if total > MAX_GUEST_HELPER_BYTES {
            bail!(
                "guest helper artifact exceeds the {} byte limit",
                MAX_GUEST_HELPER_BYTES
            );
        }
        if header.len() < 64 {
            let wanted = (64 - header.len()).min(read);
            header.extend_from_slice(&buffer[..wanted]);
        }
        hasher.update(&buffer[..read]);
        snapshot
            .write_all(&buffer[..read])
            .context("write private guest helper snapshot")?;
    }
    snapshot.sync_all().context("sync guest helper snapshot")?;
    let after = source
        .metadata()
        .context("reinspect opened guest helper artifact")?;
    if !same_stable_file(&before, &after) || total != before.len() {
        bail!("guest helper artifact changed while it was being snapshotted");
    }
    validate_linux_aarch64_elf(&header)?;
    let actual: [u8; 32] = hasher.finalize().into();
    if &actual != expected_sha256 {
        bail!(
            "guest helper SHA-256 mismatch: expected {}, got {}",
            hex::encode(expected_sha256),
            hex::encode(actual)
        );
    }
    snapshot
        .set_permissions(fs::Permissions::from_mode(0o400))
        .context("make private guest helper snapshot read-only")?;
    let snapshot_metadata = snapshot
        .metadata()
        .context("verify private guest helper snapshot")?;
    if !snapshot_metadata.is_file()
        || snapshot_metadata.uid() != current_uid()
        || snapshot_metadata.nlink() != 1
        || snapshot_metadata.len() != total
        || snapshot_metadata.permissions().mode() & 0o777 != 0o400
    {
        bail!("private guest helper snapshot failed its ownership or mode post-condition");
    }
    drop(snapshot);
    Ok(GuestHelperSnapshot {
        path: snapshot_path,
        _private_directory: Some(private_directory),
        _home_anchor: Some(home_anchor),
    })
}

fn safe_path_for_error(path: &Path) -> String {
    format!(
        "{:?}",
        sanitize_terminal_fragment(&path.as_os_str().to_string_lossy())
    )
}

fn validate_guest_helper_artifact_metadata(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        bail!("guest helper artifact is not a regular file");
    }
    if metadata.uid() != current_uid() {
        bail!("guest helper artifact is not owned by the current user");
    }
    if metadata.nlink() != 1 {
        bail!("guest helper artifact must have exactly one hard link");
    }
    if metadata.len() < 64 {
        bail!("guest helper artifact is too small to be a valid ELF executable");
    }
    if metadata.len() > MAX_GUEST_HELPER_BYTES {
        bail!(
            "guest helper artifact exceeds the {} byte limit",
            MAX_GUEST_HELPER_BYTES
        );
    }
    Ok(())
}

fn same_stable_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.nlink() == after.nlink()
}

fn validate_linux_aarch64_elf(header: &[u8]) -> Result<()> {
    if header.len() < 64
        || &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
        || u16::from_le_bytes([header[18], header[19]]) != 183
        || u32::from_le_bytes([header[20], header[21], header[22], header[23]]) != 1
    {
        bail!("guest helper artifact is not a Linux AArch64 ELF64 executable");
    }
    Ok(())
}

fn backend_label(backend: BackendKind) -> &'static str {
    match backend {
        BackendKind::Auto => "auto",
        BackendKind::LinuxBwrap => "linux-bwrap",
        BackendKind::MacosLima => "macos-lima",
    }
}

/// Create the dedicated Lima instance only when it is provably absent.
///
/// Presence is decided by an independent, fail-closed enumeration of every instance; an existing
/// instance of any status or configuration is left untouched. Creation renders a fixed discrete
/// argv (no shell, no environment interpolation), then re-inspects the result and refuses to
/// report success unless the instance exists mountless. A failed or unsafe creation is never
/// auto-deleted; the caller is told to inspect it manually.
fn create_lima_instance(
    probes: &dyn SetupProbes,
    instance: &str,
    assume_yes: bool,
) -> Result<Option<String>> {
    validate_lima_instance(instance)?;
    let Some(limactl) = probes.which("limactl") else {
        bail!("limactl was not found on PATH; install Lima before creating the instance");
    };

    if lima_instance_present(probes, &limactl, instance)? {
        eprintln!("Lima instance {instance:?} already exists; leaving it unchanged");
        return Ok(None);
    }

    confirm_instance_creation(instance, assume_yes)?;
    run_lima_create(probes, &limactl, instance)?;
    verify_created_instance(probes, &limactl, instance)?;
    Ok(Some(format!("created mountless Lima instance {instance}")))
}

/// Fail-closed presence detection independent of the named diagnostic's broad
/// nonzero-means-missing classification. Enumerates every instance as JSON-lines and matches the
/// exact validated name; any command failure, malformed record, missing/non-string name, or a
/// duplicated name aborts rather than guessing.
fn lima_instance_present(probes: &dyn SetupProbes, limactl: &Path, instance: &str) -> Result<bool> {
    Ok(find_lima_instance(probes, limactl, instance)?.is_some())
}

fn find_lima_instance(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
    let mut matches = lima_list_records(probes, limactl, None)?
        .into_iter()
        .filter(|record| record.get("name").and_then(serde_json::Value::as_str) == Some(instance));
    let record = matches.next();
    if matches.next().is_some() {
        bail!(
            "limactl reported instance {instance:?} more than once; refusing to create or modify anything"
        );
    }
    Ok(record)
}

/// Run `limactl list --json [name]` and parse it as JSON-lines: one object per non-empty line.
/// Untrusted instance names are validated as present strings but are never echoed to the terminal.
fn lima_list_records(
    probes: &dyn SetupProbes,
    limactl: &Path,
    filter: Option<&str>,
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>> {
    let mut args = vec![OsString::from("list"), OsString::from("--json")];
    if let Some(name) = filter {
        args.push(OsString::from(name));
    }
    let output = probes
        .output(limactl, &args)
        .map_err(|error| anyhow!("failed to run limactl list --json: {error}"))?;
    if !output.success {
        bail!("limactl list --json failed: {}", concise_failure(&output));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| anyhow!("limactl list --json produced non-UTF-8 output"))?;
    let mut records = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|_| anyhow!("limactl list --json produced a malformed record"))?;
        let object = match value {
            serde_json::Value::Object(map) => map,
            _ => bail!("limactl list --json produced a record that was not a JSON object"),
        };
        if object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            bail!("limactl list --json produced a record without a string name");
        }
        records.push(object);
    }
    Ok(records)
}

fn confirm_instance_creation(instance: &str, assume_yes: bool) -> Result<()> {
    if assume_yes {
        return Ok(());
    }
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        bail!(
            "creating the Lima instance requires an interactive terminal or --yes; nothing was changed"
        );
    }
    let phrase = format!("CREATE LIMA INSTANCE {instance}");
    eprintln!(
        "This creates a new dedicated Lima VM named {instance:?} with host mounts disabled. It does not start the VM or install anything inside it."
    );
    print!("Type {phrase} to confirm: ");
    io::stdout()
        .flush()
        .context("flush Lima creation confirmation prompt")?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0
        || !instance_creation_phrase_matches(instance, &answer)
    {
        bail!("Lima instance creation was not confirmed; nothing was changed");
    }
    Ok(())
}

fn instance_creation_phrase_matches(instance: &str, answer: &str) -> bool {
    answer.trim_end_matches(['\r', '\n']) == format!("CREATE LIMA INSTANCE {instance}")
}

/// Execute exactly `limactl create --name <validated-name> --mount-none template:default` as a
/// discrete argv. No shell, no environment interpolation, and no weaker fallback. A failure is
/// reported with a terminal-safe diagnostic and no cleanup or delete is attempted.
fn run_lima_create(probes: &dyn SetupProbes, limactl: &Path, instance: &str) -> Result<()> {
    validate_lima_instance(instance)?;
    let args = [
        OsString::from("create"),
        OsString::from("--name"),
        OsString::from(instance),
        OsString::from("--mount-none"),
        OsString::from("template:default"),
    ];
    let output = probes
        .output(limactl, &args)
        .map_err(|error| anyhow!("failed to run limactl create: {error}"))?;
    if !output.success {
        bail!(
            "limactl create failed: {}; inspect Lima manually before retrying",
            concise_failure(&output)
        );
    }
    Ok(())
}

/// Read-only post-condition: the exact instance must exist with a config object whose `mounts`
/// key is absent or an empty array. Any schema drift, non-empty mounts, wrong/missing name, or
/// command failure is an error, and Guard never deletes the unverified instance.
fn verify_created_instance(probes: &dyn SetupProbes, limactl: &Path, instance: &str) -> Result<()> {
    let records = lima_list_records(probes, limactl, Some(instance))?;
    let [record] = records.as_slice() else {
        bail!(
            "limactl did not return exactly one {instance:?} record after creation; inspect it manually before use and Guard will not delete it"
        );
    };
    if record.get("name").and_then(serde_json::Value::as_str) != Some(instance) {
        bail!(
            "limactl returned the wrong instance after creating {instance:?}; inspect Lima manually and Guard will not delete anything"
        );
    }
    let Some(config) = record.get("config").and_then(serde_json::Value::as_object) else {
        bail!(
            "the created instance {instance:?} reported no config object; inspect it manually and Guard will not delete it"
        );
    };
    match config.get("mounts") {
        None => Ok(()),
        Some(serde_json::Value::Array(mounts)) if mounts.is_empty() => Ok(()),
        Some(serde_json::Value::Array(_)) => bail!(
            "the created instance {instance:?} declares host mounts; inspect and remove it manually, Guard will not delete it"
        ),
        Some(_) => bail!(
            "the created instance {instance:?} reported a non-array config.mounts; inspect it manually, Guard will not delete it"
        ),
    }
}

/// Start one already-existing, stopped, declared-mountless Lima instance.
///
/// The precondition is derived from an all-instance listing rather than the diagnostic report.
/// Only the exact `Stopped` status is actionable. After the fixed mountless start invocation, both
/// the reported configuration/status and the live mount table must pass. A failed post-condition
/// leaves the instance running for manual inspection; Guard never automatically stops or deletes
/// it because that could destroy unrelated owner state.
fn start_lima_instance(
    probes: &dyn SetupProbes,
    instance: &str,
    assume_yes: bool,
) -> Result<Option<String>> {
    validate_lima_instance(instance)?;
    let Some(limactl) = probes.which("limactl") else {
        bail!("limactl was not found on PATH; install Lima before starting the instance");
    };
    let Some(record) = find_lima_instance(probes, &limactl, instance)? else {
        bail!(
            "Lima instance {instance:?} does not exist; create it mountless before attempting to start it"
        );
    };
    require_declared_mountless(&record, instance, "before startup")?;
    let Some(status) = record.get("status").and_then(serde_json::Value::as_str) else {
        bail!(
            "Lima instance {instance:?} reported no string status; refusing to start or modify it"
        );
    };
    match status {
        "Running" => {
            eprintln!("Lima instance {instance:?} is already running; leaving it unchanged");
            return Ok(None);
        }
        "Stopped" => {}
        _ => bail!(
            "Lima instance {instance:?} has unsupported status {:?}; refusing to start or modify it",
            sanitize_terminal_fragment(status)
        ),
    }

    confirm_instance_start(instance, assume_yes)?;
    run_lima_start(probes, &limactl, instance)?;
    verify_started_instance(probes, &limactl, instance)?;
    verify_live_mountlessness(probes, &limactl, instance)?;
    Ok(Some(format!(
        "started mountless Lima instance {instance} and verified its live mounts"
    )))
}

fn require_declared_mountless(
    record: &serde_json::Map<String, serde_json::Value>,
    instance: &str,
    phase: &str,
) -> Result<()> {
    let Some(config) = record.get("config").and_then(serde_json::Value::as_object) else {
        bail!(
            "Lima instance {instance:?} reported no config object {phase}; mountlessness is unknown and Guard will not modify it"
        );
    };
    match config.get("mounts") {
        None => Ok(()),
        Some(serde_json::Value::Array(mounts)) if mounts.is_empty() => Ok(()),
        Some(serde_json::Value::Array(_)) => bail!(
            "Lima instance {instance:?} declares host mounts {phase}; Guard will not start, reconfigure, or delete it"
        ),
        Some(_) => bail!(
            "Lima instance {instance:?} reported a non-array config.mounts {phase}; Guard will not modify it"
        ),
    }
}

fn confirm_instance_start(instance: &str, assume_yes: bool) -> Result<()> {
    if assume_yes {
        return Ok(());
    }
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        bail!(
            "starting the Lima instance requires an interactive terminal or --yes; nothing was changed"
        );
    }
    let phrase = format!("START LIMA INSTANCE {instance}");
    eprintln!(
        "This starts the dedicated Lima VM named {instance:?} with host mounts disabled. It does not install, reconfigure, stop, or delete anything."
    );
    print!("Type {phrase} to confirm: ");
    io::stdout()
        .flush()
        .context("flush Lima startup confirmation prompt")?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0 || !instance_start_phrase_matches(instance, &answer)
    {
        bail!("Lima instance startup was not confirmed; nothing was changed");
    }
    Ok(())
}

fn instance_start_phrase_matches(instance: &str, answer: &str) -> bool {
    answer.trim_end_matches(['\r', '\n']) == format!("START LIMA INSTANCE {instance}")
}

fn run_lima_start(probes: &dyn SetupProbes, limactl: &Path, instance: &str) -> Result<()> {
    validate_lima_instance(instance)?;
    let args = [
        OsString::from("--tty=false"),
        OsString::from("start"),
        OsString::from("--mount-none"),
        OsString::from(instance),
    ];
    let output = probes
        .output(limactl, &args)
        .map_err(|error| anyhow!("failed to run limactl start: {error}"))?;
    if !output.success {
        bail!(
            "limactl start failed: {}; inspect Lima manually before retrying, and Guard will not stop or delete the instance",
            concise_failure(&output)
        );
    }
    Ok(())
}

fn verify_started_instance(probes: &dyn SetupProbes, limactl: &Path, instance: &str) -> Result<()> {
    let records = lima_list_records(probes, limactl, Some(instance))?;
    let [record] = records.as_slice() else {
        bail!(
            "limactl did not return exactly one {instance:?} record after startup; inspect it manually and Guard will not stop or delete it"
        );
    };
    if record.get("name").and_then(serde_json::Value::as_str) != Some(instance) {
        bail!(
            "limactl returned the wrong instance after starting {instance:?}; inspect Lima manually and Guard will not stop or delete anything"
        );
    }
    require_declared_mountless(record, instance, "after startup")?;
    if record.get("status").and_then(serde_json::Value::as_str) != Some("Running") {
        bail!(
            "Lima instance {instance:?} did not report Running after startup; inspect it manually and Guard will not stop or delete it"
        );
    }
    Ok(())
}

fn verify_live_mountlessness(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
) -> Result<()> {
    verify_live_mountlessness_for_phase(probes, limactl, instance, "after startup")
}

fn verify_live_mountlessness_for_phase(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    phase: &str,
) -> Result<()> {
    let output = lima_shell(
        probes,
        limactl,
        instance,
        &[GUEST_FINDMNT, "--noheadings", "--output", "TARGET,FSTYPE"],
    )
    .map_err(|error| anyhow!("failed to inspect live Lima mounts {phase}: {error}"))?;
    if !output.success {
        bail!(
            "live mount inspection failed {phase}: {}; inspect the running instance manually, and Guard will not modify, stop, or delete it",
            concise_failure(&output)
        );
    }
    let mounts = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = mounts.lines().find(|line| is_host_sharing_mount(line)) {
        bail!(
            "unsafe live host-sharing mount detected {phase}: {}; inspect the instance manually, and Guard will not modify, stop, or delete it",
            sanitize_terminal_fragment(line.trim())
        );
    }
    Ok(())
}

/// Install the fixed runtime package-name set inside an already-running, mountless Lima instance.
///
/// The package manager runs only after independent configuration, status, and live-mount checks.
/// Those checks are repeated after confirmation, between update and install, and after install.
/// Existing complete installations are an idempotent no-op. Partial package-manager changes are
/// never guessed at or rolled back automatically.
fn install_lima_guest_packages(
    probes: &dyn SetupProbes,
    instance: &str,
    assume_yes: bool,
) -> Result<Option<String>> {
    validate_lima_instance(instance)?;
    let Some(limactl) = probes.which("limactl") else {
        bail!("limactl was not found on PATH; install Lima before provisioning guest packages");
    };

    require_safe_package_target(probes, &limactl, instance, "before package inspection")?;
    if guest_packages_probe(probes, &limactl, instance)
        .map_err(|error| anyhow!("failed to inspect guest package artifacts: {error}"))?
        .success
    {
        eprintln!("Lima instance {instance:?} already contains the required guest packages");
        return Ok(None);
    }
    require_guest_package_installer(probes, &limactl, instance)?;

    confirm_guest_package_install(instance, assume_yes)?;
    require_safe_package_target(
        probes,
        &limactl,
        instance,
        "immediately before apt-get update",
    )?;
    run_guest_apt(probes, &limactl, instance, &["update"], "apt-get update")?;

    require_safe_package_target(probes, &limactl, instance, "before apt-get install").context(
        "guest state changed after apt-get update; package-manager state may be partial and Guard will not continue or roll it back",
    )?;
    let mut install_args = vec!["install", "--yes", "--no-install-recommends", "--reinstall"];
    install_args.extend_from_slice(GUEST_PACKAGE_NAMES);
    run_guest_apt(probes, &limactl, instance, &install_args, "apt-get install")?;

    require_safe_package_target(probes, &limactl, instance, "after package installation").context(
        "guest package post-condition failed; package-manager state may be partial and Guard will not clean up, stop, or delete the instance",
    )?;
    require_guest_package_artifacts(probes, &limactl, instance).context(
        "guest package post-condition failed; package-manager state may be partial and Guard will not uninstall or roll back packages",
    )?;
    Ok(Some(format!(
        "installed and verified the fixed Lima guest package-name set in {instance}"
    )))
}

fn require_safe_package_target(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    phase: &str,
) -> Result<()> {
    let Some(record) = find_lima_instance(probes, limactl, instance)? else {
        bail!(
            "Lima instance {instance:?} does not exist {phase}; Guard will not create or modify it"
        );
    };
    require_declared_mountless(&record, instance, phase)?;
    let Some(status) = record.get("status").and_then(serde_json::Value::as_str) else {
        bail!(
            "Lima instance {instance:?} reported no string status {phase}; Guard will not modify it"
        );
    };
    if status != "Running" {
        bail!(
            "Lima instance {instance:?} has status {:?} {phase}; start it explicitly with --start-instance before installing packages",
            sanitize_terminal_fragment(status)
        );
    }
    verify_live_mountlessness_for_phase(probes, limactl, instance, phase)
}

fn guest_packages_probe(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
) -> std::io::Result<ProbeOutput> {
    let mut command = vec![GUEST_TEST];
    for (index, (_, path)) in GUEST_PACKAGE_EXECUTABLES.iter().enumerate() {
        if index > 0 {
            command.push("-a");
        }
        command.extend(["-x", *path]);
    }
    command.extend(["-a", "-s", GUEST_CA_BUNDLE]);
    lima_shell(probes, limactl, instance, &command)
}

fn require_guest_package_installer(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
) -> Result<()> {
    for (label, path) in [
        ("non-interactive privilege helper", GUEST_SUDO),
        ("clean-environment launcher", GUEST_ENV),
        ("APT package manager", GUEST_APT_GET),
    ] {
        let output = lima_shell(probes, limactl, instance, &[GUEST_TEST, "-x", path])
            .map_err(|error| anyhow!("failed to inspect {label} at {path}: {error}"))?;
        if !output.success {
            bail!(
                "guest {label} is not executable at {path}: {}; Guard will not attempt package installation",
                concise_failure(&output)
            );
        }
    }
    Ok(())
}

fn confirm_guest_package_install(instance: &str, assume_yes: bool) -> Result<()> {
    if assume_yes {
        return Ok(());
    }
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        bail!(
            "guest package installation requires an interactive terminal or --yes; nothing was changed"
        );
    }
    let phrase = format!("INSTALL GUEST PACKAGES {instance}");
    eprintln!(
        "This runs apt-get through passwordless sudo inside the dedicated Lima guest {instance:?}. It trusts that guest's configured APT repositories and root-run package scripts; it never invokes host sudo."
    );
    print!("Type {phrase} to confirm: ");
    io::stdout()
        .flush()
        .context("flush guest package installation confirmation prompt")?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0
        || !guest_package_install_phrase_matches(instance, &answer)
    {
        bail!("guest package installation was not confirmed; nothing was changed");
    }
    Ok(())
}

fn guest_package_install_phrase_matches(instance: &str, answer: &str) -> bool {
    answer.trim_end_matches(['\r', '\n']) == format!("INSTALL GUEST PACKAGES {instance}")
}

fn run_guest_apt(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    apt_args: &[&str],
    phase: &str,
) -> Result<()> {
    let mut command = vec![
        GUEST_SUDO,
        "--non-interactive",
        "--",
        GUEST_ENV,
        "-i",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        "DEBIAN_FRONTEND=noninteractive",
        "APT_LISTCHANGES_FRONTEND=none",
        GUEST_APT_GET,
    ];
    command.extend_from_slice(apt_args);
    let output = lima_shell(probes, limactl, instance, &command)
        .map_err(|error| anyhow!("failed to run guest {phase}: {error}"))?;
    if !output.success {
        bail!(
            "guest {phase} failed: {}; package-manager state may be partial, and Guard will not run cleanup, stop, or delete the instance",
            concise_failure(&output)
        );
    }
    Ok(())
}

fn require_guest_package_artifacts(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
) -> Result<()> {
    for (package, path) in GUEST_PACKAGE_EXECUTABLES {
        let output = lima_shell(probes, limactl, instance, &[GUEST_TEST, "-x", path])
            .map_err(|error| anyhow!("failed to verify guest package {package}: {error}"))?;
        if !output.success {
            bail!(
                "guest package {package} did not provide executable {path}: {}",
                concise_failure(&output)
            );
        }
    }
    let certificates = lima_shell(
        probes,
        limactl,
        instance,
        &[GUEST_TEST, "-s", GUEST_CA_BUNDLE],
    )
    .map_err(|error| anyhow!("failed to verify guest CA certificate bundle: {error}"))?;
    if !certificates.success {
        bail!(
            "guest ca-certificates did not provide a nonempty bundle at {GUEST_CA_BUNDLE}: {}",
            concise_failure(&certificates)
        );
    }
    Ok(())
}

fn install_lima_guest_helper(
    probes: &dyn SetupProbes,
    instance: &str,
    artifact: &Path,
    checksum: &str,
    assume_yes: bool,
) -> Result<Option<String>> {
    validate_lima_instance(instance)?;
    let expected = parse_sha256(checksum)?;
    let expected_hex = hex::encode(expected);
    let snapshot = probes
        .snapshot_guest_helper(artifact, &expected)
        .context("validate and snapshot guest helper artifact")?;
    let Some(limactl) = probes.which("limactl") else {
        bail!("limactl was not found on PATH; install Lima before provisioning guard-helper");
    };

    require_safe_helper_target(probes, &limactl, instance, "before helper inspection")?;
    if guest_helper_matches(probes, &limactl, instance, &expected_hex)? {
        eprintln!(
            "Lima instance {instance:?} already contains the exact guard-helper artifact and version"
        );
        return Ok(None);
    }
    require_guest_helper_installer(probes, &limactl, instance)?;
    confirm_guest_helper_install(instance, assume_yes)?;

    let guest_temp = probes.guest_helper_temp_path();
    validate_guest_helper_temp_path(&guest_temp)?;
    let root_temp = guest_helper_root_temp_path(&guest_temp)?;
    require_safe_helper_target(probes, &limactl, instance, "immediately before helper copy")?;
    for path in [&guest_temp, &root_temp] {
        let absent = lima_shell(probes, &limactl, instance, &[GUEST_TEST, "!", "-e", path])
            .map_err(|error| anyhow!("failed to inspect guest helper temporary path: {error}"))?;
        if !absent.success {
            bail!(
                "unguessable guest helper temporary path unexpectedly exists at {path}: {}; nothing was copied or installed",
                concise_failure(&absent)
            );
        }
    }
    if let Err(error) = copy_guest_helper(probes, &limactl, instance, &snapshot.path, &guest_temp) {
        let cleanup = cleanup_guest_helper_temp(probes, &limactl, instance, &guest_temp);
        bail!("{error:#}; copy may be partial; {cleanup}");
    }

    require_safe_helper_target(probes, &limactl, instance, "after helper copy and before install")
        .context(format!(
            "guest state changed after helper copy; temporary artifact may remain at {guest_temp} and Guard will not modify, stop, or delete the instance"
        ))?;
    if let Err(error) = verify_guest_hash(probes, &limactl, instance, &guest_temp, &expected_hex) {
        let cleanup = cleanup_guest_helper_temp(probes, &limactl, instance, &guest_temp);
        bail!("copied guest helper failed SHA-256 verification: {error:#}; {cleanup}");
    }
    require_safe_helper_target(probes, &limactl, instance, "immediately before helper install")
        .context(format!(
            "guest state changed before helper installation; temporary artifact may remain at {guest_temp} and Guard will not continue or clean it up"
        ))?;
    if let Err(error) =
        run_guest_helper_install(probes, &limactl, instance, &guest_temp, &root_temp)
    {
        let cleanup =
            cleanup_guest_helper_temps(probes, &limactl, instance, &[&guest_temp, &root_temp]);
        bail!("{error:#}; the existing helper was not intentionally changed; {cleanup}");
    }

    require_safe_helper_target(probes, &limactl, instance, "after root-temporary helper install")
        .context(
        format!(
            "root-temporary helper installation may be partial and artifacts may remain at {guest_temp} and {root_temp}; Guard will not clean up, stop, or delete the instance"
        ),
    )?;
    if let Err(error) =
        require_guest_helper_at(probes, &limactl, instance, &root_temp, &expected_hex)
    {
        let cleanup =
            cleanup_guest_helper_temps(probes, &limactl, instance, &[&guest_temp, &root_temp]);
        bail!(
            "root-temporary guard-helper failed its hash, ownership, mode, or version pre-activation check: {error:#}; the existing helper was not intentionally changed; {cleanup}"
        );
    }
    require_safe_helper_target(probes, &limactl, instance, "immediately before helper activation")
        .context(format!(
            "guest state changed before helper activation; artifacts may remain at {guest_temp} and {root_temp} and Guard will not continue or clean them up"
        ))?;
    if let Err(error) = activate_guest_helper(probes, &limactl, instance, &root_temp) {
        let cleanup =
            cleanup_guest_helper_temps(probes, &limactl, instance, &[&guest_temp, &root_temp]);
        bail!(
            "{error:#}; the existing helper may have changed and Guard will not roll it back; {cleanup}"
        );
    }
    require_safe_helper_target(probes, &limactl, instance, "after helper activation").context(
        format!(
            "helper activation may have changed the existing helper and the source artifact may remain at {guest_temp}; Guard will not clean up, roll back, stop, or delete the instance"
        ),
    )?;
    if let Err(error) = require_installed_guest_helper(probes, &limactl, instance, &expected_hex) {
        let cleanup = cleanup_guest_helper_temp(probes, &limactl, instance, &guest_temp);
        bail!(
            "activated guard-helper failed its hash, ownership, mode, or version post-condition: {error:#}; Guard will not roll back the previous helper; {cleanup}"
        );
    }
    remove_guest_helper_temp(probes, &limactl, instance, &guest_temp).context(
        "guard-helper was installed and verified, but its guest temporary file may remain",
    )?;
    require_safe_helper_target(probes, &limactl, instance, "after helper cleanup").context(
        "guard-helper was installed and verified, but final guest safety verification failed; Guard did not stop, delete, or reconfigure the instance",
    )?;
    Ok(Some(format!(
        "installed and verified guard-helper {} in mountless Lima instance {instance}",
        env!("CARGO_PKG_VERSION")
    )))
}

fn require_safe_helper_target(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    phase: &str,
) -> Result<()> {
    let Some(record) = find_lima_instance(probes, limactl, instance)? else {
        bail!(
            "Lima instance {instance:?} does not exist {phase}; Guard will not create or modify it"
        );
    };
    require_declared_mountless(&record, instance, phase)?;
    let Some(status) = record.get("status").and_then(serde_json::Value::as_str) else {
        bail!(
            "Lima instance {instance:?} reported no string status {phase}; Guard will not modify it"
        );
    };
    if status != "Running" {
        bail!(
            "Lima instance {instance:?} has status {:?} {phase}; start it explicitly before installing guard-helper",
            sanitize_terminal_fragment(status)
        );
    }
    verify_live_mountlessness_for_phase(probes, limactl, instance, phase)
}

fn require_guest_helper_installer(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
) -> Result<()> {
    for path in [
        GUEST_SUDO,
        GUEST_ENV,
        GUEST_INSTALL,
        GUEST_MV,
        GUEST_RM,
        GUEST_TEST,
        GUEST_SHA256SUM,
        GUEST_STAT,
    ] {
        let output =
            lima_shell(probes, limactl, instance, &[GUEST_TEST, "-x", path]).map_err(|error| {
                anyhow!("failed to inspect required guest executable {path}: {error}")
            })?;
        if !output.success {
            bail!(
                "required guest executable is unavailable at {path}: {}; nothing was copied or installed",
                concise_failure(&output)
            );
        }
    }
    Ok(())
}

fn confirm_guest_helper_install(instance: &str, assume_yes: bool) -> Result<()> {
    if assume_yes {
        return Ok(());
    }
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        bail!(
            "guest helper installation requires an interactive terminal or --yes; nothing was changed"
        );
    }
    let phrase = format!("INSTALL GUEST HELPER {instance}");
    eprintln!(
        "This copies the already verified Linux ARM64 helper snapshot into the dedicated Lima guest {instance:?} and installs it as root-owned mode 0755 at {DEFAULT_GUEST_HELPER}. It never invokes host sudo."
    );
    print!("Type {phrase} to confirm: ");
    io::stdout()
        .flush()
        .context("flush guest helper installation confirmation prompt")?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0
        || !guest_helper_install_phrase_matches(instance, &answer)
    {
        bail!("guest helper installation was not confirmed; nothing was changed");
    }
    Ok(())
}

fn guest_helper_install_phrase_matches(instance: &str, answer: &str) -> bool {
    answer.trim_end_matches(['\r', '\n']) == format!("INSTALL GUEST HELPER {instance}")
}

fn validate_guest_helper_temp_path(path: &str) -> Result<()> {
    let Some(suffix) = path.strip_prefix("/tmp/guard-helper.") else {
        bail!("internal guest helper temporary path is outside the fixed /tmp namespace");
    };
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("internal guest helper temporary path is not an unguessable hexadecimal name");
    }
    Ok(())
}

fn guest_helper_root_temp_path(guest_temp: &str) -> Result<String> {
    validate_guest_helper_temp_path(guest_temp)?;
    let suffix = guest_temp
        .strip_prefix("/tmp/guard-helper.")
        .expect("validated prefix");
    Ok(format!("/usr/local/bin/.guard-helper.{suffix}"))
}

fn copy_guest_helper(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    snapshot: &Path,
    guest_temp: &str,
) -> Result<()> {
    let destination = format!("{instance}:{guest_temp}");
    // `limactl copy` documents positional SOURCE and TARGET operands. The trusted snapshot is an
    // absolute path (and therefore cannot begin with `-`), while the destination is assembled
    // only from independently validated instance and temporary-path components.
    let args = [
        OsString::from("copy"),
        snapshot.as_os_str().to_owned(),
        OsString::from(destination),
    ];
    let output = probes
        .output(limactl, &args)
        .map_err(|error| anyhow!("failed to run limactl copy: {error}"))?;
    if !output.success {
        bail!("limactl copy failed: {}", concise_failure(&output));
    }
    Ok(())
}

fn verify_guest_hash(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    path: &str,
    expected_hex: &str,
) -> Result<()> {
    let output = lima_shell(probes, limactl, instance, &[GUEST_SHA256SUM, "--", path])
        .map_err(|error| anyhow!("failed to run guest sha256sum: {error}"))?;
    let expected_output = format!("{expected_hex}  {path}\n");
    if !output.success || output.stdout != expected_output.as_bytes() || !output.stderr.is_empty() {
        bail!("guest sha256sum did not return the exact expected digest");
    }
    Ok(())
}

fn run_guest_helper_install(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    guest_temp: &str,
    root_temp: &str,
) -> Result<()> {
    let command = [
        GUEST_SUDO,
        "--non-interactive",
        "--",
        GUEST_ENV,
        "-i",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        GUEST_INSTALL,
        "--owner=0",
        "--group=0",
        "--mode=0755",
        "--no-target-directory",
        "--",
        guest_temp,
        root_temp,
    ];
    let output = lima_shell(probes, limactl, instance, &command)
        .map_err(|error| anyhow!("failed to run guest helper install: {error}"))?;
    if !output.success {
        bail!(
            "guest helper install failed: {}; guest state may be partial",
            concise_failure(&output)
        );
    }
    Ok(())
}

fn activate_guest_helper(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    root_temp: &str,
) -> Result<()> {
    let command = [
        GUEST_SUDO,
        "--non-interactive",
        "--",
        GUEST_ENV,
        "-i",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        GUEST_MV,
        "--force",
        "--no-target-directory",
        "--",
        root_temp,
        DEFAULT_GUEST_HELPER,
    ];
    let output = lima_shell(probes, limactl, instance, &command)
        .map_err(|error| anyhow!("failed to activate guest helper: {error}"))?;
    if !output.success {
        bail!(
            "atomic guest helper activation failed: {}",
            concise_failure(&output)
        );
    }
    Ok(())
}

fn guest_helper_matches(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    expected_hex: &str,
) -> Result<bool> {
    let hash = lima_shell(
        probes,
        limactl,
        instance,
        &[GUEST_SHA256SUM, "--", DEFAULT_GUEST_HELPER],
    )
    .map_err(|error| anyhow!("failed to inspect installed helper hash: {error}"))?;
    let expected_hash = format!("{expected_hex}  {DEFAULT_GUEST_HELPER}\n");
    if !hash.success || hash.stdout != expected_hash.as_bytes() || !hash.stderr.is_empty() {
        return Ok(false);
    }
    let stat = lima_shell(
        probes,
        limactl,
        instance,
        &[
            GUEST_STAT,
            "--format=%F:%h:%u:%g:%a",
            "--",
            DEFAULT_GUEST_HELPER,
        ],
    )
    .map_err(|error| anyhow!("failed to inspect installed helper ownership and mode: {error}"))?;
    if !stat.success || stat.stdout != b"regular file:1:0:0:755\n" || !stat.stderr.is_empty() {
        return Ok(false);
    }
    let version = lima_shell(
        probes,
        limactl,
        instance,
        &[DEFAULT_GUEST_HELPER, "--version"],
    )
    .map_err(|error| anyhow!("failed to inspect installed helper version: {error}"))?;
    let expected_version = format!("guard-helper {}\n", env!("CARGO_PKG_VERSION"));
    Ok(version.success
        && version.stdout == expected_version.as_bytes()
        && version.stderr.is_empty())
}

fn require_installed_guest_helper(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    expected_hex: &str,
) -> Result<()> {
    require_guest_helper_at(
        probes,
        limactl,
        instance,
        DEFAULT_GUEST_HELPER,
        expected_hex,
    )
}

fn require_guest_helper_at(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    path: &str,
    expected_hex: &str,
) -> Result<()> {
    verify_guest_hash(probes, limactl, instance, path, expected_hex)?;
    let stat = lima_shell(
        probes,
        limactl,
        instance,
        &[GUEST_STAT, "--format=%F:%h:%u:%g:%a", "--", path],
    )
    .map_err(|error| anyhow!("failed to inspect installed helper ownership and mode: {error}"))?;
    if !stat.success || stat.stdout != b"regular file:1:0:0:755\n" || !stat.stderr.is_empty() {
        bail!("installed helper is not a regular single-link root:root file with mode 0755");
    }
    let version = lima_shell(probes, limactl, instance, &[path, "--version"])
        .map_err(|error| anyhow!("failed to inspect installed helper version: {error}"))?;
    let expected_version = format!("guard-helper {}\n", env!("CARGO_PKG_VERSION"));
    if !version.success
        || version.stdout != expected_version.as_bytes()
        || !version.stderr.is_empty()
    {
        bail!("installed helper did not report the exact expected version");
    }
    Ok(())
}

fn cleanup_guest_helper_temps(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    paths: &[&str],
) -> String {
    let results = paths
        .iter()
        .map(|path| cleanup_guest_helper_temp(probes, limactl, instance, path))
        .collect::<Vec<_>>();
    results.join("; ")
}

fn remove_guest_helper_temp(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    guest_temp: &str,
) -> Result<()> {
    require_safe_helper_target(
        probes,
        limactl,
        instance,
        "immediately before helper cleanup",
    )?;
    let command = [
        GUEST_SUDO,
        "--non-interactive",
        "--",
        GUEST_ENV,
        "-i",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        GUEST_RM,
        "--force",
        "--",
        guest_temp,
    ];
    let output = lima_shell(probes, limactl, instance, &command)
        .map_err(|error| anyhow!("failed to remove guest helper temporary file: {error}"))?;
    if !output.success {
        bail!(
            "guest temporary-file removal failed: {}",
            concise_failure(&output)
        );
    }
    let absent = lima_shell(
        probes,
        limactl,
        instance,
        &[GUEST_TEST, "!", "-e", guest_temp],
    )
    .map_err(|error| anyhow!("failed to verify guest helper temporary-file removal: {error}"))?;
    if !absent.success {
        bail!("guest helper temporary file still exists after removal");
    }
    Ok(())
}

fn cleanup_guest_helper_temp(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    guest_temp: &str,
) -> String {
    match remove_guest_helper_temp(probes, limactl, instance, guest_temp) {
        Ok(()) => "the guest temporary artifact was removed".to_owned(),
        Err(error) => format!(
            "the guest temporary artifact may remain at {guest_temp} because cleanup failed: {error:#}"
        ),
    }
}

fn is_host_sharing_mount(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ["9p", "virtiofs", "sshfs", "reverse-sshfs"]
        .iter()
        .any(|kind| lower.contains(kind))
}

fn diagnose(
    probes: &dyn SetupProbes,
    backend: BackendKind,
    lima_instance: &str,
    paths: &SetupPaths,
) -> Result<SetupReport> {
    let mut checks = Vec::new();
    checks.push(executable_check(
        probes,
        "host.git",
        "host",
        "git",
        true,
        platform_install_repair("git"),
    ));

    let policy = CompiledPolicy::builtin();
    checks.push(match policy {
        Ok(policy) => ok_check(
            "policy.builtin",
            "policy",
            true,
            format!("built-in policy compiled ({})", policy.hash()),
        ),
        Err(error) => error_check(
            "policy.builtin",
            "policy",
            true,
            format!("built-in policy failed to compile: {error:#}"),
        ),
    });

    for (id, path) in paths.private_directories() {
        checks.push(private_directory_check(id, path, &paths.home));
    }

    match backend {
        BackendKind::LinuxBwrap => diagnose_linux(probes, &mut checks),
        BackendKind::MacosLima => {
            diagnose_macos(probes, &mut checks, lima_instance)?;
        }
        BackendKind::Auto => unreachable!("backend is resolved before diagnosis"),
    }

    Ok(SetupReport {
        schema: REPORT_SCHEMA,
        platform: format!("{}-{}", env::consts::OS, env::consts::ARCH),
        backend,
        ready: false,
        checks,
        actions_taken: Vec::new(),
    })
}

fn diagnose_linux(probes: &dyn SetupProbes, checks: &mut Vec<SetupCheck>) {
    checks.push(executable_check(
        probes,
        "linux.bwrap",
        "linux-host",
        "bwrap",
        true,
        manual_repair(
            "Install Bubblewrap from the system package manager; Guard never invokes sudo.",
            &["sudo", "network"],
            &["sudo apt-get update && sudo apt-get install -y bubblewrap"],
        ),
    ));
    checks.extend(host_helper_checks(probes));
    checks.push(match probes.openat2_available() {
        Ok(true) => ok_check(
            "linux.openat2",
            "linux-kernel",
            true,
            "openat2 is available for descriptor-safe staging".to_owned(),
        ),
        Ok(false) => SetupCheck {
            id: "linux.openat2".to_owned(),
            component: "linux-kernel".to_owned(),
            required: true,
            status: CheckStatus::Missing,
            detail:
                "openat2 is unavailable; Linux 5.6 or newer is required and Guard will fail closed"
                    .to_owned(),
            path: None,
            repair: Some(manual_repair(
                "Upgrade to a kernel that provides openat2; no fallback is permitted.",
                &["sudo", "confirmation"],
                &[],
            )),
        },
        Err(error) => error_check(
            "linux.openat2",
            "linux-kernel",
            true,
            format!("could not probe openat2: {error}"),
        ),
    });

    let userns_path = Path::new("/proc/sys/user/max_user_namespaces");
    checks.push(match probes.read_to_string(userns_path) {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(0) => SetupCheck {
                id: "linux.userns".to_owned(),
                component: "linux-kernel".to_owned(),
                required: true,
                status: CheckStatus::Misconfigured,
                detail: "unprivileged user namespaces are disabled".to_owned(),
                path: Some(userns_path.to_path_buf()),
                repair: Some(manual_repair(
                    "Enable user namespaces according to the host distribution policy.",
                    &["sudo", "confirmation"],
                    &[],
                )),
            },
            Ok(limit) => ok_check(
                "linux.userns",
                "linux-kernel",
                true,
                format!("user namespace limit is {limit}"),
            ),
            Err(_) => error_check(
                "linux.userns",
                "linux-kernel",
                true,
                format!("invalid value in {}: {value:?}", userns_path.display()),
            ),
        },
        Err(error) => error_check(
            "linux.userns",
            "linux-kernel",
            true,
            format!("could not read {}: {error}", userns_path.display()),
        ),
    });

    checks.push(executable_check(
        probes,
        "linux.systemd-run",
        "linux-cgroup",
        "systemd-run",
        false,
        manual_repair(
            "Install systemd-run only if cgroup-required mode is needed.",
            &["sudo", "network"],
            &[],
        ),
    ));
    checks.push(executable_check(
        probes,
        "linux.zenity",
        "approval-ui",
        "zenity",
        false,
        manual_repair(
            "Install Zenity to enable native interactive egress approval on Linux.",
            &["sudo", "network"],
            &["sudo apt-get install -y zenity"],
        ),
    ));
}

fn diagnose_macos(
    probes: &dyn SetupProbes,
    checks: &mut Vec<SetupCheck>,
    instance: &str,
) -> Result<()> {
    let shell_instance = shell_word(instance)?;
    let Some(limactl) = probes.which("limactl") else {
        checks.push(SetupCheck {
            id: "macos.limactl".to_owned(),
            component: "macos-host".to_owned(),
            required: true,
            status: CheckStatus::Missing,
            detail: "limactl was not found on PATH".to_owned(),
            path: None,
            repair: Some(manual_repair(
                "Install Lima; Guard does not run Homebrew or download packages.",
                &["network"],
                &["brew install lima"],
            )),
        });
        return Ok(());
    };
    checks.push(ok_path_check(
        "macos.limactl",
        "macos-host",
        true,
        "Lima CLI found".to_owned(),
        limactl.clone(),
    ));

    let list_args = vec![
        OsString::from("list"),
        OsString::from("--json"),
        OsString::from(instance),
    ];
    let list = match probes.output(&limactl, &list_args) {
        Ok(output) => output,
        Err(error) => {
            checks.push(error_check(
                "lima.instance.exists",
                "lima-guest",
                true,
                format!("failed to inspect Lima instance {instance:?}: {error}"),
            ));
            return Ok(());
        }
    };
    if !list.success {
        checks.push(SetupCheck {
            id: "lima.instance.exists".to_owned(),
            component: "lima-guest".to_owned(),
            required: true,
            status: CheckStatus::Missing,
            detail: format!(
                "Lima instance {instance:?} is unavailable: {}",
                concise_output(&list.stderr)
            ),
            path: None,
            repair: Some(manual_repair(
                "Create the dedicated instance with host mounts disabled.",
                &["network", "confirmation"],
                &[&format!(
                    "limactl create --name={} --mount-none template:default",
                    shell_instance
                )],
            )),
        });
        return Ok(());
    }

    let value: serde_json::Value = match serde_json::from_slice(&list.stdout) {
        Ok(value) => value,
        Err(error) => {
            checks.push(error_check(
                "lima.instance.exists",
                "lima-guest",
                true,
                format!("limactl returned invalid JSON: {error}"),
            ));
            return Ok(());
        }
    };
    checks.push(ok_check(
        "lima.instance.exists",
        "lima-guest",
        true,
        format!("Lima instance {instance:?} exists"),
    ));

    let config = value.get("config").and_then(serde_json::Value::as_object);
    let declared_mounts = config.and_then(|config| config.get("mounts"));
    let declared_mounts_unsafe = declared_mounts
        .and_then(serde_json::Value::as_array)
        .is_some_and(|mounts| !mounts.is_empty());
    match (config, declared_mounts) {
        (None, _) => checks.push(error_check(
            "lima.instance.mountless-config",
            "lima-guest",
            true,
            "limactl JSON omitted the required config object; mountlessness is unknown".to_owned(),
        )),
        (_, Some(mounts)) if !mounts.is_array() => checks.push(error_check(
            "lima.instance.mountless-config",
            "lima-guest",
            true,
            "limactl JSON config.mounts was not an array; mountlessness is unknown".to_owned(),
        )),
        (_, Some(mounts)) if mounts.as_array().is_some_and(|mounts| !mounts.is_empty()) => checks
            .push(SetupCheck {
                id: "lima.instance.mountless-config".to_owned(),
                component: "lima-guest".to_owned(),
                required: true,
                status: CheckStatus::Unsafe,
                detail: format!(
                    "instance declares {} host mount(s); Guard will not delete or recreate it",
                    mounts.as_array().map_or(0, Vec::len)
                ),
                path: None,
                repair: None,
            }),
        (Some(_), Some(_) | None) => checks.push(ok_check(
            "lima.instance.mountless-config",
            "lima-guest",
            true,
            "instance configuration declares no host mounts".to_owned(),
        )),
    }

    let status = value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    if status != "Running" {
        checks.push(SetupCheck {
            id: "lima.instance.running".to_owned(),
            component: "lima-guest".to_owned(),
            required: true,
            status: if status == "unknown" {
                CheckStatus::Unverifiable
            } else {
                CheckStatus::Missing
            },
            detail: format!(
                "instance status is {:?}; guest checks were not executed",
                sanitize_terminal_fragment(status)
            ),
            path: None,
            repair: (!declared_mounts_unsafe).then(|| {
                manual_repair(
                    "Start the instance with host mounts disabled, then re-run the check.",
                    &["confirmation"],
                    &[&format!("limactl start --mount-none {}", shell_instance)],
                )
            }),
        });
        return Ok(());
    }
    checks.push(ok_check(
        "lima.instance.running",
        "lima-guest",
        true,
        "instance is running".to_owned(),
    ));

    let mounts = lima_shell(
        probes,
        &limactl,
        instance,
        &[GUEST_FINDMNT, "--noheadings", "--output", "TARGET,FSTYPE"],
    );
    checks.push(match mounts {
        Ok(output) if !output.success => error_check(
            "lima.instance.mountless-runtime",
            "lima-guest",
            true,
            format!("findmnt failed: {}", concise_output(&output.stderr)),
        ),
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = text.lines().find(|line| is_host_sharing_mount(line)) {
                SetupCheck {
                    id: "lima.instance.mountless-runtime".to_owned(),
                    component: "lima-guest".to_owned(),
                    required: true,
                    status: CheckStatus::Unsafe,
                    detail: format!(
                        "unsafe host-sharing mount detected: {}",
                        sanitize_terminal_fragment(line.trim())
                    ),
                    path: None,
                    repair: None,
                }
            } else {
                ok_check(
                    "lima.instance.mountless-runtime",
                    "lima-guest",
                    true,
                    "runtime mount table contains no known host-sharing filesystem".to_owned(),
                )
            }
        }
        Err(error) => error_check(
            "lima.instance.mountless-runtime",
            "lima-guest",
            true,
            format!("failed to inspect guest mounts: {error}"),
        ),
    });

    // The runtime invokes bwrap by its fixed absolute path `/usr/bin/bwrap` at the clean-environment
    // boundary, so the diagnostic requires that exact executable rather than a PATH lookup. No
    // fallback path is accepted.
    let package_repair = manual_repair(
        "Install and verify the fixed runtime package-name set inside the dedicated guest.",
        &["guest-sudo", "network", "confirmation"],
        &[&format!(
            "guard setup --install-guest-packages --backend macos-lima --lima-instance {shell_instance}"
        )],
    );
    let bwrap = lima_shell(probes, &limactl, instance, &[GUEST_TEST, "-x", GUEST_BWRAP]);
    checks.push(command_result_check(
        "lima.guest.bwrap",
        "lima-guest",
        bwrap,
        &format!("guest bubblewrap is executable at {GUEST_BWRAP}"),
        package_repair.clone(),
    ));

    let packages = guest_packages_probe(probes, &limactl, instance);
    checks.push(command_result_check(
        "lima.guest.packages",
        "lima-guest",
        packages,
        "guest contains the exact runtime executables and a nonempty CA certificate bundle",
        package_repair,
    ));

    let helper_test = lima_shell(
        probes,
        &limactl,
        instance,
        &["test", "-x", DEFAULT_GUEST_HELPER],
    );
    let helper_present = helper_test.as_ref().is_ok_and(|output| output.success);
    checks.push(command_result_check(
        "lima.guest.helper.present",
        "lima-guest",
        helper_test,
        "guest runtime helper is executable",
        manual_repair(
            "Install a Linux AArch64 guard-helper from a maintainer-signed source tag after verifying the release SHA256SUMS and per-file manifest; individual binaries are not independently signed.",
            &["confirmation", "verified-artifact"],
            &[&format!(
                "guard setup --install-guest-helper <artifact> --guest-helper-sha256 <sha256> --backend macos-lima --lima-instance {shell_instance}"
            )],
        ),
    ));
    if helper_present {
        let helper_version = lima_shell(
            probes,
            &limactl,
            instance,
            &[DEFAULT_GUEST_HELPER, "--version"],
        );
        checks.push(version_check(
            "lima.guest.helper.version",
            "lima-guest",
            helper_version,
            "guard-helper",
            env!("CARGO_PKG_VERSION"),
        ));
    }
    Ok(())
}

fn lima_shell(
    probes: &dyn SetupProbes,
    limactl: &Path,
    instance: &str,
    command: &[&str],
) -> std::io::Result<ProbeOutput> {
    let mut args = vec![
        OsString::from("--tty=false"),
        OsString::from("shell"),
        OsString::from(instance),
        OsString::from("--"),
    ];
    args.extend(command.iter().map(OsString::from));
    probes.output(limactl, &args)
}

fn executable_check(
    probes: &dyn SetupProbes,
    id: &str,
    component: &str,
    executable: &str,
    required: bool,
    repair: Repair,
) -> SetupCheck {
    match probes.which(executable) {
        Some(path) => ok_path_check(id, component, required, format!("{executable} found"), path),
        None => SetupCheck {
            id: id.to_owned(),
            component: component.to_owned(),
            required,
            status: CheckStatus::Missing,
            detail: format!("{executable} was not found on PATH"),
            path: None,
            repair: Some(repair),
        },
    }
}

fn host_helper_checks(probes: &dyn SetupProbes) -> Vec<SetupCheck> {
    let helper = probes.host_helper_path();
    let Some(helper) = helper else {
        return vec![SetupCheck {
            id: "host.helper.present".to_owned(),
            component: "linux-host".to_owned(),
            required: true,
            status: CheckStatus::Missing,
            detail: "guard-helper was not found beside guard or on PATH".to_owned(),
            path: None,
            repair: Some(manual_repair(
                "Reinstall guard and guard-helper together from the same verified release archive.",
                &["confirmation"],
                &[],
            )),
        }];
    };
    let present = ok_path_check(
        "host.helper.present",
        "linux-host",
        true,
        "trusted runtime helper found".to_owned(),
        helper.clone(),
    );
    let args = [OsString::from("--version")];
    let version = match probes.output(&helper, &args) {
        Ok(output) if output.success => {
            let mut check = version_check(
                "host.helper.version",
                "linux-host",
                Ok(output),
                "guard-helper",
                env!("CARGO_PKG_VERSION"),
            );
            check.path = Some(helper);
            check
        }
        Ok(output) => error_check(
            "host.helper.version",
            "linux-host",
            true,
            format!(
                "guard-helper --version failed: {}",
                concise_output(&output.stderr)
            ),
        ),
        Err(error) => error_check(
            "host.helper.version",
            "linux-host",
            true,
            format!("could not execute {}: {error}", helper.display()),
        ),
    };
    vec![present, version]
}

fn version_check(
    id: &str,
    component: &str,
    output: std::io::Result<ProbeOutput>,
    executable: &str,
    expected: &str,
) -> SetupCheck {
    match output {
        Ok(output) if output.success => {
            let actual = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let expected_line = format!("{executable} {expected}");
            if actual == expected_line {
                ok_check(
                    id,
                    component,
                    true,
                    format!("version matches guard ({expected})"),
                )
            } else {
                SetupCheck {
                    id: id.to_owned(),
                    component: component.to_owned(),
                    required: true,
                    status: CheckStatus::Mismatch,
                    detail: format!(
                        "expected {expected_line:?}, got {:?}",
                        sanitize_terminal_fragment(&actual)
                    ),
                    path: None,
                    repair: Some(manual_repair(
                        "Install guard and guard-helper from the same verified release.",
                        &["confirmation"],
                        &[],
                    )),
                }
            }
        }
        Ok(output) => error_check(
            id,
            component,
            true,
            format!("version probe failed: {}", concise_output(&output.stderr)),
        ),
        Err(error) => error_check(
            id,
            component,
            true,
            format!("version probe could not run: {error}"),
        ),
    }
}

fn command_result_check(
    id: &str,
    component: &str,
    output: std::io::Result<ProbeOutput>,
    success_detail: &str,
    repair: Repair,
) -> SetupCheck {
    match output {
        Ok(output) if output.success => ok_check(id, component, true, success_detail.to_owned()),
        Ok(output) => SetupCheck {
            id: id.to_owned(),
            component: component.to_owned(),
            required: true,
            status: CheckStatus::Missing,
            detail: concise_failure(&output),
            path: None,
            repair: Some(repair),
        },
        Err(error) => error_check(id, component, true, format!("probe could not run: {error}")),
    }
}

fn private_directory_check(id: &str, path: &Path, home: &Path) -> SetupCheck {
    if let Err(error) = validate_existing_path_components(path, home) {
        return SetupCheck {
            id: id.to_owned(),
            component: "guard-state".to_owned(),
            required: true,
            status: CheckStatus::Unsafe,
            detail: error.to_string(),
            path: Some(path.to_path_buf()),
            repair: None,
        };
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == current_uid()
                && metadata.permissions().mode() & 0o077 == 0 =>
        {
            ok_path_check(
                id,
                "guard-state",
                true,
                "private directory is owner-only".to_owned(),
                path.to_path_buf(),
            )
        }
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == current_uid() =>
        {
            SetupCheck {
                id: id.to_owned(),
                component: "guard-state".to_owned(),
                required: true,
                status: CheckStatus::Misconfigured,
                detail: format!(
                    "mode {:o} is broader than owner-only",
                    metadata.permissions().mode() & 0o777
                ),
                path: Some(path.to_path_buf()),
                repair: Some(auto_repair("Set the Guard-owned directory mode to 0700.")),
            }
        }
        Ok(_) => SetupCheck {
            id: id.to_owned(),
            component: "guard-state".to_owned(),
            required: true,
            status: CheckStatus::Unsafe,
            detail: "path is not an owner-controlled, non-symlink directory".to_owned(),
            path: Some(path.to_path_buf()),
            repair: None,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => SetupCheck {
            id: id.to_owned(),
            component: "guard-state".to_owned(),
            required: true,
            status: CheckStatus::Missing,
            detail: "Guard-owned private directory does not exist".to_owned(),
            path: Some(path.to_path_buf()),
            repair: Some(auto_repair(
                "Create the Guard-owned directory with mode 0700.",
            )),
        },
        Err(error) => error_check(
            id,
            "guard-state",
            true,
            format!("could not inspect {}: {error}", path.display()),
        ),
    }
}

pub(super) fn validate_existing_path_components(path: &Path, home: &Path) -> Result<()> {
    let anchor = trusted_anchor(path, home)?;
    let relative = path
        .strip_prefix(&anchor)
        .context("derive Guard state path relative to trusted anchor")?;
    let mut current = anchor;
    validate_owned_directory(&current, false)?;
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(_) => validate_owned_directory(&current, false)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect directory component {}", current.display()));
            }
        }
    }
    Ok(())
}

fn trusted_anchor(path: &Path, home: &Path) -> Result<PathBuf> {
    if path.starts_with(home) && path != home {
        return Ok(home.to_path_buf());
    }
    let mut candidate = path
        .parent()
        .ok_or_else(|| anyhow!("Guard state path has no parent: {}", path.display()))?
        .to_path_buf();
    loop {
        match fs::symlink_metadata(&candidate) {
            Ok(_) => {
                validate_owned_directory(&candidate, false).with_context(|| {
                    format!(
                        "external data/config root is not anchored by an owner-controlled directory: {}",
                        candidate.display()
                    )
                })?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !candidate.pop() {
                    bail!("no existing owner-controlled anchor for {}", path.display());
                }
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect state anchor {}", candidate.display()));
            }
        }
    }
}

fn apply_safe_repairs(report: &SetupReport, paths: &SetupPaths) -> Result<Vec<String>> {
    let allowed: BTreeMap<&Path, &str> = paths
        .private_directories()
        .into_iter()
        .map(|(id, path)| (path, id))
        .collect();
    let mut actions = Vec::new();
    let mut repaired = BTreeSet::new();
    for check in &report.checks {
        let Some(path) = check.path.as_deref() else {
            continue;
        };
        if check.repair.as_ref().map(|repair| &repair.kind) != Some(&RepairKind::Auto)
            || !allowed.contains_key(path)
            || !repaired.insert(path.to_path_buf())
        {
            continue;
        }
        repair_private_directory(path, &paths.home)
            .with_context(|| format!("repair {}", check.id))?;
        actions.push(format!("secured {} as mode 0700", path.display()));
    }
    Ok(actions)
}

fn repair_private_directory(path: &Path, home: &Path) -> Result<()> {
    let anchor = trusted_anchor(path, home)?;
    let relative = path
        .strip_prefix(&anchor)
        .context("derive Guard state path relative to trusted anchor")?;
    let mut current = anchor;
    validate_owned_directory(&current, false)?;
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(_) => validate_owned_directory(&current, false)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .with_context(|| format!("create private directory {}", current.display()))?;
                secure_private_directory(&current)?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect private directory {}", current.display()));
            }
        }
    }
    validate_owned_directory(path, false)?;
    secure_private_directory(path)
}

fn secure_private_directory(path: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| {
            format!(
                "open private directory without following links: {}",
                path.display()
            )
        })?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect opened private directory {}", path.display()))?;
    if !metadata.is_dir() || metadata.uid() != current_uid() {
        bail!(
            "opened private directory is not owner-controlled: {}",
            path.display()
        );
    }
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure opened private directory {}", path.display()))?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("reinspect opened private directory {}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("private directory is not owner-only: {}", path.display());
    }
    Ok(())
}

fn validate_owned_directory(path: &Path, require_private: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private directory {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != current_uid() {
        bail!("unsafe directory component: {}", path.display());
    }
    if require_private && metadata.permissions().mode() & 0o077 != 0 {
        bail!("private directory is not owner-only: {}", path.display());
    }
    Ok(())
}

fn render_human(report: &SetupReport, check_only: bool) {
    println!("platform: {}", report.platform);
    println!("backend: {}", backend_name(report.backend));
    for check in &report.checks {
        let requirement = if check.required {
            "required"
        } else {
            "optional"
        };
        println!(
            "[{}] {} ({requirement}): {}{}",
            check.status.as_str(),
            check.id,
            check.detail,
            check
                .path
                .as_ref()
                .map(|path| format!(" [{}]", path.display()))
                .unwrap_or_default()
        );
        if let Some(repair) = &check.repair {
            let requirements = if repair.requires.is_empty() {
                String::new()
            } else {
                format!("; requires {}", repair.requires.join(", "))
            };
            println!(
                "  repair ({}{requirements}): {}",
                repair.kind.as_str(),
                repair.detail
            );
            for command in &repair.commands {
                println!("    {command}");
            }
        }
    }
    for action in &report.actions_taken {
        println!("repaired: {action}");
    }
    if report.ready {
        println!("setup: ready");
    } else if check_only {
        println!("setup: not ready; no changes were made");
    } else {
        println!(
            "setup: not ready; complete the remaining manual repairs and run guard setup --check"
        );
    }
}

fn backend_name(backend: BackendKind) -> &'static str {
    match backend {
        BackendKind::Auto => "auto",
        BackendKind::LinuxBwrap => "linux-bwrap",
        BackendKind::MacosLima => "macos-lima",
    }
}

fn ok_check(id: &str, component: &str, required: bool, detail: String) -> SetupCheck {
    SetupCheck {
        id: id.to_owned(),
        component: component.to_owned(),
        required,
        status: CheckStatus::Ok,
        detail,
        path: None,
        repair: None,
    }
}

fn ok_path_check(
    id: &str,
    component: &str,
    required: bool,
    detail: String,
    path: PathBuf,
) -> SetupCheck {
    let mut check = ok_check(id, component, required, detail);
    check.path = Some(path);
    check
}

fn error_check(id: &str, component: &str, required: bool, detail: String) -> SetupCheck {
    SetupCheck {
        id: id.to_owned(),
        component: component.to_owned(),
        required,
        status: CheckStatus::Error,
        detail,
        path: None,
        repair: None,
    }
}

fn auto_repair(detail: &str) -> Repair {
    Repair {
        kind: RepairKind::Auto,
        requires: Vec::new(),
        commands: Vec::new(),
        detail: detail.to_owned(),
    }
}

fn manual_repair(detail: &str, requires: &[&str], commands: &[&str]) -> Repair {
    Repair {
        kind: RepairKind::Manual,
        requires: requires.iter().map(|value| (*value).to_owned()).collect(),
        commands: commands.iter().map(|value| (*value).to_owned()).collect(),
        detail: detail.to_owned(),
    }
}

fn platform_install_repair(package: &str) -> Repair {
    if cfg!(target_os = "macos") {
        manual_repair(
            &format!("Install {package} with Homebrew or the platform developer tools."),
            &["network"],
            &[&format!("brew install {package}")],
        )
    } else {
        manual_repair(
            &format!("Install {package} with the system package manager."),
            &["sudo", "network"],
            &[&format!(
                "sudo apt-get update && sudo apt-get install -y {package}"
            )],
        )
    }
}

fn concise_output(bytes: &[u8]) -> String {
    let value = sanitize_terminal_fragment(&String::from_utf8_lossy(bytes));
    let value = value.trim();
    if value.is_empty() {
        "command failed without diagnostic output".to_owned()
    } else {
        value.chars().take(500).collect()
    }
}

/// Escape any byte an untrusted subprocess could use to drive the terminal: C0/C1/DEL control
/// characters and Unicode bidirectional/format overrides become printable `\u{..}` escapes.
/// Newlines and tabs collapse to spaces so a single concise line cannot be forged into several.
fn sanitize_terminal_fragment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\n' | '\r' | '\t' => out.push(' '),
            control if control.is_control() => out.extend(control.escape_default()),
            bidi if is_bidi_or_format_control(bidi) => out.extend(bidi.escape_default()),
            other => out.push(other),
        }
    }
    out
}

/// Conservative set of zero-width, line/paragraph separator, and bidirectional formatting code
/// points that can reorder or hide terminal text without being classified as control characters.
fn is_bidi_or_format_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

fn concise_failure(output: &ProbeOutput) -> String {
    if output.stderr.iter().any(|byte| !byte.is_ascii_whitespace()) {
        concise_output(&output.stderr)
    } else {
        concise_output(&output.stdout)
    }
}

fn shell_word(value: &str) -> Result<String> {
    validate_lima_instance(value)?;
    Ok(value.to_owned())
}

pub(super) fn validate_lima_instance(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') && index > 0
        })
    {
        bail!("invalid Lima instance name {value:?}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn probe_openat2() -> std::result::Result<bool, String> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let path = b".\0";
    let how = OpenHow {
        flags: libc::O_PATH as u64 | libc::O_CLOEXEC as u64,
        mode: 0,
        resolve: 0,
    };
    // SAFETY: all pointers reference initialized memory for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr().cast::<libc::c_char>(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as libc::c_int
    };
    if fd >= 0 {
        // SAFETY: fd was returned by openat2 above and is owned by this function.
        unsafe { libc::close(fd) };
        Ok(true)
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            Ok(false)
        } else {
            Err(error.to_string())
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_openat2() -> std::result::Result<bool, String> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::ffi::OsStr;
    use tempfile::TempDir;

    #[derive(Default)]
    struct FakeProbes {
        executables: BTreeMap<String, PathBuf>,
        host_helper: Option<PathBuf>,
        outputs: BTreeMap<String, ProbeOutput>,
        queued_outputs: RefCell<BTreeMap<String, VecDeque<ProbeOutput>>>,
        calls: RefCell<Vec<String>>,
        files: BTreeMap<PathBuf, String>,
        openat2: bool,
        snapshot_path: Option<PathBuf>,
        snapshot_error: Option<String>,
        helper_temp_path: Option<String>,
    }

    impl SetupProbes for FakeProbes {
        fn which(&self, name: &str) -> Option<PathBuf> {
            self.executables.get(name).cloned()
        }

        fn host_helper_path(&self) -> Option<PathBuf> {
            self.host_helper.clone()
        }

        fn output(&self, program: &Path, args: &[OsString]) -> std::io::Result<ProbeOutput> {
            let key = command_key(program, args);
            self.calls.borrow_mut().push(key.clone());
            if let Some(output) = self
                .queued_outputs
                .borrow_mut()
                .get_mut(&key)
                .and_then(VecDeque::pop_front)
            {
                return Ok(output);
            }
            self.outputs.get(&key).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("no fake for {key}"))
            })
        }

        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            self.files.get(path).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "missing fake file")
            })
        }

        fn openat2_available(&self) -> std::result::Result<bool, String> {
            Ok(self.openat2)
        }

        fn snapshot_guest_helper(
            &self,
            artifact: &Path,
            _expected_sha256: &[u8; 32],
        ) -> Result<GuestHelperSnapshot> {
            self.calls
                .borrow_mut()
                .push(format!("snapshot {}", artifact.display()));
            if let Some(error) = &self.snapshot_error {
                bail!("{error}");
            }
            Ok(GuestHelperSnapshot {
                path: self
                    .snapshot_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/private/snapshot/artifact")),
                _private_directory: None,
                _home_anchor: None,
            })
        }

        fn guest_helper_temp_path(&self) -> String {
            self.helper_temp_path
                .clone()
                .unwrap_or_else(|| "/tmp/guard-helper.0123456789abcdef0123456789abcdef".to_owned())
        }
    }

    fn command_key(program: &Path, args: &[OsString]) -> String {
        std::iter::once(program.as_os_str())
            .chain(args.iter().map(OsString::as_os_str))
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn output(success: bool, stdout: &str, stderr: &str) -> ProbeOutput {
        ProbeOutput {
            success,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn private_paths(temp: &TempDir) -> SetupPaths {
        let data = temp.path().join("data");
        SetupPaths {
            home: temp.path().to_path_buf(),
            config: temp.path().join("config"),
            audit: data.join("audit"),
            events: data.join("events"),
            pending_changes: data.join("pending"),
            tools: data.join("tools"),
            data,
        }
    }

    #[test]
    fn state_repairs_are_private_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        let report = SetupReport {
            schema: REPORT_SCHEMA,
            platform: "test".to_owned(),
            backend: BackendKind::MacosLima,
            ready: false,
            checks: paths
                .private_directories()
                .into_iter()
                .map(|(id, path)| private_directory_check(id, path, &paths.home))
                .collect(),
            actions_taken: Vec::new(),
        };
        assert_eq!(apply_safe_repairs(&report, &paths).unwrap().len(), 6);
        for (_, path) in paths.private_directories() {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
        let second = SetupReport {
            checks: paths
                .private_directories()
                .into_iter()
                .map(|(id, path)| private_directory_check(id, path, &paths.home))
                .collect(),
            ..report
        };
        assert!(apply_safe_repairs(&second, &paths).unwrap().is_empty());
    }

    #[test]
    fn unsafe_state_path_is_never_repaired() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        std::os::unix::fs::symlink("elsewhere", &paths.data).unwrap();
        let check = private_directory_check("state.data.private", &paths.data, &paths.home);
        assert_eq!(check.status, CheckStatus::Unsafe);
        assert!(check.repair.is_none());
    }

    #[test]
    fn symlinked_state_parent_is_never_accepted_or_repaired() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &paths.data).unwrap();
        let child = paths.data.join("audit");
        let check = private_directory_check("state.audit.private", &child, &paths.home);
        assert_eq!(check.status, CheckStatus::Unsafe);
        assert!(check.repair.is_none());
    }

    #[test]
    fn owner_controlled_external_xdg_root_can_be_repaired() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let xdg = temp.path().join("external-xdg");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&xdg).unwrap();
        let state = xdg.join("sandbox-guard").join("audit");
        repair_private_directory(&state, &home).unwrap();
        let metadata = fs::symlink_metadata(&state).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn diagnosis_does_not_create_missing_state() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        let probes = FakeProbes::default();
        let report = diagnose(&probes, BackendKind::MacosLima, "sandbox-guard", &paths)
            .unwrap()
            .finish();
        assert!(!report.ready);
        for (_, path) in paths.private_directories() {
            assert!(!path.exists());
        }
    }

    #[test]
    fn mounted_lima_instance_is_unsafe_and_has_no_repair() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        for (_, path) in paths.private_directories() {
            repair_private_directory(path, &paths.home).unwrap();
        }
        let limactl = PathBuf::from("/opt/homebrew/bin/limactl");
        let mut probes = FakeProbes::default();
        probes
            .executables
            .insert("git".to_owned(), PathBuf::from("/usr/bin/git"));
        probes
            .executables
            .insert("limactl".to_owned(), limactl.clone());
        probes.outputs.insert(
            command_key(
                &limactl,
                &[
                    OsString::from("list"),
                    OsString::from("--json"),
                    OsString::from("sandbox-guard"),
                ],
            ),
            output(true, r#"{"status":"Running","config":{}}"#, ""),
        );
        probes.outputs.insert(
            command_key(
                &limactl,
                &[
                    "--tty=false",
                    "shell",
                    "sandbox-guard",
                    "--",
                    GUEST_FINDMNT,
                    "--noheadings",
                    "--output",
                    "TARGET,FSTYPE",
                ]
                .map(OsString::from),
            ),
            output(true, "/Users virtiofs\n/ ext4\n", ""),
        );
        probes.outputs.insert(
            command_key(
                &limactl,
                &[
                    "--tty=false",
                    "shell",
                    "sandbox-guard",
                    "--",
                    "sh",
                    "-c",
                    "missing=0; for name in git rsync findmnt; do command -v \"$name\" >/dev/null || { echo \"$name\"; missing=1; }; done; exit \"$missing\"",
                ]
                .map(OsString::from),
            ),
            output(true, "", ""),
        );
        probes.outputs.insert(
            command_key(
                &limactl,
                &[
                    "--tty=false",
                    "shell",
                    "sandbox-guard",
                    "--",
                    "test",
                    "-x",
                    DEFAULT_GUEST_HELPER,
                ]
                .map(OsString::from),
            ),
            output(false, "", "missing"),
        );

        let report = diagnose(&probes, BackendKind::MacosLima, "sandbox-guard", &paths)
            .unwrap()
            .finish();
        let mount = report
            .checks
            .iter()
            .find(|check| check.id == "lima.instance.mountless-runtime")
            .unwrap();
        assert_eq!(mount.status, CheckStatus::Unsafe);
        assert!(mount.repair.is_none());
        assert!(!report.ready);
    }

    #[test]
    fn declared_lima_mount_is_unsafe_and_suppresses_start_advice() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        for (_, path) in paths.private_directories() {
            repair_private_directory(path, &paths.home).unwrap();
        }
        let limactl = PathBuf::from("/opt/homebrew/bin/limactl");
        let mut probes = FakeProbes::default();
        probes
            .executables
            .insert("git".to_owned(), PathBuf::from("/usr/bin/git"));
        probes
            .executables
            .insert("limactl".to_owned(), limactl.clone());
        probes.outputs.insert(
            command_key(
                &limactl,
                &[
                    OsString::from("list"),
                    OsString::from("--json"),
                    OsString::from("sandbox-guard"),
                ],
            ),
            output(
                true,
                r#"{"status":"Stopped","config":{"mounts":[{"location":"/Users/test"}]}}"#,
                "",
            ),
        );
        let report = diagnose(&probes, BackendKind::MacosLima, "sandbox-guard", &paths)
            .unwrap()
            .finish();
        let mount = report
            .checks
            .iter()
            .find(|check| check.id == "lima.instance.mountless-config")
            .unwrap();
        assert_eq!(mount.status, CheckStatus::Unsafe);
        assert!(mount.repair.is_none());
        let running = report
            .checks
            .iter()
            .find(|check| check.id == "lima.instance.running")
            .unwrap();
        assert!(running.repair.is_none());
        assert!(
            probes
                .calls
                .borrow()
                .iter()
                .all(|call| !call.contains(" start "))
        );
    }

    #[test]
    fn missing_lima_config_object_is_an_error_not_a_clean_mount_claim() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        for (_, path) in paths.private_directories() {
            repair_private_directory(path, &paths.home).unwrap();
        }
        let limactl = PathBuf::from("/opt/homebrew/bin/limactl");
        let mut probes = FakeProbes::default();
        probes
            .executables
            .insert("git".to_owned(), PathBuf::from("/usr/bin/git"));
        probes
            .executables
            .insert("limactl".to_owned(), limactl.clone());
        probes.outputs.insert(
            command_key(
                &limactl,
                &[
                    OsString::from("list"),
                    OsString::from("--json"),
                    OsString::from("sandbox-guard"),
                ],
            ),
            output(true, r#"{"status":"Stopped"}"#, ""),
        );
        let report = diagnose(&probes, BackendKind::MacosLima, "sandbox-guard", &paths)
            .unwrap()
            .finish();
        let mount = report
            .checks
            .iter()
            .find(|check| check.id == "lima.instance.mountless-config")
            .unwrap();
        assert_eq!(mount.status, CheckStatus::Error);
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn stopped_lima_check_never_starts_the_instance() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        for (_, path) in paths.private_directories() {
            repair_private_directory(path, &paths.home).unwrap();
        }
        let limactl = PathBuf::from("/usr/local/bin/limactl");
        let mut probes = FakeProbes::default();
        probes
            .executables
            .insert("git".to_owned(), PathBuf::from("/usr/bin/git"));
        probes
            .executables
            .insert("limactl".to_owned(), limactl.clone());
        probes.outputs.insert(
            command_key(
                &limactl,
                &[
                    OsString::from("list"),
                    OsString::from("--json"),
                    OsString::from("sandbox-guard"),
                ],
            ),
            output(true, r#"{"status":"Stopped","config":{"mounts":[]}}"#, ""),
        );
        let report = diagnose(&probes, BackendKind::MacosLima, "sandbox-guard", &paths)
            .unwrap()
            .finish();
        assert!(!report.ready);
        assert!(
            probes
                .calls
                .borrow()
                .iter()
                .all(|call| !call.contains(" start "))
        );
        assert_eq!(probes.calls.borrow().len(), 1);
    }

    #[test]
    fn invalid_lima_names_cannot_enter_rendered_commands() {
        for value in ["", "-bad", "bad name", "bad;rm", "a/b"] {
            assert!(validate_lima_instance(value).is_err());
        }
        assert!(validate_lima_instance("sandbox-guard_2.example").is_ok());
        assert!(shell_word("bad;name").is_err());
    }

    #[test]
    fn exit_codes_distinguish_ready_known_failure_and_probe_error() {
        let report = |status| {
            SetupReport {
                schema: REPORT_SCHEMA,
                platform: "test".to_owned(),
                backend: BackendKind::LinuxBwrap,
                ready: false,
                checks: vec![SetupCheck {
                    id: "test".to_owned(),
                    component: "test".to_owned(),
                    required: true,
                    status,
                    detail: "test".to_owned(),
                    path: None,
                    repair: None,
                }],
                actions_taken: Vec::new(),
            }
            .finish()
        };
        assert_eq!(report(CheckStatus::Ok).exit_code(), 0);
        assert_eq!(report(CheckStatus::Mismatch).exit_code(), 1);
        assert_eq!(report(CheckStatus::Error).exit_code(), 3);
    }

    #[test]
    fn linux_diagnostics_cover_helper_openat2_and_userns() {
        let temp = tempfile::tempdir().unwrap();
        let paths = private_paths(&temp);
        for (_, path) in paths.private_directories() {
            repair_private_directory(path, &paths.home).unwrap();
        }
        let helper = PathBuf::from("/tmp/fake-guard-helper");
        let mut probes = FakeProbes {
            host_helper: Some(helper.clone()),
            openat2: true,
            ..FakeProbes::default()
        };
        probes
            .executables
            .insert("git".to_owned(), PathBuf::from("/usr/bin/git"));
        probes
            .executables
            .insert("bwrap".to_owned(), PathBuf::from("/usr/bin/bwrap"));
        probes.files.insert(
            PathBuf::from("/proc/sys/user/max_user_namespaces"),
            "1024\n".to_owned(),
        );
        probes.outputs.insert(
            command_key(&helper, &[OsString::from("--version")]),
            output(
                true,
                &format!("guard-helper {}\n", env!("CARGO_PKG_VERSION")),
                "",
            ),
        );
        let report = diagnose(&probes, BackendKind::LinuxBwrap, "sandbox-guard", &paths)
            .unwrap()
            .finish();
        assert!(report.ready);
        assert_eq!(report.exit_code(), 0);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id == "host.helper.version" && check.status == CheckStatus::Ok)
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id == "linux.openat2" && check.status == CheckStatus::Ok)
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id == "linux.userns" && check.status == CheckStatus::Ok)
        );
    }

    // ---- explicit Lima instance creation ----

    use crate::Cli;
    use clap::Parser;

    const LIMACTL: &str = "/opt/homebrew/bin/limactl";

    fn lima_probes() -> FakeProbes {
        let mut probes = FakeProbes::default();
        probes
            .executables
            .insert("limactl".to_owned(), PathBuf::from(LIMACTL));
        probes
    }

    fn list_key(filter: Option<&str>) -> String {
        let mut args = vec![OsString::from("list"), OsString::from("--json")];
        if let Some(name) = filter {
            args.push(OsString::from(name));
        }
        command_key(Path::new(LIMACTL), &args)
    }

    fn create_key(instance: &str) -> String {
        command_key(
            Path::new(LIMACTL),
            &[
                OsString::from("create"),
                OsString::from("--name"),
                OsString::from(instance),
                OsString::from("--mount-none"),
                OsString::from("template:default"),
            ],
        )
    }

    fn start_key(instance: &str) -> String {
        command_key(
            Path::new(LIMACTL),
            &[
                OsString::from("--tty=false"),
                OsString::from("start"),
                OsString::from("--mount-none"),
                OsString::from(instance),
            ],
        )
    }

    fn shell_key(instance: &str, command: &[&str]) -> String {
        let mut args = vec![
            OsString::from("--tty=false"),
            OsString::from("shell"),
            OsString::from(instance),
            OsString::from("--"),
        ];
        args.extend(command.iter().map(OsString::from));
        command_key(Path::new(LIMACTL), &args)
    }

    fn mount_inspection_key(instance: &str) -> String {
        shell_key(
            instance,
            &[GUEST_FINDMNT, "--noheadings", "--output", "TARGET,FSTYPE"],
        )
    }

    fn package_probe_key(instance: &str) -> String {
        let mut command = vec![GUEST_TEST];
        for (index, (_, path)) in GUEST_PACKAGE_EXECUTABLES.iter().enumerate() {
            if index > 0 {
                command.push("-a");
            }
            command.extend(["-x", *path]);
        }
        command.extend(["-a", "-s", GUEST_CA_BUNDLE]);
        shell_key(instance, &command)
    }

    fn guest_test_key(instance: &str, predicate: &str, path: &str) -> String {
        shell_key(instance, &[GUEST_TEST, predicate, path])
    }

    fn guest_apt_key(instance: &str, apt_args: &[&str]) -> String {
        let mut command = vec![
            GUEST_SUDO,
            "--non-interactive",
            "--",
            GUEST_ENV,
            "-i",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root",
            "DEBIAN_FRONTEND=noninteractive",
            "APT_LISTCHANGES_FRONTEND=none",
            GUEST_APT_GET,
        ];
        command.extend_from_slice(apt_args);
        shell_key(instance, &command)
    }

    const HELPER_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const HELPER_TEMP: &str = "/tmp/guard-helper.0123456789abcdef0123456789abcdef";
    const HELPER_ROOT_TEMP: &str = "/usr/local/bin/.guard-helper.0123456789abcdef0123456789abcdef";
    const SNAPSHOT: &str = "/private/snapshot/artifact";

    fn guest_hash_key(instance: &str, path: &str) -> String {
        shell_key(instance, &[GUEST_SHA256SUM, "--", path])
    }

    fn guest_hash_output(path: &str) -> ProbeOutput {
        output(true, &format!("{HELPER_SHA256}  {path}\n"), "")
    }

    fn helper_stat_key(instance: &str, path: &str) -> String {
        shell_key(
            instance,
            &[GUEST_STAT, "--format=%F:%h:%u:%g:%a", "--", path],
        )
    }

    fn helper_version_key(instance: &str, path: &str) -> String {
        shell_key(instance, &[path, "--version"])
    }

    fn helper_copy_key(instance: &str) -> String {
        command_key(
            Path::new(LIMACTL),
            &[
                OsString::from("copy"),
                OsString::from(SNAPSHOT),
                OsString::from(format!("{instance}:{HELPER_TEMP}")),
            ],
        )
    }

    fn helper_install_key(instance: &str) -> String {
        shell_key(
            instance,
            &[
                GUEST_SUDO,
                "--non-interactive",
                "--",
                GUEST_ENV,
                "-i",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME=/root",
                GUEST_INSTALL,
                "--owner=0",
                "--group=0",
                "--mode=0755",
                "--no-target-directory",
                "--",
                HELPER_TEMP,
                HELPER_ROOT_TEMP,
            ],
        )
    }

    fn helper_activate_key(instance: &str) -> String {
        shell_key(
            instance,
            &[
                GUEST_SUDO,
                "--non-interactive",
                "--",
                GUEST_ENV,
                "-i",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME=/root",
                GUEST_MV,
                "--force",
                "--no-target-directory",
                "--",
                HELPER_ROOT_TEMP,
                DEFAULT_GUEST_HELPER,
            ],
        )
    }

    fn helper_rm_key(instance: &str, path: &str) -> String {
        shell_key(
            instance,
            &[
                GUEST_SUDO,
                "--non-interactive",
                "--",
                GUEST_ENV,
                "-i",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME=/root",
                GUEST_RM,
                "--force",
                "--",
                path,
            ],
        )
    }

    fn seed_helper_install(probes: &mut FakeProbes) {
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{"mounts":[]}}"#,
                "",
            ),
        );
        probes.outputs.insert(
            mount_inspection_key("sandbox-guard"),
            output(true, "/ ext4\n", ""),
        );
        queue_outputs(
            probes,
            guest_hash_key("sandbox-guard", DEFAULT_GUEST_HELPER),
            vec![
                output(false, "", "missing"),
                guest_hash_output(DEFAULT_GUEST_HELPER),
            ],
        );
        for path in [
            GUEST_SUDO,
            GUEST_ENV,
            GUEST_INSTALL,
            GUEST_MV,
            GUEST_RM,
            GUEST_TEST,
            GUEST_SHA256SUM,
            GUEST_STAT,
        ] {
            probes.outputs.insert(
                guest_test_key("sandbox-guard", "-x", path),
                output(true, "", ""),
            );
        }
        probes.outputs.insert(
            shell_key("sandbox-guard", &[GUEST_TEST, "!", "-e", HELPER_TEMP]),
            output(true, "", ""),
        );
        probes.outputs.insert(
            shell_key("sandbox-guard", &[GUEST_TEST, "!", "-e", HELPER_ROOT_TEMP]),
            output(true, "", ""),
        );
        probes
            .outputs
            .insert(helper_copy_key("sandbox-guard"), output(true, "", ""));
        probes.outputs.insert(
            guest_hash_key("sandbox-guard", HELPER_TEMP),
            guest_hash_output(HELPER_TEMP),
        );
        probes
            .outputs
            .insert(helper_install_key("sandbox-guard"), output(true, "", ""));
        probes.outputs.insert(
            guest_hash_key("sandbox-guard", HELPER_ROOT_TEMP),
            guest_hash_output(HELPER_ROOT_TEMP),
        );
        probes.outputs.insert(
            helper_stat_key("sandbox-guard", HELPER_ROOT_TEMP),
            output(true, "regular file:1:0:0:755\n", ""),
        );
        probes.outputs.insert(
            helper_version_key("sandbox-guard", HELPER_ROOT_TEMP),
            output(
                true,
                &format!("guard-helper {}\n", env!("CARGO_PKG_VERSION")),
                "",
            ),
        );
        probes
            .outputs
            .insert(helper_activate_key("sandbox-guard"), output(true, "", ""));
        probes.outputs.insert(
            helper_stat_key("sandbox-guard", DEFAULT_GUEST_HELPER),
            output(true, "regular file:1:0:0:755\n", ""),
        );
        probes.outputs.insert(
            helper_version_key("sandbox-guard", DEFAULT_GUEST_HELPER),
            output(
                true,
                &format!("guard-helper {}\n", env!("CARGO_PKG_VERSION")),
                "",
            ),
        );
        for path in [HELPER_TEMP, HELPER_ROOT_TEMP] {
            probes
                .outputs
                .insert(helper_rm_key("sandbox-guard", path), output(true, "", ""));
        }
    }

    fn queue_outputs(probes: &FakeProbes, key: String, outputs: Vec<ProbeOutput>) {
        probes
            .queued_outputs
            .borrow_mut()
            .insert(key, outputs.into());
    }

    fn assert_no_lifecycle_mutation(probes: &FakeProbes) {
        for call in probes.calls.borrow().iter() {
            for forbidden in [
                " start ",
                " stop ",
                " delete",
                " restart",
                "reconfigure",
                " edit ",
            ] {
                assert!(
                    !call.contains(forbidden),
                    "unexpected lifecycle mutation in call: {call}"
                );
            }
        }
    }

    fn assert_no_destructive_lifecycle_mutation(probes: &FakeProbes) {
        for call in probes.calls.borrow().iter() {
            for forbidden in [" stop ", " delete", " restart", "reconfigure", " edit "] {
                assert!(
                    !call.contains(forbidden),
                    "unexpected destructive lifecycle mutation in call: {call}"
                );
            }
        }
    }

    fn assert_no_package_mutation(probes: &FakeProbes) {
        assert!(
            probes
                .calls
                .borrow()
                .iter()
                .all(|call| !call.contains(GUEST_APT_GET)),
            "unexpected guest package mutation: {:?}",
            probes.calls.borrow()
        );
    }

    #[test]
    fn absent_instance_is_created_mountless_verified_and_recorded() {
        let mut probes = lima_probes();
        probes
            .outputs
            .insert(list_key(None), output(true, r#"{"name":"other-vm"}"#, ""));
        probes
            .outputs
            .insert(create_key("sandbox-guard"), output(true, "", ""));
        probes.outputs.insert(
            list_key(Some("sandbox-guard")),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Stopped","config":{"mounts":[]}}"#,
                "",
            ),
        );

        let action = create_lima_instance(&probes, "sandbox-guard", true).unwrap();
        assert_eq!(
            action.as_deref(),
            Some("created mountless Lima instance sandbox-guard")
        );
        let calls = probes.calls.borrow().clone();
        assert_eq!(
            calls,
            vec![
                list_key(None),
                create_key("sandbox-guard"),
                list_key(Some("sandbox-guard")),
            ]
        );
        assert!(calls[1].contains("--mount-none"));
        assert!(calls[1].contains("--name sandbox-guard"));
        assert_no_lifecycle_mutation(&probes);
    }

    #[test]
    fn missing_config_object_after_create_absent_mounts_key_is_accepted() {
        let mut probes = lima_probes();
        probes.outputs.insert(list_key(None), output(true, "", ""));
        probes
            .outputs
            .insert(create_key("sandbox-guard"), output(true, "", ""));
        probes.outputs.insert(
            list_key(Some("sandbox-guard")),
            output(true, r#"{"name":"sandbox-guard","config":{}}"#, ""),
        );
        // An empty config object with no mounts key is mountless and must be accepted.
        assert!(create_lima_instance(&probes, "sandbox-guard", true).is_ok());
    }

    #[test]
    fn existing_instance_of_any_config_is_left_untouched_without_prompt() {
        let mut probes = lima_probes();
        // Even a mounted, running instance is a no-op for this action; it is never reconfigured.
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                "{\"name\":\"sandbox-guard\",\"status\":\"Running\",\"config\":{\"mounts\":[{\"location\":\"/Users\"}]}}\n{\"name\":\"other\"}",
                "",
            ),
        );
        // assume_yes=false proves the present branch returns before any confirmation.
        let action = create_lima_instance(&probes, "sandbox-guard", false).unwrap();
        assert_eq!(action, None);
        assert_eq!(probes.calls.borrow().clone(), vec![list_key(None)]);
        assert_no_lifecycle_mutation(&probes);
    }

    #[test]
    fn failed_malformed_or_duplicate_listing_never_creates() {
        for listing in [
            output(false, "", "limactl exploded"),
            output(true, "{ this is not json", ""),
            output(true, "[1,2,3]", ""),
            output(true, r#"{"status":"Running"}"#, ""),
            output(
                true,
                "{\"name\":\"sandbox-guard\"}\n{\"name\":\"sandbox-guard\"}",
                "",
            ),
        ] {
            let mut probes = lima_probes();
            probes.outputs.insert(list_key(None), listing);
            probes
                .outputs
                .insert(create_key("sandbox-guard"), output(true, "", ""));
            assert!(create_lima_instance(&probes, "sandbox-guard", true).is_err());
            assert_eq!(probes.calls.borrow().clone(), vec![list_key(None)]);
            assert_no_lifecycle_mutation(&probes);
        }
    }

    #[test]
    fn unsafe_postcondition_fails_closed_and_never_deletes() {
        for verify in [
            // missing config object
            output(true, r#"{"name":"sandbox-guard","status":"Stopped"}"#, ""),
            // non-empty mounts
            output(
                true,
                r#"{"name":"sandbox-guard","config":{"mounts":[{"location":"/Users"}]}}"#,
                "",
            ),
            // mounts is not an array
            output(
                true,
                r#"{"name":"sandbox-guard","config":{"mounts":"/Users"}}"#,
                "",
            ),
            // wrong / missing instance record
            output(true, r#"{"name":"other","config":{"mounts":[]}}"#, ""),
            // named lookup returned an ambiguous extra record
            output(
                true,
                "{\"name\":\"sandbox-guard\",\"config\":{}}\n{\"name\":\"other\",\"config\":{}}",
                "",
            ),
            // verification command failed
            output(false, "", "list failed"),
        ] {
            let mut probes = lima_probes();
            probes.outputs.insert(list_key(None), output(true, "", ""));
            probes
                .outputs
                .insert(create_key("sandbox-guard"), output(true, "", ""));
            probes
                .outputs
                .insert(list_key(Some("sandbox-guard")), verify);
            assert!(create_lima_instance(&probes, "sandbox-guard", true).is_err());
            assert_no_lifecycle_mutation(&probes);
        }
    }

    #[test]
    fn create_failure_reports_terminal_safe_diagnostic_without_cleanup() {
        let mut probes = lima_probes();
        probes.outputs.insert(list_key(None), output(true, "", ""));
        probes.outputs.insert(
            create_key("sandbox-guard"),
            output(false, "", "boom\u{1b}]0;title\u{7}\u{202e}reversed"),
        );
        let error = create_lima_instance(&probes, "sandbox-guard", true).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(rendered.contains("\\u{1b}"));
        assert_no_lifecycle_mutation(&probes);
    }

    #[test]
    fn injected_instance_name_is_rejected_before_any_command() {
        let probes = lima_probes();
        for bad in ["bad;rm", "../evil", "a b", "-leading", ""] {
            assert!(create_lima_instance(&probes, bad, true).is_err());
            assert!(start_lima_instance(&probes, bad, true).is_err());
            assert!(install_lima_guest_packages(&probes, bad, true).is_err());
            assert!(
                install_lima_guest_helper(&probes, bad, Path::new("artifact"), HELPER_SHA256, true)
                    .is_err()
            );
        }
        assert!(
            probes
                .calls
                .borrow()
                .iter()
                .all(|call| call.starts_with("snapshot "))
        );
    }

    #[test]
    fn verified_guest_helper_is_installed_with_fixed_argv_and_exact_postconditions() {
        let mut probes = lima_probes();
        seed_helper_install(&mut probes);

        let action = install_lima_guest_helper(
            &probes,
            "sandbox-guard",
            Path::new("release/guard-helper"),
            HELPER_SHA256,
            true,
        )
        .unwrap();
        assert_eq!(
            action.as_deref(),
            Some(concat!(
                "installed and verified guard-helper ",
                env!("CARGO_PKG_VERSION"),
                " in mountless Lima instance sandbox-guard"
            ))
        );
        let calls = probes.calls.borrow();
        assert!(calls.contains(&helper_copy_key("sandbox-guard")));
        assert!(calls.contains(&helper_install_key("sandbox-guard")));
        assert!(calls.contains(&helper_activate_key("sandbox-guard")));
        assert!(calls.contains(&helper_rm_key("sandbox-guard", HELPER_TEMP)));
        assert!(calls.iter().all(|call| !call.contains(" sh -c ")));
        assert!(helper_install_key("sandbox-guard").contains(
            "/usr/bin/sudo --non-interactive -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root /usr/bin/install --owner=0 --group=0 --mode=0755 --no-target-directory --"
        ));
        drop(calls);
        assert_no_destructive_lifecycle_mutation(&probes);
    }

    #[test]
    fn exact_guest_helper_is_an_idempotent_noop_before_confirmation() {
        let mut probes = lima_probes();
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{}}"#,
                "",
            ),
        );
        probes.outputs.insert(
            mount_inspection_key("sandbox-guard"),
            output(true, "/ ext4\n", ""),
        );
        probes.outputs.insert(
            guest_hash_key("sandbox-guard", DEFAULT_GUEST_HELPER),
            guest_hash_output(DEFAULT_GUEST_HELPER),
        );
        probes.outputs.insert(
            helper_stat_key("sandbox-guard", DEFAULT_GUEST_HELPER),
            output(true, "regular file:1:0:0:755\n", ""),
        );
        probes.outputs.insert(
            helper_version_key("sandbox-guard", DEFAULT_GUEST_HELPER),
            output(
                true,
                &format!("guard-helper {}\n", env!("CARGO_PKG_VERSION")),
                "",
            ),
        );
        assert_eq!(
            install_lima_guest_helper(
                &probes,
                "sandbox-guard",
                Path::new("artifact"),
                HELPER_SHA256,
                false,
            )
            .unwrap(),
            None
        );
        let calls = probes.calls.borrow();
        assert!(!calls.iter().any(|call| call.contains(" copy ")));
        assert!(!calls.iter().any(|call| call.contains(GUEST_INSTALL)));
    }

    #[test]
    fn symlink_or_hardlinked_installed_helper_is_never_an_exact_noop() {
        for metadata in [
            "symbolic link:1:0:0:777\n",
            "regular file:2:0:0:755\n",
            "regular file:1:501:20:755\n",
        ] {
            let mut probes = lima_probes();
            probes.outputs.insert(
                guest_hash_key("sandbox-guard", DEFAULT_GUEST_HELPER),
                guest_hash_output(DEFAULT_GUEST_HELPER),
            );
            probes.outputs.insert(
                helper_stat_key("sandbox-guard", DEFAULT_GUEST_HELPER),
                output(true, metadata, ""),
            );
            assert!(
                !guest_helper_matches(&probes, Path::new(LIMACTL), "sandbox-guard", HELPER_SHA256,)
                    .unwrap()
            );
            assert!(
                require_installed_guest_helper(
                    &probes,
                    Path::new(LIMACTL),
                    "sandbox-guard",
                    HELPER_SHA256,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn unsafe_target_or_bad_snapshot_never_copies_or_installs_helper() {
        let mut unsafe_probes = lima_probes();
        unsafe_probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{"mounts":[{"location":"/Users"}]}}"#,
                "",
            ),
        );
        assert!(
            install_lima_guest_helper(
                &unsafe_probes,
                "sandbox-guard",
                Path::new("artifact"),
                HELPER_SHA256,
                true,
            )
            .is_err()
        );
        assert!(
            !unsafe_probes
                .calls
                .borrow()
                .contains(&helper_copy_key("sandbox-guard"))
        );

        let mut bad_snapshot = lima_probes();
        bad_snapshot.snapshot_error = Some("symlink, race, digest, or ELF rejected".to_owned());
        assert!(
            install_lima_guest_helper(
                &bad_snapshot,
                "sandbox-guard",
                Path::new("artifact"),
                HELPER_SHA256,
                true,
            )
            .is_err()
        );
        assert_eq!(bad_snapshot.calls.borrow().len(), 1);
    }

    #[test]
    fn copy_install_and_postcondition_failures_never_claim_success_or_rollback() {
        for failed_key in [
            helper_copy_key("sandbox-guard"),
            helper_install_key("sandbox-guard"),
            helper_activate_key("sandbox-guard"),
            helper_version_key("sandbox-guard", DEFAULT_GUEST_HELPER),
        ] {
            let mut probes = lima_probes();
            seed_helper_install(&mut probes);
            probes
                .outputs
                .insert(failed_key.clone(), output(false, "", "hostile failure"));
            let error = install_lima_guest_helper(
                &probes,
                "sandbox-guard",
                Path::new("artifact"),
                HELPER_SHA256,
                true,
            )
            .unwrap_err();
            let rendered = format!("{error:#}");
            assert!(rendered.contains("temporary") || rendered.contains("copy may be partial"));
            assert!(
                probes.calls.borrow().iter().all(|call| {
                    !call.contains(" stop ")
                        && !call.contains(" delete")
                        && !call.contains(" reconfigure")
                }),
                "unexpected rollback/lifecycle call: {:?}",
                probes.calls.borrow()
            );
        }
    }

    #[test]
    fn root_temporary_helper_must_pass_exact_checks_before_activation() {
        let mut probes = lima_probes();
        seed_helper_install(&mut probes);
        probes.outputs.insert(
            helper_stat_key("sandbox-guard", HELPER_ROOT_TEMP),
            output(true, "regular file:2:0:0:755\n", ""),
        );
        let error = install_lima_guest_helper(
            &probes,
            "sandbox-guard",
            Path::new("artifact"),
            HELPER_SHA256,
            true,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("pre-activation check"));
        let calls = probes.calls.borrow();
        assert!(!calls.contains(&helper_activate_key("sandbox-guard")));
        assert!(calls.contains(&helper_rm_key("sandbox-guard", HELPER_TEMP)));
        assert!(calls.contains(&helper_rm_key("sandbox-guard", HELPER_ROOT_TEMP)));
    }

    #[test]
    fn guest_state_race_immediately_before_activation_leaves_truthful_residuals() {
        let mut probes = lima_probes();
        seed_helper_install(&mut probes);
        let running = output(
            true,
            r#"{"name":"sandbox-guard","status":"Running","config":{"mounts":[]}}"#,
            "",
        );
        let stopped = output(
            true,
            r#"{"name":"sandbox-guard","status":"Stopped","config":{"mounts":[]}}"#,
            "",
        );
        queue_outputs(
            &probes,
            list_key(None),
            vec![
                running.clone(),
                running.clone(),
                running.clone(),
                running.clone(),
                running,
                stopped,
            ],
        );
        let error = install_lima_guest_helper(
            &probes,
            "sandbox-guard",
            Path::new("artifact"),
            HELPER_SHA256,
            true,
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("artifacts may remain"));
        assert!(rendered.contains(HELPER_TEMP));
        assert!(rendered.contains(HELPER_ROOT_TEMP));
        let calls = probes.calls.borrow();
        assert!(!calls.contains(&helper_activate_key("sandbox-guard")));
        assert!(!calls.contains(&helper_rm_key("sandbox-guard", HELPER_TEMP)));
        assert_no_destructive_lifecycle_mutation(&probes);
    }

    #[test]
    fn wrong_copied_hash_is_cleaned_without_installing() {
        let mut probes = lima_probes();
        seed_helper_install(&mut probes);
        probes.outputs.insert(
            guest_hash_key("sandbox-guard", HELPER_TEMP),
            output(true, &format!("{}  {HELPER_TEMP}\n", "0".repeat(64)), ""),
        );
        let error = install_lima_guest_helper(
            &probes,
            "sandbox-guard",
            Path::new("artifact"),
            HELPER_SHA256,
            true,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("SHA-256 verification"));
        assert!(
            !probes
                .calls
                .borrow()
                .contains(&helper_install_key("sandbox-guard"))
        );
        assert!(
            probes
                .calls
                .borrow()
                .contains(&helper_rm_key("sandbox-guard", HELPER_TEMP))
        );
    }

    #[test]
    fn internal_temp_path_injection_is_rejected_before_copy() {
        let mut probes = lima_probes();
        seed_helper_install(&mut probes);
        probes.helper_temp_path = Some("/tmp/helper;touch /Users/pwned".to_owned());
        assert!(
            install_lima_guest_helper(
                &probes,
                "sandbox-guard",
                Path::new("artifact"),
                HELPER_SHA256,
                true,
            )
            .is_err()
        );
        assert!(
            !probes
                .calls
                .borrow()
                .contains(&helper_copy_key("sandbox-guard"))
        );
    }

    #[test]
    fn helper_confirmation_phrase_is_exact() {
        assert!(guest_helper_install_phrase_matches(
            "sandbox-guard",
            "INSTALL GUEST HELPER sandbox-guard\n"
        ));
        for bad in [
            "yes\n",
            " INSTALL GUEST HELPER sandbox-guard\n",
            "INSTALL GUEST HELPER sandbox-guard \n",
            "INSTALL GUEST HELPER other\n",
        ] {
            assert!(!guest_helper_install_phrase_matches("sandbox-guard", bad));
        }
    }

    #[test]
    fn helper_artifact_snapshot_rejects_symlink_hash_and_wrong_elf() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = temp.path().join("helper");
        let mut elf = vec![0_u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        fs::write(&artifact, &elf).unwrap();
        let digest: [u8; 32] = Sha256::digest(&elf).into();
        let snapshot = create_guest_helper_snapshot_in(&artifact, &digest, temp.path()).unwrap();
        assert_eq!(fs::read(&snapshot.path).unwrap(), elf);
        let snapshot_parent = snapshot.path.parent().unwrap();
        assert_eq!(
            fs::symlink_metadata(snapshot_parent)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(snapshot_parent.starts_with(temp.path()));

        let wrong = [0_u8; 32];
        assert!(create_guest_helper_snapshot_in(&artifact, &wrong, temp.path()).is_err());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        fs::write(&artifact, &elf).unwrap();
        let digest: [u8; 32] = Sha256::digest(&elf).into();
        assert!(create_guest_helper_snapshot_in(&artifact, &digest, temp.path()).is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&artifact, &link).unwrap();
        assert!(create_guest_helper_snapshot_in(&link, &digest, temp.path()).is_err());
        let hardlink = temp.path().join("hardlink");
        fs::hard_link(&artifact, &hardlink).unwrap();
        assert!(create_guest_helper_snapshot_in(&artifact, &digest, temp.path()).is_err());
    }

    #[test]
    fn snapshot_rejects_symlinked_home_anchor_and_escapes_hostile_artifact_path() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();
        let home_link = temp.path().join("home-link");
        std::os::unix::fs::symlink(&home, &home_link).unwrap();
        let missing = temp.path().join("bad\u{1b}]0;title\u{7}\u{202e}path");
        let error = create_guest_helper_snapshot_in(&missing, &[0_u8; 32], &home_link).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(rendered.contains("\\\\u{1b}"));

        let artifact = home.join("helper");
        let mut elf = vec![0_u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        fs::write(&artifact, &elf).unwrap();
        let digest: [u8; 32] = Sha256::digest(&elf).into();
        assert!(create_guest_helper_snapshot_in(&artifact, &digest, &home_link).is_err());
    }

    #[test]
    fn malformed_checksum_is_rejected_before_snapshot_or_guest_probe() {
        for checksum in ["00", &"g".repeat(64)] {
            let probes = lima_probes();
            assert!(
                install_lima_guest_helper(
                    &probes,
                    "sandbox-guard",
                    Path::new("artifact"),
                    checksum,
                    true,
                )
                .is_err()
            );
            assert!(probes.calls.borrow().is_empty());
        }
    }

    #[test]
    fn stable_file_check_detects_artifact_change_or_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = temp.path().join("helper");
        fs::write(&artifact, vec![0_u8; 64]).unwrap();
        let before = fs::metadata(&artifact).unwrap();
        fs::write(&artifact, vec![1_u8; 65]).unwrap();
        let changed = fs::metadata(&artifact).unwrap();
        assert!(!same_stable_file(&before, &changed));
        fs::remove_file(&artifact).unwrap();
        fs::write(&artifact, vec![0_u8; 64]).unwrap();
        let replaced = fs::metadata(&artifact).unwrap();
        assert!(!same_stable_file(&before, &replaced));
    }

    #[test]
    fn instance_creation_confirmation_phrase_is_exact() {
        assert!(instance_creation_phrase_matches(
            "sandbox-guard",
            "CREATE LIMA INSTANCE sandbox-guard\n"
        ));
        assert!(instance_creation_phrase_matches(
            "sandbox-guard",
            "CREATE LIMA INSTANCE sandbox-guard\r\n"
        ));
        for answer in [
            "yes\n",
            " CREATE LIMA INSTANCE sandbox-guard\n",
            "CREATE LIMA INSTANCE sandbox-guard \n",
            "CREATE LIMA INSTANCE other\n",
        ] {
            assert!(!instance_creation_phrase_matches("sandbox-guard", answer));
        }
    }

    #[test]
    fn stopped_instance_is_started_mountless_verified_and_recorded() {
        let mut probes = lima_probes();
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Stopped","config":{"mounts":[]}}"#,
                "",
            ),
        );
        probes
            .outputs
            .insert(start_key("sandbox-guard"), output(true, "", ""));
        probes.outputs.insert(
            list_key(Some("sandbox-guard")),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{"mounts":[]}}"#,
                "",
            ),
        );
        probes.outputs.insert(
            mount_inspection_key("sandbox-guard"),
            output(true, "/ ext4\n/workspace tmpfs\n", ""),
        );

        let action = start_lima_instance(&probes, "sandbox-guard", true).unwrap();
        assert_eq!(
            action.as_deref(),
            Some("started mountless Lima instance sandbox-guard and verified its live mounts")
        );
        assert_eq!(
            probes.calls.borrow().clone(),
            vec![
                list_key(None),
                start_key("sandbox-guard"),
                list_key(Some("sandbox-guard")),
                mount_inspection_key("sandbox-guard"),
            ]
        );
        assert_no_destructive_lifecycle_mutation(&probes);
    }

    #[test]
    fn running_mountless_instance_is_a_start_noop_without_prompt() {
        let mut probes = lima_probes();
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{}}"#,
                "",
            ),
        );
        let action = start_lima_instance(&probes, "sandbox-guard", false).unwrap();
        assert_eq!(action, None);
        assert_eq!(probes.calls.borrow().clone(), vec![list_key(None)]);
        assert_no_destructive_lifecycle_mutation(&probes);
    }

    #[test]
    fn absent_unsafe_or_ambiguous_instance_is_never_started() {
        for listing in [
            output(true, "", ""),
            output(true, r#"{"name":"sandbox-guard","status":"Stopped"}"#, ""),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Stopped","config":{"mounts":[{"location":"/Users"}]}}"#,
                "",
            ),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Stopped","config":{"mounts":"/Users"}}"#,
                "",
            ),
            output(
                true,
                r#"{"name":"sandbox-guard","config":{"mounts":[]}}"#,
                "",
            ),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Broken","config":{"mounts":[]}}"#,
                "",
            ),
            output(
                true,
                "{\"name\":\"sandbox-guard\",\"status\":\"Stopped\",\"config\":{}}\n{\"name\":\"sandbox-guard\",\"status\":\"Stopped\",\"config\":{}}",
                "",
            ),
        ] {
            let mut probes = lima_probes();
            probes.outputs.insert(list_key(None), listing);
            probes
                .outputs
                .insert(start_key("sandbox-guard"), output(true, "", ""));
            assert!(start_lima_instance(&probes, "sandbox-guard", true).is_err());
            assert_eq!(probes.calls.borrow().clone(), vec![list_key(None)]);
            assert_no_lifecycle_mutation(&probes);
        }
    }

    #[test]
    fn unsafe_start_postcondition_fails_closed_and_never_stops_or_deletes() {
        for verify in [
            output(true, r#"{"name":"sandbox-guard","status":"Running"}"#, ""),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{"mounts":[{"location":"/Users"}]}}"#,
                "",
            ),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Stopped","config":{}}"#,
                "",
            ),
            output(
                true,
                r#"{"name":"other","status":"Running","config":{}}"#,
                "",
            ),
            output(
                true,
                "{\"name\":\"sandbox-guard\",\"status\":\"Running\",\"config\":{}}\n{\"name\":\"other\",\"status\":\"Running\",\"config\":{}}",
                "",
            ),
            output(false, "", "list failed"),
        ] {
            let mut probes = lima_probes();
            probes.outputs.insert(
                list_key(None),
                output(
                    true,
                    r#"{"name":"sandbox-guard","status":"Stopped","config":{}}"#,
                    "",
                ),
            );
            probes
                .outputs
                .insert(start_key("sandbox-guard"), output(true, "", ""));
            probes
                .outputs
                .insert(list_key(Some("sandbox-guard")), verify);
            assert!(start_lima_instance(&probes, "sandbox-guard", true).is_err());
            assert!(probes.calls.borrow().contains(&start_key("sandbox-guard")));
            assert_no_destructive_lifecycle_mutation(&probes);
        }

        for mounts in [
            output(true, "/Users virtiofs\n", ""),
            output(false, "", "findmnt failed"),
        ] {
            let mut probes = lima_probes();
            probes.outputs.insert(
                list_key(None),
                output(
                    true,
                    r#"{"name":"sandbox-guard","status":"Stopped","config":{}}"#,
                    "",
                ),
            );
            probes
                .outputs
                .insert(start_key("sandbox-guard"), output(true, "", ""));
            probes.outputs.insert(
                list_key(Some("sandbox-guard")),
                output(
                    true,
                    r#"{"name":"sandbox-guard","status":"Running","config":{}}"#,
                    "",
                ),
            );
            probes
                .outputs
                .insert(mount_inspection_key("sandbox-guard"), mounts);
            assert!(start_lima_instance(&probes, "sandbox-guard", true).is_err());
            assert_no_destructive_lifecycle_mutation(&probes);
        }
    }

    #[test]
    fn missing_guest_packages_are_installed_with_fixed_argv_and_verified() {
        let mut probes = lima_probes();
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{"mounts":[]}}"#,
                "",
            ),
        );
        probes.outputs.insert(
            mount_inspection_key("sandbox-guard"),
            output(true, "/ ext4\n/workspace tmpfs\n", ""),
        );
        probes.outputs.insert(
            package_probe_key("sandbox-guard"),
            output(false, "", "missing packages"),
        );
        for path in [GUEST_SUDO, GUEST_ENV, GUEST_APT_GET] {
            probes.outputs.insert(
                guest_test_key("sandbox-guard", "-x", path),
                output(true, "", ""),
            );
        }
        let update = guest_apt_key("sandbox-guard", &["update"]);
        let mut install_args = vec!["install", "--yes", "--no-install-recommends", "--reinstall"];
        install_args.extend_from_slice(GUEST_PACKAGE_NAMES);
        let install = guest_apt_key("sandbox-guard", &install_args);
        probes.outputs.insert(update.clone(), output(true, "", ""));
        probes.outputs.insert(install.clone(), output(true, "", ""));
        for (_, path) in GUEST_PACKAGE_EXECUTABLES {
            probes.outputs.insert(
                guest_test_key("sandbox-guard", "-x", path),
                output(true, "", ""),
            );
        }
        probes.outputs.insert(
            guest_test_key("sandbox-guard", "-s", GUEST_CA_BUNDLE),
            output(true, "", ""),
        );

        let action = install_lima_guest_packages(&probes, "sandbox-guard", true).unwrap();
        assert_eq!(
            action.as_deref(),
            Some("installed and verified the fixed Lima guest package-name set in sandbox-guard")
        );
        let calls = probes.calls.borrow();
        assert_eq!(calls.iter().filter(|call| **call == update).count(), 1);
        assert_eq!(calls.iter().filter(|call| **call == install).count(), 1);
        assert!(install.contains("/usr/bin/sudo --non-interactive -- /usr/bin/env -i"));
        assert!(install.contains("DEBIAN_FRONTEND=noninteractive"));
        assert!(install.contains("--no-install-recommends --reinstall"));
        assert!(install.contains("bubblewrap git ca-certificates rsync util-linux"));
        assert_eq!(
            calls.iter().filter(|call| **call == list_key(None)).count(),
            4
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| **call == mount_inspection_key("sandbox-guard"))
                .count(),
            4
        );
        assert!(calls.iter().all(|call| !call.contains(" sh -c ")));
        drop(calls);
        assert_no_destructive_lifecycle_mutation(&probes);
    }

    #[test]
    fn complete_guest_package_set_is_an_idempotent_noop_before_confirmation() {
        let mut probes = lima_probes();
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{}}"#,
                "",
            ),
        );
        probes.outputs.insert(
            mount_inspection_key("sandbox-guard"),
            output(true, "/ ext4\n", ""),
        );
        probes
            .outputs
            .insert(package_probe_key("sandbox-guard"), output(true, "", ""));

        // assume_yes=false proves the complete branch returns before prompting.
        assert_eq!(
            install_lima_guest_packages(&probes, "sandbox-guard", false).unwrap(),
            None
        );
        assert_eq!(
            probes.calls.borrow().clone(),
            vec![
                list_key(None),
                mount_inspection_key("sandbox-guard"),
                package_probe_key("sandbox-guard"),
            ]
        );
        assert_no_package_mutation(&probes);
    }

    #[test]
    fn missing_post_install_artifact_fails_without_recording_success_or_cleanup() {
        let mut probes = lima_probes();
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{}}"#,
                "",
            ),
        );
        probes.outputs.insert(
            mount_inspection_key("sandbox-guard"),
            output(true, "/ ext4\n", ""),
        );
        probes.outputs.insert(
            package_probe_key("sandbox-guard"),
            output(false, "", "missing"),
        );
        for path in [GUEST_SUDO, GUEST_ENV, GUEST_APT_GET] {
            probes.outputs.insert(
                guest_test_key("sandbox-guard", "-x", path),
                output(true, "", ""),
            );
        }
        probes.outputs.insert(
            guest_apt_key("sandbox-guard", &["update"]),
            output(true, "", ""),
        );
        let mut install_args = vec!["install", "--yes", "--no-install-recommends", "--reinstall"];
        install_args.extend_from_slice(GUEST_PACKAGE_NAMES);
        probes.outputs.insert(
            guest_apt_key("sandbox-guard", &install_args),
            output(true, "", ""),
        );
        probes.outputs.insert(
            guest_test_key("sandbox-guard", "-x", GUEST_BWRAP),
            output(false, "", "missing after apt"),
        );

        let error = install_lima_guest_packages(&probes, "sandbox-guard", true).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("post-condition failed"));
        assert!(rendered.contains("will not uninstall or roll back"));
        assert!(probes.calls.borrow().iter().all(|call| {
            !call.contains(" autoremove") && !call.contains(" remove ") && !call.contains(" clean")
        }));
        assert_no_destructive_lifecycle_mutation(&probes);
    }

    #[test]
    fn unsafe_or_nonrunning_guest_is_never_provisioned() {
        for (listing, mounts) in [
            (output(true, "", ""), None),
            (
                output(
                    true,
                    r#"{"name":"sandbox-guard","status":"Stopped","config":{}}"#,
                    "",
                ),
                None,
            ),
            (
                output(
                    true,
                    r#"{"name":"sandbox-guard","status":"Running","config":{"mounts":[{"location":"/Users"}]}}"#,
                    "",
                ),
                None,
            ),
            (
                output(
                    true,
                    r#"{"name":"sandbox-guard","status":"Running","config":{}}"#,
                    "",
                ),
                Some(output(true, "/Users virtiofs\n", "")),
            ),
        ] {
            let mut probes = lima_probes();
            probes.outputs.insert(list_key(None), listing);
            if let Some(mounts) = mounts {
                probes
                    .outputs
                    .insert(mount_inspection_key("sandbox-guard"), mounts);
            }
            assert!(install_lima_guest_packages(&probes, "sandbox-guard", true).is_err());
            assert_no_package_mutation(&probes);
            assert_no_lifecycle_mutation(&probes);
        }
    }

    #[test]
    fn guest_state_change_after_update_prevents_package_install() {
        let mut probes = lima_probes();
        let running = output(
            true,
            r#"{"name":"sandbox-guard","status":"Running","config":{}}"#,
            "",
        );
        let stopped = output(
            true,
            r#"{"name":"sandbox-guard","status":"Stopped","config":{}}"#,
            "",
        );
        queue_outputs(
            &probes,
            list_key(None),
            vec![running.clone(), running, stopped],
        );
        probes.outputs.insert(
            mount_inspection_key("sandbox-guard"),
            output(true, "/ ext4\n", ""),
        );
        probes.outputs.insert(
            package_probe_key("sandbox-guard"),
            output(false, "", "missing"),
        );
        for path in [GUEST_SUDO, GUEST_ENV, GUEST_APT_GET] {
            probes.outputs.insert(
                guest_test_key("sandbox-guard", "-x", path),
                output(true, "", ""),
            );
        }
        let update = guest_apt_key("sandbox-guard", &["update"]);
        probes.outputs.insert(update.clone(), output(true, "", ""));
        let mut install_args = vec!["install", "--yes", "--no-install-recommends", "--reinstall"];
        install_args.extend_from_slice(GUEST_PACKAGE_NAMES);
        let install = guest_apt_key("sandbox-guard", &install_args);

        let error = install_lima_guest_packages(&probes, "sandbox-guard", true).unwrap_err();
        assert!(format!("{error:#}").contains("package-manager state may be partial"));
        let calls = probes.calls.borrow();
        assert!(calls.contains(&update));
        assert!(!calls.contains(&install));
        drop(calls);
        assert_no_destructive_lifecycle_mutation(&probes);
    }

    #[test]
    fn guest_apt_failure_is_terminal_safe_and_never_runs_cleanup() {
        let mut probes = lima_probes();
        probes.outputs.insert(
            list_key(None),
            output(
                true,
                r#"{"name":"sandbox-guard","status":"Running","config":{}}"#,
                "",
            ),
        );
        probes.outputs.insert(
            mount_inspection_key("sandbox-guard"),
            output(true, "/ ext4\n", ""),
        );
        probes.outputs.insert(
            package_probe_key("sandbox-guard"),
            output(false, "", "missing"),
        );
        for path in [GUEST_SUDO, GUEST_ENV, GUEST_APT_GET] {
            probes.outputs.insert(
                guest_test_key("sandbox-guard", "-x", path),
                output(true, "", ""),
            );
        }
        let update = guest_apt_key("sandbox-guard", &["update"]);
        probes.outputs.insert(
            update,
            output(false, "", "boom\u{1b}]0;title\u{7}\u{202e}reversed"),
        );

        let error = install_lima_guest_packages(&probes, "sandbox-guard", true).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(rendered.contains("\\u{1b}"));
        assert!(probes.calls.borrow().iter().all(|call| {
            !call.contains(" autoremove") && !call.contains(" remove ") && !call.contains(" clean")
        }));
        assert_no_destructive_lifecycle_mutation(&probes);
    }

    #[test]
    fn guest_package_install_confirmation_phrase_is_exact() {
        assert!(guest_package_install_phrase_matches(
            "sandbox-guard",
            "INSTALL GUEST PACKAGES sandbox-guard\n"
        ));
        assert!(guest_package_install_phrase_matches(
            "sandbox-guard",
            "INSTALL GUEST PACKAGES sandbox-guard\r\n"
        ));
        for answer in [
            "yes\n",
            " INSTALL GUEST PACKAGES sandbox-guard\n",
            "INSTALL GUEST PACKAGES sandbox-guard \n",
            "INSTALL GUEST PACKAGES other\n",
        ] {
            assert!(!guest_package_install_phrase_matches(
                "sandbox-guard",
                answer
            ));
        }
    }

    #[test]
    fn instance_start_confirmation_phrase_is_exact() {
        assert!(instance_start_phrase_matches(
            "sandbox-guard",
            "START LIMA INSTANCE sandbox-guard\n"
        ));
        assert!(instance_start_phrase_matches(
            "sandbox-guard",
            "START LIMA INSTANCE sandbox-guard\r\n"
        ));
        for answer in [
            "yes\n",
            " START LIMA INSTANCE sandbox-guard\n",
            "START LIMA INSTANCE sandbox-guard \n",
            "START LIMA INSTANCE other\n",
        ] {
            assert!(!instance_start_phrase_matches("sandbox-guard", answer));
        }
    }

    #[test]
    fn json_start_without_yes_is_rejected_before_probing() {
        let probes = lima_probes();
        let error = run_start_instance(
            &probes,
            BackendKind::MacosLima,
            "sandbox-guard",
            false,
            true,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("--yes"));
        assert!(probes.calls.borrow().is_empty());
    }

    #[test]
    fn json_create_without_yes_is_rejected_before_probing() {
        let probes = lima_probes();
        let error = run_create_instance(
            &probes,
            BackendKind::MacosLima,
            "sandbox-guard",
            false,
            true,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("--yes"));
        assert!(probes.calls.borrow().is_empty());
    }

    #[test]
    fn json_guest_packages_without_yes_is_rejected_before_probing() {
        let probes = lima_probes();
        let error = run_install_guest_packages(
            &probes,
            BackendKind::MacosLima,
            "sandbox-guard",
            false,
            true,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("--yes"));
        assert!(probes.calls.borrow().is_empty());
    }

    #[test]
    fn json_guest_helper_without_yes_is_rejected_before_snapshot_or_probing() {
        let probes = lima_probes();
        let error = run_install_guest_helper(
            &probes,
            BackendKind::MacosLima,
            "sandbox-guard",
            Path::new("artifact"),
            HELPER_SHA256,
            false,
            true,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("--yes"));
        assert!(probes.calls.borrow().is_empty());
    }

    #[test]
    fn linux_backend_rejects_create_before_mutation() {
        let probes = lima_probes();
        assert!(
            run_create_instance(
                &probes,
                BackendKind::LinuxBwrap,
                "sandbox-guard",
                true,
                false
            )
            .is_err()
        );
        assert!(probes.calls.borrow().is_empty());
        assert!(
            validate_instance_action_target("--create-instance", BackendKind::MacosLima, "linux")
                .is_err()
        );
        assert!(
            validate_instance_action_target(
                "--install-guest-packages",
                BackendKind::LinuxBwrap,
                "macos"
            )
            .is_err()
        );
        assert!(
            validate_instance_action_target(
                "--install-guest-helper",
                BackendKind::LinuxBwrap,
                "macos"
            )
            .is_err()
        );
    }

    #[test]
    fn clap_conflicts_create_instance_with_check() {
        assert!(Cli::try_parse_from(["guard", "setup", "--check"]).is_ok());
        assert!(Cli::try_parse_from(["guard", "setup", "--create-instance", "--yes"]).is_ok());
        assert!(Cli::try_parse_from(["guard", "setup", "--start-instance", "--yes"]).is_ok());
        assert!(
            Cli::try_parse_from(["guard", "setup", "--install-guest-packages", "--yes"]).is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "guard",
                "setup",
                "--install-guest-helper",
                "guard-helper",
                "--guest-helper-sha256",
                HELPER_SHA256,
                "--yes",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["guard", "setup", "--install-guest-helper", "guard-helper"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["guard", "setup", "--guest-helper-sha256", HELPER_SHA256,])
                .is_err()
        );
        assert!(Cli::try_parse_from(["guard", "setup", "--check", "--create-instance"]).is_err());
        assert!(Cli::try_parse_from(["guard", "setup", "--check", "--start-instance"]).is_err());
        assert!(
            Cli::try_parse_from(["guard", "setup", "--create-instance", "--start-instance"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["guard", "setup", "--check", "--install-guest-packages"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "guard",
                "setup",
                "--start-instance",
                "--install-guest-packages",
            ])
            .is_err()
        );
        for action in [
            "--check",
            "--create-instance",
            "--start-instance",
            "--install-guest-packages",
        ] {
            assert!(
                Cli::try_parse_from([
                    "guard",
                    "setup",
                    action,
                    "--install-guest-helper",
                    "guard-helper",
                    "--guest-helper-sha256",
                    HELPER_SHA256,
                ])
                .is_err()
            );
        }
        assert!(
            Cli::try_parse_from([
                "guard",
                "setup",
                "--create-instance",
                "--install-guest-packages",
            ])
            .is_err()
        );
        // `--yes` is deliberately inert without an explicit action, which lets future setup
        // actions reuse the confirmation flag without widening any current command path.
        assert!(Cli::try_parse_from(["guard", "setup", "--yes"]).is_ok());
    }

    #[test]
    fn concise_output_escapes_control_and_bidi_bytes() {
        let hostile = b"line1\nline2\x1b]0;hijack\x07\xe2\x80\xaereversed";
        let rendered = concise_output(hostile);
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("\\u{1b}"));
        assert!(rendered.contains("line1 line2"));
    }
}
