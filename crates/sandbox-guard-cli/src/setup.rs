use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use directories::{BaseDirs, ProjectDirs};
use sandbox_guard_core::CompiledPolicy;
use sandbox_guard_runner::BackendKind;
use serde::Serialize;

use crate::{SetupArgs, current_uid};

const REPORT_SCHEMA: u32 = 1;
const DEFAULT_GUEST_HELPER: &str = "/usr/local/bin/guard-helper";

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
            pending_changes: data.join("pending-changes"),
            tools: data.join("tools"),
            data,
            config,
        })
    }

    fn private_directories(&self) -> [(&'static str, &Path); 5] {
        [
            ("state.data.private", &self.data),
            ("state.config.private", &self.config),
            ("state.audit.private", &self.audit),
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

trait SetupProbes {
    fn which(&self, name: &str) -> Option<PathBuf>;
    fn host_helper_path(&self) -> Option<PathBuf>;
    fn output(&self, program: &Path, args: &[OsString]) -> std::io::Result<ProbeOutput>;
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
    fn openat2_available(&self) -> std::result::Result<bool, String>;
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
    let output = lima_shell(
        probes,
        limactl,
        instance,
        &["findmnt", "--noheadings", "--output", "TARGET,FSTYPE"],
    )
    .map_err(|error| anyhow!("failed to inspect live Lima mounts after startup: {error}"))?;
    if !output.success {
        bail!(
            "live mount inspection failed after startup: {}; inspect the running instance manually, and Guard will not stop or delete it",
            concise_failure(&output)
        );
    }
    let mounts = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = mounts.lines().find(|line| is_host_sharing_mount(line)) {
        bail!(
            "unsafe live host-sharing mount detected after startup: {}; inspect and remove the instance manually, and Guard will not stop or delete it",
            sanitize_terminal_fragment(line.trim())
        );
    }
    Ok(())
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
        &["findmnt", "--noheadings", "--output", "TARGET,FSTYPE"],
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

    let packages = lima_shell(
        probes,
        &limactl,
        instance,
        &[
            "sh",
            "-c",
            "missing=0; for name in bwrap git rsync findmnt; do command -v \"$name\" >/dev/null || { echo \"$name\"; missing=1; }; done; exit \"$missing\"",
        ],
    );
    checks.push(command_result_check(
        "lima.guest.packages",
        "lima-guest",
        packages,
        "guest contains bwrap, git, rsync, and findmnt",
        manual_repair(
            "Install the required packages inside the guest; Guard never invokes guest sudo.",
            &["sudo", "network"],
            &[
                &format!("limactl shell {shell_instance} -- sudo apt-get update"),
                &format!(
                    "limactl shell {} -- sudo apt-get install -y bubblewrap git rsync util-linux ca-certificates",
                    shell_instance
                ),
            ],
        ),
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
            "Install the guard-helper from the same verified release as guard; setup does not trust an arbitrary helper artifact.",
            &["confirmation"],
            &[],
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
    use std::ffi::OsStr;
    use tempfile::TempDir;

    #[derive(Default)]
    struct FakeProbes {
        executables: BTreeMap<String, PathBuf>,
        host_helper: Option<PathBuf>,
        outputs: BTreeMap<String, ProbeOutput>,
        calls: RefCell<Vec<String>>,
        files: BTreeMap<PathBuf, String>,
        openat2: bool,
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
        assert_eq!(apply_safe_repairs(&report, &paths).unwrap().len(), 5);
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
                    "findmnt",
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
                    "missing=0; for name in bwrap git rsync findmnt; do command -v \"$name\" >/dev/null || { echo \"$name\"; missing=1; }; done; exit \"$missing\"",
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

    fn mount_inspection_key(instance: &str) -> String {
        command_key(
            Path::new(LIMACTL),
            &[
                OsString::from("--tty=false"),
                OsString::from("shell"),
                OsString::from(instance),
                OsString::from("--"),
                OsString::from("findmnt"),
                OsString::from("--noheadings"),
                OsString::from("--output"),
                OsString::from("TARGET,FSTYPE"),
            ],
        )
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
        }
        assert!(probes.calls.borrow().is_empty());
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
    }

    #[test]
    fn clap_conflicts_create_instance_with_check() {
        assert!(Cli::try_parse_from(["guard", "setup", "--check"]).is_ok());
        assert!(Cli::try_parse_from(["guard", "setup", "--create-instance", "--yes"]).is_ok());
        assert!(Cli::try_parse_from(["guard", "setup", "--start-instance", "--yes"]).is_ok());
        assert!(Cli::try_parse_from(["guard", "setup", "--check", "--create-instance"]).is_err());
        assert!(Cli::try_parse_from(["guard", "setup", "--check", "--start-instance"]).is_err());
        assert!(
            Cli::try_parse_from(["guard", "setup", "--create-instance", "--start-instance"])
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
