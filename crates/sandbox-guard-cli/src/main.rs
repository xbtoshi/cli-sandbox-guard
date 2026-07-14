use std::env;
use std::ffi::OsString;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use sandbox_guard_core::{
    CompiledPolicy, ResourceLimitRecord, RunRecord, Stage, StageOptions, default_staging_base,
    export_changes, garbage_collect, install_verified_tool, is_valid_candidate_path,
    verify_installed_tool,
};
use sandbox_guard_helper::ProbeReport;
use sandbox_guard_runner::{
    BackendKind, CgroupMode, NetworkMode, ResourceLimits, RunOutcome, RunRequest, ToolSpec, plan,
    run as run_isolated,
};

#[derive(Debug, Parser)]
#[command(
    name = "guard",
    version,
    about = "Run AI coding CLIs against a sanitized, isolated workspace",
    long_about = "Sandbox Guard stages a policy-filtered copy of a repository, constructs fresh Git metadata, and runs an untrusted CLI in a platform isolation backend. The host repository is never mounted into the sandbox."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Stage and run an untrusted tool. Changes are discarded unless explicitly exported.
    Run(RunArgs),
    /// Create a persistent sanitized workspace without running a tool.
    Stage(StageArgs),
    /// Print the effective built-in plus user policy.
    Policy(PolicyArgs),
    /// Check host prerequisites without changing the system.
    Doctor(DoctorArgs),
    /// Remove old, unlocked staging directories owned by the current user.
    Gc(GcArgs),
    /// Execute hostile fixture probes against a real isolation backend.
    Test(TestArgs),
    /// Install or verify a detached-signature-verified tool artifact.
    Tool(ToolArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Repository or directory to sanitize.
    #[arg(long, default_value = ".")]
    source: PathBuf,

    /// Additive user policy in TOML format.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Override the private staging directory base.
    #[arg(long)]
    staging_base: Option<PathBuf>,

    /// Isolation backend. Auto selects Bubblewrap on Linux and Lima on macOS.
    #[arg(long, value_enum, default_value_t = BackendArg::Auto)]
    backend: BackendArg,

    /// Network mode. Denied is the safe default.
    #[arg(long, value_enum, default_value_t = NetworkArg::Denied)]
    network: NetworkArg,

    /// Required acknowledgement for the unrestricted network mode.
    #[arg(long)]
    allow_unrestricted_network: bool,

    /// Allow an exact hostname or *.subdomain suffix in controlled network mode.
    #[arg(long = "allow-host", value_name = "HOST")]
    allow_hosts: Vec<String>,

    /// Forward an environment variable by name. Values are never written to the audit log.
    #[arg(long = "forward-env", value_name = "NAME")]
    forward_env: Vec<String>,

    /// Read-only installation root for a non-system tool.
    #[arg(long)]
    tool_root: Option<PathBuf>,

    /// Managed Lima instance used by the macOS backend.
    #[arg(long, default_value = "sandbox-guard")]
    lima_instance: String,

    /// Runtime helper path (host path on Linux, guest path on macOS).
    #[arg(long)]
    helper: Option<PathBuf>,

    /// cgroup v2 enforcement policy.
    #[arg(long, value_enum, default_value_t = CgroupArg::BestEffort)]
    cgroup: CgroupArg,

    /// Maximum address space and cgroup memory, in MiB.
    #[arg(long, default_value_t = 8192)]
    memory_mib: u64,

    /// Maximum size of one file written by the tool, in MiB.
    #[arg(long, default_value_t = 1024)]
    max_file_mib: u64,

    /// Maximum CPU time consumed by the tool process.
    #[arg(long, default_value_t = 3600)]
    cpu_seconds: u64,

    /// Maximum open file descriptors.
    #[arg(long, default_value_t = 1024)]
    open_files: u64,

    /// Maximum processes/threads; also cgroup TasksMax when available.
    #[arg(long, default_value_t = 256)]
    max_processes: u64,

    /// cgroup CPU quota percentage; 100 is one full CPU.
    #[arg(long, default_value_t = 200)]
    cpu_percent: u64,

    /// Atomically export safe changed files plus a review manifest outside the source tree.
    #[arg(long, value_name = "DIRECTORY")]
    export_changes: Option<PathBuf>,

    /// Skip creation of synthetic Git metadata.
    #[arg(long)]
    no_synthetic_git: bool,

    /// Print the backend invocation with secret values redacted, without running it.
    #[arg(long)]
    dry_run: bool,

    /// Keep the disposable staged workspace after the command exits.
    #[arg(long)]
    keep_stage: bool,

    /// Tool and arguments. Place them after the double dash.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    tool: Vec<OsString>,
}

#[derive(Debug, Args)]
struct StageArgs {
    /// Repository or directory to sanitize.
    #[arg(default_value = ".")]
    source: PathBuf,

    /// Additive user policy in TOML format.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Override the private staging directory base.
    #[arg(long)]
    staging_base: Option<PathBuf>,

    /// Skip creation of synthetic Git metadata.
    #[arg(long)]
    no_synthetic_git: bool,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    /// Additive user policy in TOML format.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Explain whether a relative path is denied.
    #[arg(long)]
    check: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Backend to inspect.
    #[arg(long, value_enum, default_value_t = BackendArg::Auto)]
    backend: BackendArg,
}

#[derive(Debug, Args)]
struct GcArgs {
    /// Override the staging base to inspect.
    #[arg(long)]
    staging_base: Option<PathBuf>,

    /// Minimum age of an orphan before removal.
    #[arg(long, default_value_t = 24)]
    older_than_hours: u64,

    /// Report what would be removed without changing anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct TestArgs {
    /// Backend to execute. Auto selects the native backend.
    #[arg(long, value_enum, default_value_t = BackendArg::Auto)]
    backend: BackendArg,

    /// Managed Lima instance used by the macOS backend.
    #[arg(long, default_value = "sandbox-guard")]
    lima_instance: String,

    /// Runtime helper path (host path on Linux, guest path on macOS).
    #[arg(long)]
    helper: Option<PathBuf>,

    /// Require cgroup v2 enforcement rather than accepting rlimits only.
    #[arg(long)]
    require_cgroup: bool,
}

#[derive(Debug, Args)]
struct ToolArgs {
    #[command(subcommand)]
    command: ToolCommand,
}

#[derive(Debug, Subcommand)]
enum ToolCommand {
    /// Verify an Ed25519 signature and signer fingerprint, then atomically install the artifact.
    Install(ToolInstallArgs),
    /// Re-verify an installed artifact against a pinned signer fingerprint.
    Verify(ToolVerifyArgs),
}

#[derive(Debug, Args)]
struct ToolInstallArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    artifact: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long)]
    signer_sha256: String,
    #[arg(long)]
    store: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ToolVerifyArgs {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    signer_sha256: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackendArg {
    Auto,
    LinuxBwrap,
    MacosLima,
}

impl From<BackendArg> for BackendKind {
    fn from(value: BackendArg) -> Self {
        match value {
            BackendArg::Auto => Self::Auto,
            BackendArg::LinuxBwrap => Self::LinuxBwrap,
            BackendArg::MacosLima => Self::MacosLima,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NetworkArg {
    Denied,
    Controlled,
    Unrestricted,
}

impl From<NetworkArg> for NetworkMode {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Denied => Self::Denied,
            NetworkArg::Controlled => Self::Controlled,
            NetworkArg::Unrestricted => Self::Unrestricted,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CgroupArg {
    Required,
    BestEffort,
    Disabled,
}

impl From<CgroupArg> for CgroupMode {
    fn from(value: CgroupArg) -> Self {
        match value {
            CgroupArg::Required => Self::Required,
            CgroupArg::BestEffort => Self::BestEffort,
            CgroupArg::Disabled => Self::Disabled,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            eprintln!("guard: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Run(args) => run_command(args),
        Command::Stage(args) => stage_command(args),
        Command::Policy(args) => policy_command(args),
        Command::Doctor(args) => doctor_command(args),
        Command::Gc(args) => gc_command(args),
        Command::Test(args) => test_command(args),
        Command::Tool(args) => tool_command(args),
    }
}

fn run_command(args: RunArgs) -> Result<i32> {
    let network: NetworkMode = args.network.into();
    if network == NetworkMode::Unrestricted && !args.allow_unrestricted_network {
        bail!(
            "--network unrestricted exposes services reachable from the backend network; repeat with --allow-unrestricted-network to acknowledge this residual risk"
        );
    }
    if args.dry_run && args.export_changes.is_some() {
        bail!("--export-changes cannot be combined with --dry-run");
    }

    let policy_path = resolve_policy_path(args.policy)?;
    let policy = CompiledPolicy::load(policy_path.as_deref())?;
    let export_policy = policy.clone();
    let source_root = fs::canonicalize(&args.source)
        .with_context(|| format!("failed to resolve source {}", args.source.display()))?;
    let mut options = StageOptions::new(&source_root, policy);
    options.staging_base = args.staging_base;
    options.synthetic_git = !args.no_synthetic_git;
    let mut stage = Stage::build(options).context("staging failed closed")?;

    let (command, tool_args) = args
        .tool
        .split_first()
        .ok_or_else(|| anyhow!("tool command cannot be empty"))?;
    let forwarded_env = collect_forwarded_environment(&args.forward_env)?;
    let resource_limits = resource_limits(
        args.memory_mib,
        args.max_file_mib,
        args.cpu_seconds,
        args.open_files,
        args.max_processes,
        args.cpu_percent,
    )?;
    let backend: BackendKind = args.backend.into();
    let resolved_backend = backend.resolve()?;
    let request = RunRequest {
        workspace: stage.workspace().to_path_buf(),
        run_id: stage.manifest().run_id.to_string(),
        tool: ToolSpec {
            command: command.clone(),
            args: tool_args.to_vec(),
            tool_root: args.tool_root,
        },
        network,
        allowed_egress_hosts: args.allow_hosts.clone(),
        forwarded_env,
        resource_limits,
        cgroup_mode: args.cgroup.into(),
        helper_path: args.helper,
        lima_instance: args.lima_instance,
    };

    print_stage_summary(&stage);
    if args.dry_run {
        let command_plan = plan(&request, resolved_backend)?;
        for warning in &command_plan.warnings {
            eprintln!("warning: {warning}");
        }
        println!("backend: {:?}", resolved_backend);
        println!("plan: {}", command_plan.rendered());
        persist_run_audit(
            &mut stage,
            resolved_backend,
            network,
            command,
            &args.forward_env,
            &request,
            None,
            None,
            false,
        )?;
        if args.keep_stage {
            let kept = stage.keep()?;
            println!("staged workspace kept at {}", kept.workspace.display());
        }
        return Ok(0);
    }

    let result = run_isolated(&request, resolved_backend);
    match result {
        Ok(outcome) => {
            for warning in &outcome.warnings {
                eprintln!("warning: {warning}");
            }
            let success = outcome.status.success();
            let exit_code = outcome.status.code();
            persist_run_audit(
                &mut stage,
                outcome.backend,
                network,
                command,
                &args.forward_env,
                &request,
                Some(&outcome),
                exit_code,
                success,
            )?;
            publish_change_export(
                args.export_changes.as_deref(),
                &stage,
                &source_root,
                &export_policy,
            )?;
            if args.keep_stage {
                let kept = stage.keep()?;
                println!("staged workspace kept at {}", kept.workspace.display());
            }
            Ok(exit_code.unwrap_or(128))
        }
        Err(error) => {
            persist_run_audit(
                &mut stage,
                resolved_backend,
                network,
                command,
                &args.forward_env,
                &request,
                None,
                None,
                false,
            )?;
            Err(error.into())
        }
    }
}

fn stage_command(args: StageArgs) -> Result<i32> {
    let policy_path = resolve_policy_path(args.policy)?;
    let policy = CompiledPolicy::load(policy_path.as_deref())?;
    let mut options = StageOptions::new(&args.source, policy);
    options.staging_base = args.staging_base;
    options.synthetic_git = !args.no_synthetic_git;
    let stage = Stage::build(options).context("staging failed closed")?;
    print_stage_summary(&stage);
    let kept = stage.keep()?;
    println!("workspace: {}", kept.workspace.display());
    println!("audit: {}", kept.audit_path.display());
    Ok(0)
}

fn policy_command(args: PolicyArgs) -> Result<i32> {
    let policy_path = resolve_policy_path(args.policy)?;
    let policy = CompiledPolicy::load(policy_path.as_deref())?;
    if let Some(path) = args.check {
        if !is_valid_candidate_path(&path) {
            bail!("--check expects a non-empty relative path containing no parent components");
        }
        match policy.denied_by_path_or_ancestor(&path) {
            Some(rule) => println!("denied: {} (rule: {rule:?})", path.display()),
            None => println!("allowed by filename policy: {}", path.display()),
        }
    } else {
        println!("{}", serde_json::to_string_pretty(policy.effective())?);
        println!("policy_sha256: {}", policy.hash());
    }
    Ok(0)
}

fn doctor_command(args: DoctorArgs) -> Result<i32> {
    let backend: BackendKind = args.backend.into();
    let resolved = backend.resolve()?;
    let mut healthy = true;

    println!("platform: {}-{}", env::consts::OS, env::consts::ARCH);
    healthy &= report_executable("git", "synthetic Git baseline");
    match resolved {
        BackendKind::LinuxBwrap => {
            healthy &= report_executable("bwrap", "Linux isolation backend");
            healthy &= report_host_helper();
            let _ = report_executable(
                "systemd-run",
                "optional cgroup v2 scope (use --cgroup required to mandate it)",
            );
            println!("linux staging: openat2 required at runtime (Linux 5.6 or newer)");
        }
        BackendKind::MacosLima => {
            healthy &= report_executable("limactl", "macOS Linux-VM backend");
            println!(
                "lima instance: sandbox-guard must be created with --mount-none and contain bwrap, /usr/local/bin/guard-helper, plus the selected tool"
            );
        }
        BackendKind::Auto => unreachable!(),
    }
    let policy = CompiledPolicy::builtin()?;
    println!("policy: ok ({})", policy.hash());
    println!("default user policy: {}", default_policy_path()?.display());
    println!("audit directory: {}", default_audit_dir()?.display());

    if healthy { Ok(0) } else { Ok(1) }
}

fn gc_command(args: GcArgs) -> Result<i32> {
    let base = args.staging_base.unwrap_or_else(default_staging_base);
    let age = Duration::from_secs(args.older_than_hours.saturating_mul(60 * 60));
    let report = garbage_collect(&base, age, args.dry_run)?;
    for path in &report.removed {
        println!("removed: {}", path.display());
    }
    for path in &report.would_remove {
        println!("would remove: {}", path.display());
    }
    println!(
        "gc: removed={}, would_remove={}, active={}, recent={}",
        report.removed.len(),
        report.would_remove.len(),
        report.active.len(),
        report.recent.len()
    );
    Ok(0)
}

fn test_command(args: TestArgs) -> Result<i32> {
    let backend: BackendKind = args.backend.into();
    let backend = backend.resolve()?;
    let fixture = tempfile::tempdir()?;
    fs::write(fixture.path().join("README.md"), "sandbox self-test\n")?;
    fs::write(
        fixture.path().join(".env.self-test"),
        "MUST_NOT_BE_STAGED=true\n",
    )?;
    let outside = tempfile::NamedTempFile::new()?;
    fs::write(outside.path(), "host-only canary\n")?;
    let policy = CompiledPolicy::builtin()?;
    let mut stage_options = StageOptions::new(fixture.path(), policy);
    stage_options.synthetic_git = false;
    let stage = Stage::build(stage_options).context("self-test staging failed closed")?;
    if stage.workspace().join(".env.self-test").exists() {
        bail!("self-test failed: built-in secret policy did not exclude .env.self-test");
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let loopback_port = listener.local_addr()?.port();
    let forbidden_environment = env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .find(|name| {
            !matches!(name.as_str(), "HOME" | "PATH" | "LANG")
                && name.bytes().enumerate().all(|(index, byte)| {
                    matches!(byte, b'A'..=b'Z' | b'_') || (index > 0 && byte.is_ascii_digit())
                })
        })
        .context("self-test could not find a host environment canary")?;
    let helper = resolve_test_helper(backend, args.helper)?;
    let output = stage.workspace().join("probe.json");
    let request = RunRequest {
        workspace: stage.workspace().to_path_buf(),
        run_id: stage.manifest().run_id.to_string(),
        tool: ToolSpec {
            command: helper.as_os_str().to_owned(),
            args: vec![
                OsString::from("probe"),
                OsString::from("--output"),
                OsString::from("/workspace/probe.json"),
                OsString::from("--outside-path"),
                outside.path().as_os_str().to_owned(),
                OsString::from("--host-pid"),
                OsString::from(std::process::id().to_string()),
                OsString::from("--loopback-port"),
                OsString::from(loopback_port.to_string()),
                OsString::from("--forbidden-environment"),
                OsString::from(&forbidden_environment),
            ],
            tool_root: None,
        },
        network: NetworkMode::Denied,
        allowed_egress_hosts: vec![],
        forwarded_env: vec![],
        resource_limits: ResourceLimits::default(),
        cgroup_mode: if args.require_cgroup {
            CgroupMode::Required
        } else {
            CgroupMode::BestEffort
        },
        helper_path: Some(helper),
        lima_instance: args.lima_instance,
    };
    let outcome = run_isolated(&request, backend)?;
    drop(listener);
    if !outcome.status.success() {
        bail!("hostile backend probe exited with {}", outcome.status);
    }
    let report: ProbeReport = serde_json::from_slice(
        &fs::read(&output).context("hostile backend probe did not produce its report")?,
    )?;
    if !report.success {
        bail!("hostile backend probe reported a failed invariant: {report:#?}");
    }
    println!("backend: {backend:?}");
    println!("filesystem boundary: ok");
    println!("environment boundary: ok");
    println!("PID namespace: ok");
    println!("host loopback isolation: ok");
    println!("seccomp namespace-escape denial: ok");
    println!("seccomp thread compatibility: ok");
    println!("trusted supervisor memory: protected");
    println!("rlimits: ok");
    println!(
        "cgroup v2: {}",
        if outcome.cgroup_enforced {
            "enforced"
        } else {
            "unavailable (best-effort mode)"
        }
    );
    Ok(0)
}

fn resolve_test_helper(backend: BackendKind, explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if backend == BackendKind::MacosLima {
        return Ok(PathBuf::from("/usr/local/bin/guard-helper"));
    }
    let current = env::current_exe()?;
    let sibling = current.with_file_name("guard-helper");
    if sibling.is_file() {
        Ok(sibling)
    } else {
        which::which("guard-helper").context(
            "guard-helper is required; build the workspace or pass --helper with its absolute path",
        )
    }
}

fn tool_command(args: ToolArgs) -> Result<i32> {
    match args.command {
        ToolCommand::Install(args) => {
            let store = args.store.unwrap_or(default_tool_store()?);
            let installed = install_verified_tool(
                &args.artifact,
                &args.signature,
                &args.public_key,
                &args.signer_sha256,
                &store,
                &args.name,
                &args.version,
            )?;
            println!(
                "verified signer: {}",
                installed.manifest.signer_fingerprint_sha256
            );
            println!("artifact sha256: {}", installed.manifest.artifact_sha256);
            println!("tool root: {}", installed.root.display());
            println!("executable: {}", installed.executable.display());
            Ok(0)
        }
        ToolCommand::Verify(args) => {
            let installed = verify_installed_tool(&args.root, &args.signer_sha256)?;
            println!(
                "verified: {} {}",
                installed.manifest.name, installed.manifest.version
            );
            println!("artifact sha256: {}", installed.manifest.artifact_sha256);
            println!("executable: {}", installed.executable.display());
            Ok(0)
        }
    }
}

fn default_tool_store() -> Result<PathBuf> {
    let project = ProjectDirs::from("com", "xbtoshi", "sandbox-guard")
        .ok_or_else(|| anyhow!("could not determine the user data directory"))?;
    Ok(project.data_local_dir().join("tools"))
}

fn resource_limits(
    memory_mib: u64,
    max_file_mib: u64,
    cpu_seconds: u64,
    open_files: u64,
    max_processes: u64,
    cpu_percent: u64,
) -> Result<ResourceLimits> {
    if memory_mib == 0
        || max_file_mib == 0
        || cpu_seconds == 0
        || open_files < 16
        || max_processes == 0
        || cpu_percent == 0
    {
        bail!("resource limits must be positive and --open-files must be at least 16");
    }
    Ok(ResourceLimits {
        memory_bytes: memory_mib
            .checked_mul(1024 * 1024)
            .context("--memory-mib overflow")?,
        max_file_bytes: max_file_mib
            .checked_mul(1024 * 1024)
            .context("--max-file-mib overflow")?,
        cpu_seconds,
        open_files,
        max_processes,
        cpu_percent,
    })
}

fn publish_change_export(
    destination: Option<&Path>,
    stage: &Stage,
    source_root: &Path,
    policy: &CompiledPolicy,
) -> Result<()> {
    let Some(destination) = destination else {
        return Ok(());
    };
    let report = export_changes(
        stage.workspace(),
        source_root,
        stage.manifest(),
        policy,
        destination,
    )?;
    println!("changes: {}", report.destination.display());
    println!(
        "change manifest: {} accepted, {} rejected",
        report.manifest.changes.len(),
        report.manifest.rejected.len()
    );
    for rejected in &report.manifest.rejected {
        eprintln!(
            "warning: rejected change {}: {}",
            rejected.path, rejected.reason
        );
    }
    Ok(())
}

fn report_executable(name: &str, purpose: &str) -> bool {
    match which::which(name) {
        Ok(path) => {
            println!("{name}: {} ({purpose})", path.display());
            true
        }
        Err(_) => {
            println!("{name}: MISSING ({purpose})");
            false
        }
    }
}

fn report_host_helper() -> bool {
    let sibling = env::current_exe()
        .ok()
        .map(|path| path.with_file_name("guard-helper"));
    if let Some(path) = sibling.filter(|path| path.is_file()) {
        println!("guard-helper: {} (trusted runtime helper)", path.display());
        true
    } else {
        report_executable("guard-helper", "trusted runtime helper")
    }
}

fn collect_forwarded_environment(names: &[String]) -> Result<Vec<(String, String)>> {
    let mut result = Vec::with_capacity(names.len());
    for name in names {
        let value = env::var(name)
            .with_context(|| format!("--forward-env {name} was requested but is not set"))?;
        result.push((name.clone(), value));
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn persist_run_audit(
    stage: &mut Stage,
    backend: BackendKind,
    network: NetworkMode,
    tool: &OsString,
    environment_names: &[String],
    request: &RunRequest,
    outcome: Option<&RunOutcome>,
    exit_code: Option<i32>,
    success: bool,
) -> Result<()> {
    let limits = request.resource_limits;
    stage.manifest_mut().run = Some(RunRecord {
        backend: format!("{backend:?}"),
        network: network.as_str().to_owned(),
        tool: tool.to_string_lossy().into_owned(),
        forwarded_environment_names: environment_names.to_vec(),
        allowed_egress_hosts: request.allowed_egress_hosts.clone(),
        egress_audit: outcome
            .map(|outcome| outcome.egress_audit.clone())
            .unwrap_or_default(),
        resource_limits: ResourceLimitRecord {
            memory_bytes: limits.memory_bytes,
            max_file_bytes: limits.max_file_bytes,
            cpu_seconds: limits.cpu_seconds,
            open_files: limits.open_files,
            max_processes: limits.max_processes,
            cpu_percent: limits.cpu_percent,
        },
        cgroup_enforced: outcome.is_some_and(|outcome| outcome.cgroup_enforced),
        seccomp_enforced: outcome.is_some_and(|outcome| outcome.seccomp_enforced),
        exit_code,
        success,
    });
    stage.flush_audit()?;
    let timestamp = stage
        .manifest()
        .created_at
        .format("%Y%m%dT%H%M%SZ")
        .to_string();
    let destination =
        default_audit_dir()?.join(format!("{timestamp}-{}.json", stage.manifest().run_id));
    stage.persist_audit(&destination)?;
    println!("audit: {}", destination.display());
    Ok(())
}

fn default_audit_dir() -> Result<PathBuf> {
    let project = ProjectDirs::from("com", "xbtoshi", "sandbox-guard")
        .ok_or_else(|| anyhow!("could not determine the user data directory"))?;
    Ok(project.data_local_dir().join("audit"))
}

fn default_policy_path() -> Result<PathBuf> {
    let project = ProjectDirs::from("com", "xbtoshi", "sandbox-guard")
        .ok_or_else(|| anyhow!("could not determine the user configuration directory"))?;
    Ok(project.config_dir().join("policy.toml"))
}

fn resolve_policy_path(explicit: Option<PathBuf>) -> Result<Option<PathBuf>> {
    if explicit.is_some() {
        return Ok(explicit);
    }
    let default = default_policy_path()?;
    Ok(default.is_file().then_some(default))
}

fn print_stage_summary(stage: &Stage) {
    let totals = &stage.manifest().totals;
    println!(
        "staged: {} files, {} bytes; excluded: {} paths",
        totals.included_files, totals.included_bytes, totals.excluded_paths
    );
    println!("policy: {}", stage.manifest().policy_sha256);
}
