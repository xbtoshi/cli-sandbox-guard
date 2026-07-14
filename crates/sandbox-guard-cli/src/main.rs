use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use sandbox_guard_core::{
    CompiledPolicy, RunRecord, Stage, StageOptions, default_staging_base, garbage_collect,
    is_valid_candidate_path,
};
use sandbox_guard_runner::{
    BackendKind, NetworkMode, RunRequest, ToolSpec, plan, run as run_isolated,
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
    /// Stage and run an untrusted tool. Changes are discarded.
    Run(RunArgs),
    /// Create a persistent sanitized workspace without running a tool.
    Stage(StageArgs),
    /// Print the effective built-in plus user policy.
    Policy(PolicyArgs),
    /// Check host prerequisites without changing the system.
    Doctor(DoctorArgs),
    /// Remove old, unlocked staging directories owned by the current user.
    Gc(GcArgs),
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

    /// Forward an environment variable by name. Values are never written to the audit log.
    #[arg(long = "forward-env", value_name = "NAME")]
    forward_env: Vec<String>,

    /// Read-only installation root for a non-system tool.
    #[arg(long)]
    tool_root: Option<PathBuf>,

    /// Managed Lima instance used by the macOS backend.
    #[arg(long, default_value = "sandbox-guard")]
    lima_instance: String,

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
    Unrestricted,
}

impl From<NetworkArg> for NetworkMode {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Denied => Self::Denied,
            NetworkArg::Unrestricted => Self::Unrestricted,
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
    }
}

fn run_command(args: RunArgs) -> Result<i32> {
    let network: NetworkMode = args.network.into();
    if network == NetworkMode::Unrestricted && !args.allow_unrestricted_network {
        bail!(
            "--network unrestricted exposes services reachable from the backend network; repeat with --allow-unrestricted-network to acknowledge this residual risk"
        );
    }

    let policy_path = resolve_policy_path(args.policy)?;
    let policy = CompiledPolicy::load(policy_path.as_deref())?;
    let mut options = StageOptions::new(&args.source, policy);
    options.staging_base = args.staging_base;
    options.synthetic_git = !args.no_synthetic_git;
    let mut stage = Stage::build(options).context("staging failed closed")?;

    let (command, tool_args) = args
        .tool
        .split_first()
        .ok_or_else(|| anyhow!("tool command cannot be empty"))?;
    let forwarded_env = collect_forwarded_environment(&args.forward_env)?;
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
        forwarded_env,
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
                exit_code,
                success,
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
            println!("linux staging: openat2 required at runtime (Linux 5.6 or newer)");
        }
        BackendKind::MacosLima => {
            healthy &= report_executable("limactl", "macOS Linux-VM backend");
            println!(
                "lima instance: sandbox-guard must be created with --mount-none and contain bwrap plus the selected tool"
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
    exit_code: Option<i32>,
    success: bool,
) -> Result<()> {
    stage.manifest_mut().run = Some(RunRecord {
        backend: format!("{backend:?}"),
        network: network.as_str().to_owned(),
        tool: tool.to_string_lossy().into_owned(),
        forwarded_environment_names: environment_names.to_vec(),
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
