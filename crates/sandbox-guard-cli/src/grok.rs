use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Local, TimeDelta, Utc};
use clap::Args;
use directories::{BaseDirs, ProjectDirs};
use sandbox_guard_core::{CompiledPolicy, Stage, StageOptions, UserPolicy};
use sandbox_guard_runner::ProcessSpec;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{BackendArg, CgroupArg, NetworkArg, PersistentRunState, RunArgs, run_command_with};

const GROK_PROXY_HOST: &str = "cli-chat-proxy.grok.com";
const GROK_SESSION_TOKEN: &str = "GROK_SESSION_TOKEN";
const GROK_AUTH_PROVIDER_COMMAND: &str = "GROK_AUTH_PROVIDER_COMMAND";
const AUTH_PROVIDER_COMMAND: &str = "printf '%s\\n' \"$GROK_SESSION_TOKEN\"";
const SAFE_GROK_ARGUMENTS: &[&str] = &["--disable-web-search", "--no-memory", "--no-alt-screen"];
const MINIMUM_TOKEN_VALIDITY_MINUTES: i64 = 10;
const MAX_AUTH_FILE_BYTES: u64 = 1024 * 1024;
const GROK_SESSION_CWD: &str = "%2Fworkspace";
const GROK_SESSION_INDEX: &str = "session_search.sqlite";
const GROK_PROMPT_HISTORY: &str = "prompt_history.jsonl";
const SESSION_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const SESSION_MAX_FILES: u64 = 10_000;

#[derive(Debug, Args)]
pub(super) struct GrokArgs {
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

    /// Maximum size of one file written by Grok, in MiB.
    #[arg(long, default_value_t = 1024)]
    max_file_mib: u64,

    /// Maximum CPU time consumed by Grok.
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

    /// Discard isolated workspace changes without the default trusted review/apply prompt.
    #[arg(long)]
    no_change_review: bool,

    /// Keep the disposable staged workspace after Grok exits.
    #[arg(long)]
    keep_stage: bool,

    /// Host Grok executable used only for trusted OAuth login or refresh.
    #[arg(long)]
    host_grok: Option<PathBuf>,

    /// Refresh host OAuth even when the current access token is still valid.
    #[arg(long)]
    reauthenticate: bool,

    /// Use Grok's experimental native-scrollback renderer.
    #[arg(long)]
    scrollback: bool,

    /// Keep egress fixed to Grok's API host without native prompts for additional HTTPS hosts.
    #[arg(long)]
    no_egress_prompts: bool,

    /// Resume a Guard-managed Grok session by UUID.
    #[arg(
        long,
        short = 'r',
        value_name = "SESSION_ID",
        conflicts_with = "continue_session"
    )]
    resume: Option<Uuid>,

    /// Continue the most recently updated Guard-managed session for this source directory.
    #[arg(long = "continue", short = 'c', conflicts_with = "resume")]
    continue_session: bool,

    /// Additional Grok arguments. Place them after the double dash.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    grok_args: Vec<OsString>,
}

pub(super) fn run(args: GrokArgs) -> Result<i32> {
    let base_dirs = BaseDirs::new().context("could not determine the user home directory")?;
    let auth_path = base_dirs.home_dir().join(".grok/auth.json");
    let host_grok = resolve_host_grok(args.host_grok.as_deref(), base_dirs.home_dir())?;
    let now = Utc::now();
    let credential = ensure_grok_credential_with(&auth_path, now, args.reauthenticate, || {
        refresh_host_grok_auth(&host_grok, &auth_path, args.reauthenticate)
    })?;
    println!(
        "grok authentication: short-lived access valid until {}",
        credential
            .expires_at
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S %z")
    );

    reject_passthrough_session_controls(&args.grok_args)?;
    let session_state = GrokSessionState::prepare(&args.source, args.resume)?;
    let tool = grok_tool_arguments(
        args.scrollback,
        args.resume,
        args.continue_session,
        args.grok_args,
    );

    let run_args = RunArgs {
        source: args.source,
        policy: args.policy,
        staging_base: args.staging_base,
        backend: args.backend,
        network: NetworkArg::Controlled,
        allow_unrestricted_network: false,
        allow_hosts: vec![GROK_PROXY_HOST.to_owned()],
        ask_egress: !args.no_egress_prompts,
        forward_env: Vec::new(),
        tool_root: None,
        lima_instance: args.lima_instance,
        helper: args.helper,
        cgroup: args.cgroup,
        memory_mib: args.memory_mib,
        max_file_mib: args.max_file_mib,
        cpu_seconds: args.cpu_seconds,
        open_files: args.open_files,
        max_processes: args.max_processes,
        cpu_percent: args.cpu_percent,
        review_changes: args.export_changes.is_none() && !args.no_change_review,
        export_changes: args.export_changes,
        no_synthetic_git: false,
        dry_run: false,
        keep_stage: args.keep_stage,
        tool,
    };
    let environment = vec![
        (GROK_SESSION_TOKEN.to_owned(), credential.access_token),
        (
            GROK_AUTH_PROVIDER_COMMAND.to_owned(),
            AUTH_PROVIDER_COMMAND.to_owned(),
        ),
    ];
    let preflight = ProcessSpec {
        command: OsString::from("grok"),
        args: vec![OsString::from("login")],
    };
    run_command_with(
        run_args,
        environment,
        Some(preflight),
        Some(Box::new(session_state)),
    )
}

fn grok_tool_arguments(
    scrollback: bool,
    resume: Option<Uuid>,
    continue_session: bool,
    grok_args: Vec<OsString>,
) -> Vec<OsString> {
    let mut tool = vec![OsString::from("grok")];
    tool.extend(SAFE_GROK_ARGUMENTS.iter().map(OsString::from));
    if scrollback {
        tool.push(OsString::from("--minimal"));
    }
    if let Some(session_id) = resume {
        tool.push(OsString::from("--resume"));
        tool.push(OsString::from(session_id.to_string()));
    } else if continue_session {
        tool.push(OsString::from("--continue"));
    }
    tool.extend(grok_args);
    tool
}

fn reject_passthrough_session_controls(arguments: &[OsString]) -> Result<()> {
    for argument in arguments {
        let value = argument.to_string_lossy();
        if matches!(value.as_ref(), "--resume" | "-r" | "--continue" | "-c")
            || value.starts_with("--resume=")
        {
            bail!(
                "pass session controls directly to Guard (`guard grok --resume ID` or `guard grok --continue`) so the private session snapshot can be restored first"
            );
        }
    }
    Ok(())
}

struct GrokSessionState {
    store: GrokSessionStore,
    stage: Stage,
}

impl GrokSessionState {
    fn prepare(source: &Path, resume: Option<Uuid>) -> Result<Self> {
        let source = fs::canonicalize(source)
            .with_context(|| format!("resolve Grok session source {}", source.display()))?;
        let store = GrokSessionStore::open(&source)?;
        let empty;
        let input = if let Some(snapshot) = store.current_snapshot()? {
            snapshot
        } else {
            empty = tempfile::tempdir().context("create empty Grok session source")?;
            fs::set_permissions(empty.path(), fs::Permissions::from_mode(0o700))?;
            empty.path().to_path_buf()
        };
        let mut options = StageOptions::new(&input, session_policy()?);
        options.synthetic_git = false;
        let stage = Stage::build(options).context("validate stored Grok sessions")?;
        ensure_clean_session_stage(&stage)?;
        validate_session_layout(stage.workspace())?;
        if let Some(session_id) = resume {
            let session = stage
                .workspace()
                .join(GROK_SESSION_CWD)
                .join(session_id.to_string());
            let metadata = fs::symlink_metadata(&session).with_context(|| {
                format!(
                    "Grok session {session_id} is not stored for source {}",
                    source.display()
                )
            })?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("stored Grok session {session_id} is not a real directory");
            }
        }
        Ok(Self { store, stage })
    }
}

impl PersistentRunState for GrokSessionState {
    fn writable_path(&self) -> &Path {
        self.stage.workspace()
    }

    fn publish(self: Box<Self>) -> Result<()> {
        let mut options = StageOptions::new(self.stage.workspace(), session_policy()?);
        options.synthetic_git = false;
        options.staging_base = Some(self.store.snapshots.clone());
        let validated = Stage::build(options).context("validate returned Grok session state")?;
        ensure_clean_session_stage(&validated)?;
        let session_count = validate_session_layout(validated.workspace())?;
        let snapshot_id = Uuid::new_v4();
        let destination = self.store.snapshots.join(snapshot_id.to_string());
        validated
            .publish_workspace(&destination)
            .context("publish validated Grok session snapshot")?;
        self.store.activate(snapshot_id)?;
        self.store.cleanup_old_snapshots(snapshot_id);
        println!("grok sessions: {session_count} stored privately");
        Ok(())
    }
}

struct GrokSessionStore {
    root: PathBuf,
    snapshots: PathBuf,
    previous: Option<Uuid>,
}

impl GrokSessionStore {
    fn open(source: &Path) -> Result<Self> {
        let project = ProjectDirs::from("com", "xbtoshi", "sandbox-guard")
            .context("could not determine the application data directory")?;
        Self::open_at(&project.data_local_dir().join("grok-sessions"), source)
    }

    fn open_at(base: &Path, source: &Path) -> Result<Self> {
        let digest = Sha256::digest(source.as_os_str().as_bytes());
        ensure_private_directory(base)?;
        let root = base.join(hex::encode(digest));
        ensure_private_directory(&root)?;
        let snapshots = root.join("snapshots");
        ensure_private_directory(&snapshots)?;
        let mut store = Self {
            root,
            snapshots,
            previous: None,
        };
        store.previous = store.read_current()?;
        Ok(store)
    }

    fn current_snapshot(&self) -> Result<Option<PathBuf>> {
        let Some(snapshot_id) = self.previous else {
            return Ok(None);
        };
        let snapshot = self.snapshots.join(snapshot_id.to_string());
        validate_private_directory(&snapshot)?;
        Ok(Some(snapshot))
    }

    fn read_current(&self) -> Result<Option<Uuid>> {
        let path = self.root.join("CURRENT");
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("open current Grok session snapshot"),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != current_uid()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > 64
        {
            bail!("Grok session CURRENT pointer is not a private regular file");
        }
        let mut value = String::new();
        file.read_to_string(&mut value)?;
        Ok(Some(
            Uuid::parse_str(value.trim()).context("parse Grok session CURRENT pointer")?,
        ))
    }

    fn activate(&self, snapshot_id: Uuid) -> Result<()> {
        let temporary = self.root.join(format!(".CURRENT-{snapshot_id}"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .context("create temporary Grok session pointer")?;
        use std::io::Write;
        if let Err(error) = writeln!(file, "{snapshot_id}").and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("write Grok session pointer");
        }
        if let Err(error) = fs::rename(&temporary, self.root.join("CURRENT")) {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("activate Grok session snapshot");
        }
        OpenOptions::new()
            .read(true)
            .open(&self.root)?
            .sync_all()
            .context("sync Grok session store")
    }

    fn cleanup_old_snapshots(&self, active: Uuid) {
        let Ok(entries) = fs::read_dir(&self.snapshots) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(snapshot_id) = Uuid::parse_str(&name) else {
                continue;
            };
            if snapshot_id == active || Some(snapshot_id) == self.previous {
                continue;
            }
            let path = entry.path();
            if fs::symlink_metadata(&path)
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                && let Err(error) = fs::remove_dir_all(&path)
            {
                eprintln!(
                    "warning: could not remove old Grok session snapshot {}: {error}",
                    path.display()
                );
            }
        }
    }
}

fn session_policy() -> Result<CompiledPolicy> {
    CompiledPolicy::with_user_policy(UserPolicy {
        max_total_bytes: Some(SESSION_MAX_TOTAL_BYTES),
        max_files: Some(SESSION_MAX_FILES),
        ..UserPolicy::default()
    })
    .context("compile private Grok session policy")
}

fn ensure_clean_session_stage(stage: &Stage) -> Result<()> {
    if let Some(excluded) = stage.manifest().excluded.first() {
        bail!(
            "Grok session state contains an unsafe path {} ({:?})",
            excluded.path,
            excluded.reason
        );
    }
    Ok(())
}

fn validate_session_layout(root: &Path) -> Result<usize> {
    let mut cwd = None;
    for entry in fs::read_dir(root).context("inspect Grok session state root")? {
        let entry = entry?;
        let name = entry.file_name();
        let metadata = fs::symlink_metadata(entry.path())?;
        if name == GROK_SESSION_CWD {
            if cwd.is_some() || !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("encoded Grok session workspace is not one real directory");
            }
            cwd = Some(entry.path());
        } else if name == GROK_SESSION_INDEX {
            require_private_session_file(&entry.path(), &metadata, GROK_SESSION_INDEX)?;
        } else {
            bail!("unexpected entry in Grok session state: {name:?}");
        }
    }
    let Some(cwd) = cwd else {
        return Ok(0);
    };
    let mut count = 0;
    for entry in fs::read_dir(cwd)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("Grok session ID is not valid UTF-8"))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if name == GROK_PROMPT_HISTORY {
            require_private_session_file(&entry.path(), &metadata, GROK_PROMPT_HISTORY)?;
            continue;
        }
        Uuid::parse_str(&name)
            .with_context(|| format!("invalid Grok session directory {name:?}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("Grok session {name} is not a real directory");
        }
        count += 1;
    }
    Ok(count)
}

fn require_private_session_file(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        bail!(
            "Grok session metadata {label} is not a singly linked regular file: {}",
            path.display()
        );
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("create private directory {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure private directory {}", path.display()))?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private directory {}", path.display()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("private directory is unsafe: {}", path.display());
    }
    Ok(())
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the current process's effective uid.
    unsafe { libc::geteuid() }
}

struct GrokCredential {
    access_token: String,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct GrokAuthEntry {
    #[serde(default)]
    auth_mode: String,
    key: Option<String>,
    expires_at: Option<String>,
}

fn ensure_grok_credential_with<F>(
    auth_path: &Path,
    now: DateTime<Utc>,
    force_refresh: bool,
    refresh: F,
) -> Result<GrokCredential>
where
    F: FnOnce() -> Result<()>,
{
    let current = load_optional_grok_credential(auth_path)?;
    let minimum_expiry = now + TimeDelta::minutes(MINIMUM_TOKEN_VALIDITY_MINUTES);
    if !force_refresh
        && let Some(credential) = current
        && credential.expires_at > minimum_expiry
    {
        return Ok(credential);
    }

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        eprintln!(
            "grok authentication: refreshing through the confined host CLI; browser interaction may be required"
        );
    } else {
        println!(
            "grok authentication: refreshing through the host CLI in a strict, empty-workspace sandbox"
        );
    }
    refresh()?;
    let refreshed = load_grok_credential(auth_path)
        .context("host Grok login completed but no usable OAuth credential was written")?;
    if refreshed.expires_at <= minimum_expiry {
        bail!(
            "host Grok login returned an access token that expires too soon ({})",
            refreshed.expires_at.to_rfc3339()
        );
    }
    Ok(refreshed)
}

fn load_optional_grok_credential(path: &Path) -> Result<Option<GrokCredential>> {
    match fs::symlink_metadata(path) {
        Ok(_) => load_grok_credential(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("inspect Grok auth file {}", path.display()))
        }
    }
}

fn load_grok_credential(path: &Path) -> Result<GrokCredential> {
    let bytes = read_private_auth_file(path)?;
    let entries: BTreeMap<String, GrokAuthEntry> = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse Grok auth file {}", path.display()))?;
    entries
        .into_values()
        .filter(|entry| entry.auth_mode.eq_ignore_ascii_case("oidc"))
        .filter_map(|entry| {
            let access_token = entry.key.filter(|value| !value.is_empty())?;
            let expires_at = DateTime::parse_from_rfc3339(entry.expires_at.as_deref()?)
                .ok()?
                .with_timezone(&Utc);
            Some(GrokCredential {
                access_token,
                expires_at,
            })
        })
        .max_by_key(|credential| credential.expires_at)
        .ok_or_else(|| anyhow!("{} contains no usable OIDC access token", path.display()))
}

fn read_private_auth_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open Grok auth file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect Grok auth file {}", path.display()))?;
    // SAFETY: geteuid has no pointer arguments and cannot invalidate Rust state.
    let current_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != current_uid
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_AUTH_FILE_BYTES
    {
        bail!(
            "refusing unsafe Grok auth file {}: require an owner-only, singly linked regular file no larger than {} bytes",
            path.display(),
            MAX_AUTH_FILE_BYTES
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read Grok auth file {}", path.display()))?;
    Ok(bytes)
}

fn resolve_host_grok(explicit: Option<&Path>, home: &Path) -> Result<PathBuf> {
    let candidate = if let Some(path) = explicit {
        path.to_path_buf()
    } else {
        let standard = home.join(".grok/bin/grok");
        if standard.is_file() {
            standard
        } else {
            which::which("grok").context(
                "host Grok is required for OAuth; install it or pass --host-grok explicitly",
            )?
        }
    };
    let resolved = fs::canonicalize(&candidate)
        .with_context(|| format!("resolve host Grok executable {}", candidate.display()))?;
    let metadata = fs::metadata(&resolved)
        .with_context(|| format!("inspect host Grok executable {}", resolved.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!(
            "host Grok executable is not an executable regular file: {}",
            resolved.display()
        );
    }
    Ok(resolved)
}

fn refresh_host_grok_auth(host_grok: &Path, auth_path: &Path, force_login: bool) -> Result<()> {
    if !force_login && auth_path.is_file() {
        let status = run_host_grok_auth_command(host_grok, ["models"])?;
        if status.success()
            && load_optional_grok_credential(auth_path)?.is_some_and(|credential| {
                credential.expires_at
                    > Utc::now() + TimeDelta::minutes(MINIMUM_TOKEN_VALIDITY_MINUTES)
            })
        {
            return Ok(());
        }
        eprintln!("grok authentication: silent refresh was unavailable; browser login is required");
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!(
            "Grok OAuth login requires an interactive terminal; run `guard grok` once interactively"
        );
    }
    let status = run_host_grok_auth_command(host_grok, ["login", "--oauth"])?;
    if !status.success() {
        bail!("strict host Grok login exited with {status}");
    }
    Ok(())
}

fn run_host_grok_auth_command<const N: usize>(
    host_grok: &Path,
    arguments: [&str; N],
) -> Result<std::process::ExitStatus> {
    let empty_workspace = tempfile::Builder::new()
        .prefix("sandbox-guard-grok-login-")
        .tempdir()
        .context("create private empty workspace for host Grok login")?;
    fs::set_permissions(empty_workspace.path(), fs::Permissions::from_mode(0o700))
        .context("secure private empty workspace for host Grok login")?;
    let status = Command::new(host_grok)
        .args(["--sandbox", "strict"])
        .args(arguments)
        .current_dir(empty_workspace.path())
        .env_remove("XAI_API_KEY")
        .env_remove(GROK_SESSION_TOKEN)
        .env_remove(GROK_AUTH_PROVIDER_COMMAND)
        .env_remove("GROK_SANDBOX")
        .status()
        .with_context(|| {
            format!(
                "execute confined host Grok auth command {}",
                host_grok.display()
            )
        })?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn write_auth(path: &Path, token: &str, expires_at: DateTime<Utc>) {
        let document = serde_json::json!({
            "https://auth.x.ai::test": {
                "auth_mode": "oidc",
                "key": token,
                "expires_at": expires_at.to_rfc3339(),
            }
        });
        fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn fresh_private_oauth_token_does_not_trigger_login() {
        let directory = tempfile::tempdir().unwrap();
        let auth = directory.path().join("auth.json");
        let now = DateTime::parse_from_rfc3339("2026-07-15T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        write_auth(&auth, "test-access-token", now + TimeDelta::hours(6));
        let called = Cell::new(false);
        let credential = ensure_grok_credential_with(&auth, now, false, || {
            called.set(true);
            Ok(())
        })
        .unwrap();
        assert!(!called.get());
        assert_eq!(credential.access_token, "test-access-token");
    }

    #[test]
    fn expired_oauth_token_is_reloaded_after_trusted_login() {
        let directory = tempfile::tempdir().unwrap();
        let auth = directory.path().join("auth.json");
        let now = DateTime::parse_from_rfc3339("2026-07-15T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        write_auth(&auth, "expired", now - TimeDelta::minutes(1));
        let credential = ensure_grok_credential_with(&auth, now, false, || {
            write_auth(&auth, "refreshed", now + TimeDelta::hours(6));
            Ok(())
        })
        .unwrap();
        assert_eq!(credential.access_token, "refreshed");
    }

    #[test]
    fn group_readable_auth_file_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let auth = directory.path().join("auth.json");
        write_auth(&auth, "secret", Utc::now() + TimeDelta::hours(6));
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_grok_credential(&auth).is_err());
    }

    #[test]
    fn symlinked_auth_file_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("real-auth.json");
        let link = directory.path().join("auth.json");
        write_auth(&target, "secret", Utc::now() + TimeDelta::hours(6));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(load_grok_credential(&link).is_err());
    }

    #[test]
    fn auth_provider_command_references_only_the_private_environment_name() {
        assert_eq!(
            AUTH_PROVIDER_COMMAND,
            "printf '%s\\n' \"$GROK_SESSION_TOKEN\""
        );
        assert!(!AUTH_PROVIDER_COMMAND.contains("test-access-token"));
    }

    #[test]
    fn normal_ui_is_default_and_native_scrollback_is_opt_in() {
        let normal = grok_tool_arguments(false, None, false, Vec::new());
        let scrollback = grok_tool_arguments(true, None, false, Vec::new());

        assert!(!normal.contains(&OsString::from("--minimal")));
        assert!(scrollback.contains(&OsString::from("--minimal")));
        assert!(SAFE_GROK_ARGUMENTS.contains(&"--no-alt-screen"));
    }

    #[test]
    fn grok_session_arguments_are_guard_owned() {
        let session = Uuid::new_v4();
        let resumed = grok_tool_arguments(false, Some(session), false, Vec::new());
        assert!(resumed.windows(2).any(|values| {
            values
                == [
                    OsString::from("--resume"),
                    OsString::from(session.to_string()),
                ]
        }));
        assert!(reject_passthrough_session_controls(&[OsString::from("--resume")]).is_err());
        assert!(reject_passthrough_session_controls(&[OsString::from("--continue")]).is_err());
    }

    #[test]
    fn compiled_profile_matches_the_current_grok_boundary() {
        let profile = sandbox_guard_core::builtin_grok_profile();
        profile.validate().unwrap();

        assert_eq!(profile.name, "grok");
        assert_eq!(profile.tool.command, "grok");
        assert_eq!(
            profile.tool.guest_executable,
            Path::new("/opt/sandbox-guard/tools/grok")
        );
        assert_eq!(
            profile.tool.forced_arguments,
            SAFE_GROK_ARGUMENTS
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(profile.tool.scrollback_arguments, ["--minimal"]);
        let preflight = profile.tool.preflight.as_ref().unwrap();
        assert_eq!(preflight.command, "grok");
        assert_eq!(preflight.arguments, ["login"]);
        assert_eq!(
            profile.tool.forbidden_passthrough,
            [
                sandbox_guard_core::ArgumentRule {
                    kind: sandbox_guard_core::ArgumentMatch::Exact,
                    value: "--resume".to_owned(),
                },
                sandbox_guard_core::ArgumentRule {
                    kind: sandbox_guard_core::ArgumentMatch::Exact,
                    value: "-r".to_owned(),
                },
                sandbox_guard_core::ArgumentRule {
                    kind: sandbox_guard_core::ArgumentMatch::Exact,
                    value: "--continue".to_owned(),
                },
                sandbox_guard_core::ArgumentRule {
                    kind: sandbox_guard_core::ArgumentMatch::Exact,
                    value: "-c".to_owned(),
                },
                sandbox_guard_core::ArgumentRule {
                    kind: sandbox_guard_core::ArgumentMatch::Prefix,
                    value: "--resume=".to_owned(),
                },
            ]
        );
        assert_eq!(
            profile.egress.allowed_https_hosts[0].hostname,
            GROK_PROXY_HOST
        );
        assert!(!profile.egress.allowed_https_hosts[0].include_subdomains);
        assert!(profile.egress.interactive_approval_default);
        assert_eq!(
            profile.credentials.host_auth_file,
            Path::new(".grok/auth.json")
        );
        assert_eq!(profile.credentials.value_environment, GROK_SESSION_TOKEN);
        assert_eq!(
            profile.credentials.provider_command_environment,
            GROK_AUTH_PROVIDER_COMMAND
        );
        assert_eq!(profile.credentials.provider_command, AUTH_PROVIDER_COMMAND);
        assert_eq!(
            profile.credentials.minimum_validity_minutes,
            MINIMUM_TOKEN_VALIDITY_MINUTES as u64
        );
        assert_eq!(profile.credentials.max_auth_file_bytes, MAX_AUTH_FILE_BYTES);
        assert_eq!(
            profile.credentials.scrubbed_host_environment,
            [
                "XAI_API_KEY",
                GROK_SESSION_TOKEN,
                GROK_AUTH_PROVIDER_COMMAND,
                "GROK_SANDBOX"
            ]
        );
        let sessions = profile.sessions.unwrap();
        assert_eq!(
            sessions.guest_mount_path,
            Path::new(sandbox_guard_runner::WRITABLE_HOME_STATE_GUEST_PATH)
        );
        assert_eq!(sessions.workspace_key, GROK_SESSION_CWD);
        assert_eq!(sessions.index_file, GROK_SESSION_INDEX);
        assert_eq!(sessions.prompt_history_file, GROK_PROMPT_HISTORY);
        assert_eq!(sessions.max_total_bytes, SESSION_MAX_TOTAL_BYTES);
        assert_eq!(sessions.max_files, SESSION_MAX_FILES);
        assert!(profile.terminal.mouse_reporting_default);
        assert!(profile.terminal.native_scrollback_opt_in);
        assert!(profile.clipboard.image_import);
        assert!(profile.seccomp.clone3_enosys_shim_expected);
    }

    #[test]
    fn private_session_snapshot_round_trips_through_validation() {
        let data = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let store = GrokSessionStore::open_at(data.path(), &source).unwrap();
        let empty = tempfile::tempdir().unwrap();
        let mut options = StageOptions::new(empty.path(), session_policy().unwrap());
        options.synthetic_git = false;
        let stage = Stage::build(options).unwrap();
        let session_id = Uuid::new_v4();
        let session = stage
            .workspace()
            .join(GROK_SESSION_CWD)
            .join(session_id.to_string());
        fs::create_dir_all(&session).unwrap();
        fs::write(session.join("summary.json"), b"{}\n").unwrap();
        fs::write(stage.workspace().join(GROK_SESSION_INDEX), b"test-index\n").unwrap();
        fs::write(
            stage
                .workspace()
                .join(GROK_SESSION_CWD)
                .join(GROK_PROMPT_HISTORY),
            b"test prompt\n",
        )
        .unwrap();

        Box::new(GrokSessionState { store, stage })
            .publish()
            .unwrap();

        let reopened = GrokSessionStore::open_at(data.path(), &source).unwrap();
        let snapshot = reopened.current_snapshot().unwrap().unwrap();
        assert_eq!(
            fs::read(
                snapshot
                    .join(GROK_SESSION_CWD)
                    .join(session_id.to_string())
                    .join("summary.json")
            )
            .unwrap(),
            b"{}\n"
        );
        assert_eq!(validate_session_layout(&snapshot).unwrap(), 1);
    }

    #[test]
    fn hostile_returned_session_link_is_never_published() {
        let data = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let store = GrokSessionStore::open_at(data.path(), &source).unwrap();
        let empty = tempfile::tempdir().unwrap();
        let mut options = StageOptions::new(empty.path(), session_policy().unwrap());
        options.synthetic_git = false;
        let stage = Stage::build(options).unwrap();
        let session = stage
            .workspace()
            .join(GROK_SESSION_CWD)
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&session).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", session.join("summary.json")).unwrap();

        assert!(
            Box::new(GrokSessionState { store, stage })
                .publish()
                .is_err()
        );
    }

    #[test]
    fn session_layout_rejects_non_uuid_and_extra_roots() {
        let state = tempfile::tempdir().unwrap();
        fs::create_dir(state.path().join("unexpected")).unwrap();
        assert!(validate_session_layout(state.path()).is_err());

        fs::remove_dir(state.path().join("unexpected")).unwrap();
        fs::create_dir(state.path().join(GROK_SESSION_CWD)).unwrap();
        fs::create_dir(state.path().join(GROK_SESSION_CWD).join("latest")).unwrap();
        assert!(validate_session_layout(state.path()).is_err());
    }
}
