use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Local, TimeDelta, Utc};
use clap::Args;
use directories::BaseDirs;
use sandbox_guard_runner::ProcessSpec;
use serde::Deserialize;

use super::{BackendArg, CgroupArg, NetworkArg, RunArgs, run_command_with};

const GROK_PROXY_HOST: &str = "cli-chat-proxy.grok.com";
const GROK_SESSION_TOKEN: &str = "GROK_SESSION_TOKEN";
const GROK_AUTH_PROVIDER_COMMAND: &str = "GROK_AUTH_PROVIDER_COMMAND";
const AUTH_PROVIDER_COMMAND: &str = "printf '%s\\n' \"$GROK_SESSION_TOKEN\"";
const SAFE_GROK_ARGUMENTS: &[&str] = &[
    "--disable-web-search",
    "--no-memory",
    "--minimal",
    "--no-alt-screen",
];
const MINIMUM_TOKEN_VALIDITY_MINUTES: i64 = 10;
const MAX_AUTH_FILE_BYTES: u64 = 1024 * 1024;

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

    /// Keep the disposable staged workspace after Grok exits.
    #[arg(long)]
    keep_stage: bool,

    /// Host Grok executable used only for trusted OAuth login or refresh.
    #[arg(long)]
    host_grok: Option<PathBuf>,

    /// Refresh host OAuth even when the current access token is still valid.
    #[arg(long)]
    reauthenticate: bool,

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

    let mut tool = vec![OsString::from("grok")];
    tool.extend(SAFE_GROK_ARGUMENTS.iter().map(OsString::from));
    tool.extend(args.grok_args);

    let run_args = RunArgs {
        source: args.source,
        policy: args.policy,
        staging_base: args.staging_base,
        backend: args.backend,
        network: NetworkArg::Controlled,
        allow_unrestricted_network: false,
        allow_hosts: vec![GROK_PROXY_HOST.to_owned()],
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
    run_command_with(run_args, environment, Some(preflight))
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
    fn safe_defaults_use_native_scrollback_for_selection() {
        assert!(SAFE_GROK_ARGUMENTS.contains(&"--minimal"));
        assert!(SAFE_GROK_ARGUMENTS.contains(&"--no-alt-screen"));
    }
}
