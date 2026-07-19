use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_guard_helper::EnvironmentEntry;
use tempfile::{Builder as TempBuilder, TempDir};

use crate::approval::ApprovalController;
use crate::clipboard::{INBOX_DIRECTORY, SANDBOX_INBOX, read_clipboard_image, write_private_image};
use crate::terminal::{ClipboardPaste, run_interactive};
use crate::{
    BackendKind, CgroupMode, CommandPlan, NetworkMode, ResourceLimits, RunOutcome, RunRequest,
    RunnerError, path_is_within,
};

pub(crate) const GUEST_RUNTIME: &str = "/run/sandbox-guard";
const GUEST_ENVIRONMENT: &str = "/run/sandbox-guard/environment.json";
const GUEST_PROXY_SOCKET: &str = "/run/sandbox-guard/egress.sock";
const GUEST_HELPER: &str = "/opt/sandbox-guard/helper";

/// Fixed absolute `env` used to install the clean-environment boundary before bwrap. Hard-coding
/// the path (rather than a PATH lookup) guarantees no PATH-selected `env` runs before the
/// environment is cleared. See the launcher-scrub guarantee in `docs/SECURITY_MODEL.md`.
const HOST_CLEAN_ENV: &str = "/usr/bin/env";
/// Same fixed `env` inside the managed Lima guest.
const GUEST_CLEAN_ENV: &str = "/usr/bin/env";
/// Canonical apt-installed `bwrap` location inside the managed Lima guest. The setup diagnostic
/// requires this exact executable, so the guest boundary invokes it absolutely (no PATH lookup).
const GUEST_BWRAP: &str = "/usr/bin/bwrap";

pub struct LinuxBwrapRunner;

/// Exercise the namespace/root-filesystem portion of the production Bubblewrap boundary.
///
/// Presence and `--version` checks do not establish that unprivileged user namespaces actually
/// work under the host's kernel and distribution policy. This probe deliberately uses the same
/// fixed clean-environment launcher and the production namespace/capability/root construction,
/// then executes only `/usr/bin/true` inside the disposable sandbox.
pub fn linux_namespace_probe_available(bwrap: &Path) -> Result<bool, RunnerError> {
    let args = linux_namespace_probe_args();
    Command::new(HOST_CLEAN_ENV)
        .arg("-i")
        .arg(bwrap)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|source| RunnerError::Execute {
            program: PathBuf::from(HOST_CLEAN_ENV),
            source,
        })
}

fn linux_namespace_probe_args() -> Vec<OsString> {
    let mut args = Vec::new();
    for value in [
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--unshare-net",
    ] {
        push(&mut args, value);
    }
    push(&mut args, "--hostname");
    push(&mut args, "sandbox-guard-probe");
    push(&mut args, "--cap-drop");
    push(&mut args, "ALL");
    push(&mut args, "--clearenv");
    push(&mut args, "--tmpfs");
    push(&mut args, "/");
    push(&mut args, "--proc");
    push(&mut args, "/proc");
    push(&mut args, "--dev");
    push(&mut args, "/dev");
    push(&mut args, "--tmpfs");
    push(&mut args, "/tmp");
    for directory in ["/home", "/home/guard", "/opt", "/run"] {
        push(&mut args, "--dir");
        push(&mut args, directory);
    }
    bind_if_present(&mut args, "/usr", "/usr");
    bind_if_present(&mut args, "/bin", "/bin");
    bind_if_present(&mut args, "/lib", "/lib");
    bind_if_present(&mut args, "/lib64", "/lib64");
    bind_if_present(&mut args, "/etc/ssl", "/etc/ssl");
    for (name, value) in [
        ("HOME", "/home/guard"),
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "C.UTF-8"),
    ] {
        push(&mut args, "--setenv");
        push(&mut args, name);
        push(&mut args, value);
    }
    push(&mut args, "/usr/bin/true");
    args
}

impl LinuxBwrapRunner {
    pub fn plan(request: &RunRequest) -> Result<CommandPlan, RunnerError> {
        let bwrap = which::which("bwrap").map_err(|source| RunnerError::DependencyMissing {
            name: "bwrap",
            source,
        })?;
        let helper = resolve_host_helper(request)?;
        let workspace = canonical_workspace(request)?;
        let runtime = planned_runtime_path(request, &workspace);
        let use_cgroup =
            request.cgroup_mode != CgroupMode::Disabled && which::which("systemd-run").is_ok();
        Self::build_plan(request, bwrap, helper, &runtime, use_cgroup)
    }

    fn build_plan(
        request: &RunRequest,
        bwrap: PathBuf,
        helper: PathBuf,
        runtime: &Path,
        use_cgroup: bool,
    ) -> Result<CommandPlan, RunnerError> {
        let workspace = canonical_workspace(request)?;
        let (tool_command, tool_mount) = resolve_host_tool(request)?;
        let bwrap_args = build_bwrap_args(
            request,
            &workspace,
            runtime,
            &helper,
            Path::new(GUEST_HELPER),
            tool_command,
            tool_mount,
        );
        let (program, args) = if use_cgroup {
            wrap_in_systemd_scope(request, bwrap, bwrap_args)
        } else {
            launch_bwrap_with_clean_env(bwrap, bwrap_args)
        };
        Ok(CommandPlan {
            program,
            args,
            redacted_args: BTreeSet::new(),
            warnings: network_warnings(request.network, "host"),
        })
    }

    pub fn run(request: &RunRequest) -> Result<RunOutcome, RunnerError> {
        let bwrap = which::which("bwrap").map_err(|source| RunnerError::DependencyMissing {
            name: "bwrap",
            source,
        })?;
        let helper = resolve_host_helper(request)?;
        let workspace = canonical_workspace(request)?;
        prepare_workspace_inbox(&workspace)?;
        let runtime = RuntimeDirectory::new(&workspace, &request.forwarded_env)?;
        let mut proxy = if request.network == NetworkMode::Controlled {
            Some(ProxyProcess::start(
                &helper,
                &runtime,
                &request.allowed_egress_hosts,
                request.interactive_egress_approval,
                request.egress_decision_store.as_deref(),
            )?)
        } else {
            None
        };
        let (use_cgroup, mut warnings) = resolve_cgroup_mode(request, &helper)?;
        let plan = Self::build_plan(request, bwrap, helper, runtime.root(), use_cgroup)?;
        warnings.extend(plan.warnings.clone());
        let (status, clipboard_imports) = if request.interactive {
            let interactive =
                run_interactive(&plan.program, &plan.args, request.interactive_ux, || {
                    let image = read_clipboard_image()?;
                    write_private_image(&runtime.inbox, &image)?;
                    Ok(ClipboardPaste {
                        text: image.attachment_reference(),
                        audit: image.audit_entry(),
                    })
                })?;
            (interactive.status, interactive.clipboard_imports)
        } else {
            let status = Command::new(&plan.program)
                .args(&plan.args)
                .status()
                .map_err(|source| RunnerError::Execute {
                    program: plan.program.clone(),
                    source,
                })?;
            (status, Vec::new())
        };
        let egress_approvals = proxy.as_mut().map(ProxyProcess::stop).unwrap_or_default();
        let egress_audit = fs::read_to_string(&runtime.audit_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        cleanup_workspace_inbox(&workspace)?;
        Ok(RunOutcome {
            backend: BackendKind::LinuxBwrap,
            status,
            warnings,
            cgroup_enforced: use_cgroup,
            seccomp_enforced: true,
            egress_audit,
            egress_approvals,
            clipboard_imports,
        })
    }
}

fn canonical_workspace(request: &RunRequest) -> Result<PathBuf, RunnerError> {
    fs::canonicalize(&request.workspace).map_err(|source| RunnerError::Inspect {
        path: request.workspace.clone(),
        source,
    })
}

struct RuntimeDirectory {
    temp: TempDir,
    socket: PathBuf,
    audit_log: PathBuf,
    inbox: PathBuf,
}

impl RuntimeDirectory {
    fn new(workspace: &Path, environment: &[(String, String)]) -> Result<Self, RunnerError> {
        let parent = workspace
            .parent()
            .ok_or_else(|| RunnerError::SetupFailed("workspace has no parent".to_owned()))?;
        let temp = TempBuilder::new()
            .prefix(".sandbox-guard-runtime-")
            .tempdir_in(parent)
            .map_err(|source| RunnerError::Inspect {
                path: parent.to_path_buf(),
                source,
            })?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).map_err(|source| {
            RunnerError::Inspect {
                path: temp.path().to_path_buf(),
                source,
            }
        })?;
        write_environment_file(&temp.path().join("environment.json"), environment)?;
        let inbox = temp.path().join("inbox");
        fs::create_dir(&inbox).map_err(|source| RunnerError::Inspect {
            path: inbox.clone(),
            source,
        })?;
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700)).map_err(|source| {
            RunnerError::Inspect {
                path: inbox.clone(),
                source,
            }
        })?;
        Ok(Self {
            socket: temp.path().join("egress.sock"),
            audit_log: temp.path().join("egress-audit.log"),
            inbox,
            temp,
        })
    }

    fn root(&self) -> &Path {
        self.temp.path()
    }
}

pub(crate) fn prepare_workspace_inbox(workspace: &Path) -> Result<(), RunnerError> {
    let inbox = workspace.join(INBOX_DIRECTORY);
    match fs::symlink_metadata(&inbox) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(RunnerError::SetupFailed(format!(
                "reserved clipboard inbox already exists: {}",
                inbox.display()
            )));
        }
        Err(source) => {
            return Err(RunnerError::Inspect {
                path: inbox,
                source,
            });
        }
    }
    fs::create_dir(&inbox).map_err(|source| RunnerError::Inspect {
        path: inbox.clone(),
        source,
    })?;
    fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700)).map_err(|source| {
        RunnerError::Inspect {
            path: inbox,
            source,
        }
    })
}

pub(crate) fn cleanup_workspace_inbox(workspace: &Path) -> Result<(), RunnerError> {
    let inbox = workspace.join(INBOX_DIRECTORY);
    fs::remove_dir(&inbox).map_err(|source| RunnerError::Inspect {
        path: inbox,
        source,
    })
}

pub(crate) fn write_environment_file(
    path: &Path,
    environment: &[(String, String)],
) -> Result<(), RunnerError> {
    let entries: Vec<_> = environment
        .iter()
        .map(|(name, value)| EnvironmentEntry {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| RunnerError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
    serde_json::to_writer(&mut file, &entries).map_err(|source| {
        RunnerError::SetupFailed(format!("serialize private environment: {source}"))
    })?;
    file.sync_all().map_err(|source| RunnerError::Inspect {
        path: path.to_path_buf(),
        source,
    })
}

struct ProxyProcess {
    child: Child,
    approval: Option<ApprovalController>,
    stopped: bool,
}

impl ProxyProcess {
    fn start(
        helper: &Path,
        runtime: &RuntimeDirectory,
        allowed_hosts: &[String],
        interactive_approval: bool,
        decision_store: Option<&Path>,
    ) -> Result<Self, RunnerError> {
        let mut command = Command::new(helper);
        command
            .arg("proxy")
            .arg("--socket")
            .arg(&runtime.socket)
            .arg("--audit-log")
            .arg(&runtime.audit_log);
        if interactive_approval {
            command
                .arg("--approval-stdio")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped());
        } else {
            command.stdin(Stdio::null()).stdout(Stdio::null());
        }
        for host in allowed_hosts {
            command.arg("--allow-host").arg(host);
        }
        let mut child = command.spawn().map_err(|source| RunnerError::Execute {
            program: helper.to_path_buf(),
            source,
        })?;
        let approval = if interactive_approval {
            let requests = child.stdout.take().ok_or_else(|| {
                RunnerError::SetupFailed("egress approval request pipe was not created".to_owned())
            })?;
            let responses = child.stdin.take().ok_or_else(|| {
                RunnerError::SetupFailed("egress approval response pipe was not created".to_owned())
            })?;
            let decision_store = decision_store.ok_or_else(|| {
                RunnerError::SetupFailed("egress decision store was not configured".to_owned())
            })?;
            match ApprovalController::start(requests, responses, decision_store.to_path_buf()) {
                Ok(controller) => Some(controller),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            }
        } else {
            None
        };
        let mut proxy = Self {
            child,
            approval,
            stopped: false,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = proxy
                .child
                .try_wait()
                .map_err(|source| RunnerError::Execute {
                    program: helper.to_path_buf(),
                    source,
                })?
            {
                return Err(RunnerError::HelperFailed(format!(
                    "egress proxy exited with {status}"
                )));
            }
            let socket_ready = fs::symlink_metadata(&runtime.socket)
                .map(|metadata| {
                    metadata.file_type().is_socket() && metadata.permissions().mode() & 0o077 == 0
                })
                .unwrap_or(false);
            let audit_ready = fs::symlink_metadata(&runtime.audit_log)
                .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o077 == 0)
                .unwrap_or(false);
            if socket_ready && audit_ready {
                break;
            }
            if Instant::now() >= deadline {
                return Err(RunnerError::HelperFailed(
                    "egress proxy did not become ready".to_owned(),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(proxy)
    }

    fn stop(&mut self) -> Vec<String> {
        if self.stopped {
            return Vec::new();
        }
        self.stopped = true;
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.approval
            .take()
            .map(ApprovalController::finish)
            .unwrap_or_default()
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn build_bwrap_args(
    request: &RunRequest,
    workspace: &Path,
    runtime_host: &Path,
    helper_host: &Path,
    helper_guest: &Path,
    tool_command: OsString,
    tool_mount: Option<(PathBuf, PathBuf)>,
) -> Vec<OsString> {
    let mut args = Vec::<OsString>::new();
    push(&mut args, "--die-with-parent");
    push(&mut args, "--new-session");
    push(&mut args, "--unshare-user");
    push(&mut args, "--unshare-pid");
    push(&mut args, "--unshare-ipc");
    push(&mut args, "--unshare-uts");
    push(&mut args, "--unshare-cgroup");
    if request.network != NetworkMode::Unrestricted {
        push(&mut args, "--unshare-net");
    }
    push(&mut args, "--hostname");
    push(&mut args, "sandbox-guard");
    push(&mut args, "--cap-drop");
    push(&mut args, "ALL");
    push(&mut args, "--clearenv");
    push(&mut args, "--tmpfs");
    push(&mut args, "/");
    push(&mut args, "--proc");
    push(&mut args, "/proc");
    push(&mut args, "--dev");
    push(&mut args, "/dev");
    push(&mut args, "--tmpfs");
    push(&mut args, "/tmp");
    push(&mut args, "--tmpfs");
    push(&mut args, "/dev/shm");
    for directory in [
        "/home",
        "/home/guard",
        "/home/guard/.grok",
        "/opt",
        "/opt/sandbox-guard",
        "/run",
    ] {
        push(&mut args, "--dir");
        push(&mut args, directory);
    }
    bind_if_present(&mut args, "/usr", "/usr");
    bind_if_present(&mut args, "/bin", "/bin");
    bind_if_present(&mut args, "/lib", "/lib");
    bind_if_present(&mut args, "/lib64", "/lib64");
    bind_if_present(&mut args, "/etc/ssl", "/etc/ssl");
    bind_if_present(&mut args, "/etc/pki", "/etc/pki");
    bind_if_present(&mut args, "/etc/ca-certificates", "/etc/ca-certificates");
    for path in [
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "/etc/localtime",
    ] {
        bind_file_if_present(&mut args, path, path);
    }
    if request.network == NetworkMode::Unrestricted {
        bind_file_if_present(&mut args, "/etc/resolv.conf", "/etc/resolv.conf");
        bind_file_if_present(&mut args, "/etc/hosts", "/etc/hosts");
    }
    push(&mut args, "--ro-bind");
    args.push(helper_host.as_os_str().to_owned());
    args.push(helper_guest.as_os_str().to_owned());
    push(&mut args, "--ro-bind");
    args.push(runtime_host.as_os_str().to_owned());
    push(&mut args, GUEST_RUNTIME);
    if let Some(state) = &request.writable_home_state {
        push(&mut args, "--bind");
        args.push(state.host_source.as_os_str().to_owned());
        args.push(state.guest_target.as_os_str().to_owned());
    }
    if let Some((host, guest)) = tool_mount {
        push(&mut args, "--ro-bind");
        args.push(host.into_os_string());
        args.push(guest.into_os_string());
    }
    push(&mut args, "--bind");
    args.push(workspace.as_os_str().to_owned());
    push(&mut args, "/workspace");
    push(&mut args, "--ro-bind");
    args.push(runtime_host.join("inbox").into_os_string());
    push(&mut args, SANDBOX_INBOX);
    push(&mut args, "--chdir");
    push(&mut args, "/workspace");
    for (name, value) in [
        ("HOME", "/home/guard"),
        (
            "PATH",
            "/opt/sandbox-guard/tool:/usr/local/bin:/usr/bin:/bin",
        ),
        ("LANG", "C.UTF-8"),
    ] {
        push(&mut args, "--setenv");
        push(&mut args, name);
        push(&mut args, value);
    }
    if request.interactive {
        push(&mut args, "--setenv");
        push(&mut args, "TERM");
        push(&mut args, "xterm-256color");
    }
    args.extend(supervisor_args(
        request,
        helper_guest,
        tool_command,
        &request.tool.args,
    ));
    args
}

pub(crate) fn guest_bwrap_args(
    request: &RunRequest,
    workspace: &Path,
    runtime_root: &Path,
    helper: &Path,
) -> Vec<OsString> {
    let mut args = Vec::new();
    push(&mut args, "--die-with-parent");
    push(&mut args, "--new-session");
    push(&mut args, "--unshare-user");
    push(&mut args, "--unshare-pid");
    push(&mut args, "--unshare-ipc");
    push(&mut args, "--unshare-uts");
    push(&mut args, "--unshare-cgroup");
    if request.network != NetworkMode::Unrestricted {
        push(&mut args, "--unshare-net");
    }
    push(&mut args, "--hostname");
    push(&mut args, "sandbox-guard");
    push(&mut args, "--cap-drop");
    push(&mut args, "ALL");
    push(&mut args, "--clearenv");
    push(&mut args, "--tmpfs");
    push(&mut args, "/");
    push(&mut args, "--proc");
    push(&mut args, "/proc");
    push(&mut args, "--dev");
    push(&mut args, "/dev");
    push(&mut args, "--tmpfs");
    push(&mut args, "/tmp");
    push(&mut args, "--tmpfs");
    push(&mut args, "/dev/shm");
    for directory in [
        "/home",
        "/home/guard",
        "/home/guard/.grok",
        "/opt",
        "/opt/sandbox-guard",
        "/run",
    ] {
        push(&mut args, "--dir");
        push(&mut args, directory);
    }
    for path in [
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/usr/local",
        "/opt/sandbox-guard/tools",
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "/etc/localtime",
    ] {
        push(&mut args, "--ro-bind-try");
        push(&mut args, path);
        push(&mut args, path);
    }
    if let Some(root) = &request.tool.tool_root {
        push(&mut args, "--ro-bind");
        args.push(root.as_os_str().to_owned());
        args.push(root.as_os_str().to_owned());
    }
    if request.network == NetworkMode::Unrestricted {
        for path in ["/etc/resolv.conf", "/etc/hosts"] {
            push(&mut args, "--ro-bind-try");
            push(&mut args, path);
            push(&mut args, path);
        }
    }
    push(&mut args, "--ro-bind");
    args.push(runtime_root.as_os_str().to_owned());
    push(&mut args, GUEST_RUNTIME);
    if let Some(state) = &request.writable_home_state {
        push(&mut args, "--bind");
        args.push(runtime_root.join("session-state").into_os_string());
        args.push(state.guest_target.as_os_str().to_owned());
    }
    push(&mut args, "--bind");
    args.push(workspace.as_os_str().to_owned());
    push(&mut args, "/workspace");
    push(&mut args, "--ro-bind");
    args.push(runtime_root.join("inbox").into_os_string());
    push(&mut args, SANDBOX_INBOX);
    push(&mut args, "--chdir");
    push(&mut args, "/workspace");
    for (name, value) in [
        ("HOME", "/home/guard"),
        (
            "PATH",
            "/opt/sandbox-guard/tools:/usr/local/bin:/usr/bin:/bin",
        ),
        ("LANG", "C.UTF-8"),
    ] {
        push(&mut args, "--setenv");
        push(&mut args, name);
        push(&mut args, value);
    }
    if request.interactive {
        push(&mut args, "--setenv");
        push(&mut args, "TERM");
        push(&mut args, "xterm-256color");
    }
    args.extend(supervisor_args(
        request,
        helper,
        request.tool.command.clone(),
        &request.tool.args,
    ));
    args
}

fn supervisor_args(
    request: &RunRequest,
    helper: &Path,
    tool_command: OsString,
    tool_args: &[OsString],
) -> Vec<OsString> {
    let limits = request.resource_limits;
    let mut args = Vec::new();
    push(&mut args, "--");
    args.push(helper.as_os_str().to_owned());
    push(&mut args, "supervise");
    push(&mut args, "--environment");
    push(&mut args, GUEST_ENVIRONMENT);
    if request.network == NetworkMode::Controlled {
        push(&mut args, "--proxy-socket");
        push(&mut args, GUEST_PROXY_SOCKET);
    }
    for (name, value) in [
        ("--memory-bytes", limits.memory_bytes),
        ("--max-file-bytes", limits.max_file_bytes),
        ("--cpu-seconds", limits.cpu_seconds),
        ("--open-files", limits.open_files),
        ("--max-processes", limits.max_processes),
        ("--cpu-percent", limits.cpu_percent),
    ] {
        push(&mut args, name);
        args.push(value.to_string().into());
    }
    if let Some(preflight) = &request.preflight {
        push(&mut args, "--preflight-command");
        args.push(if preflight.command == request.tool.command {
            tool_command.clone()
        } else {
            preflight.command.clone()
        });
        for argument in &preflight.args {
            push(&mut args, "--preflight-arg");
            args.push(argument.clone());
        }
    }
    push(&mut args, "--");
    args.push(tool_command);
    args.extend(tool_args.iter().cloned());
    args
}

/// Launch a host `bwrap` from a fully empty process environment.
///
/// Bubblewrap's `--clearenv` scrubs the environment of the executed *child*, but bwrap itself
/// stays alive as pid 1 inside the sandbox pid namespace, and its own `/proc/1/environ` remains
/// readable by the confined tool. Interposing `env -i` here means bwrap execs with no inherited
/// variables at all, so no host session identity or secret survives on pid 1.
///
/// Both executables at this trust boundary are fixed absolute paths: `/usr/bin/env` (so a
/// PATH-selected `env` cannot run before the environment is cleared) and the runner's already
/// resolved absolute `bwrap` path (so the emptied environment does not defeat command lookup).
fn launch_bwrap_with_clean_env(
    bwrap: PathBuf,
    bwrap_args: Vec<OsString>,
) -> (PathBuf, Vec<OsString>) {
    let mut args = Vec::with_capacity(bwrap_args.len() + 2);
    push(&mut args, "-i");
    args.push(bwrap.into_os_string());
    args.extend(bwrap_args);
    (PathBuf::from(HOST_CLEAN_ENV), args)
}

pub(crate) fn wrap_guest_cgroup(request: &RunRequest, bwrap_args: Vec<OsString>) -> Vec<OsString> {
    let mut args = vec![OsString::from("systemd-run")];
    args.extend(systemd_scope_args(request));
    args.extend(guest_bwrap_command(bwrap_args));
    args
}

/// Build the guest-side `bwrap` invocation behind an `env -i` clean-environment boundary.
///
/// On the Lima guest, `bwrap` is reached over `limactl shell`, so it inherits the guest login
/// session's environment (home, proxy, XDG/DBUS, SSH). As on the host, that environment stays
/// visible on bwrap's `/proc/1/environ`. `env -i` drops all of it, leaving pid 1 with an empty
/// environment; the bwrap child receives its own PATH through `--setenv`.
///
/// Both executables are fixed absolute guest paths — `/usr/bin/env` and `/usr/bin/bwrap`, the
/// canonical apt-installed locations the setup diagnostic requires — so a PATH-selected binary can
/// never run at this boundary and no fixed PATH needs to leak onto pid 1.
pub(crate) fn guest_bwrap_command(bwrap_args: Vec<OsString>) -> Vec<OsString> {
    let mut command = Vec::with_capacity(bwrap_args.len() + 3);
    push(&mut command, GUEST_CLEAN_ENV);
    push(&mut command, "-i");
    push(&mut command, GUEST_BWRAP);
    command.extend(bwrap_args);
    command
}

fn wrap_in_systemd_scope(
    request: &RunRequest,
    bwrap: PathBuf,
    bwrap_args: Vec<OsString>,
) -> (PathBuf, Vec<OsString>) {
    let mut args = systemd_scope_args(request);
    // systemd-run legitimately needs the user-session environment to reach the user systemd
    // manager, so the clean-environment boundary is placed *after* it, immediately before bwrap.
    // `/usr/bin/env` is fixed and absolute so a PATH-selected `env` cannot run at this boundary.
    push(&mut args, HOST_CLEAN_ENV);
    push(&mut args, "-i");
    args.push(bwrap.into_os_string());
    args.extend(bwrap_args);
    (PathBuf::from("systemd-run"), args)
}

fn systemd_scope_args(request: &RunRequest) -> Vec<OsString> {
    systemd_scope_args_for_unit(
        request.resource_limits,
        &format!("sandbox-guard-{}", request.run_id),
    )
}

fn systemd_scope_args_for_unit(limits: ResourceLimits, unit: &str) -> Vec<OsString> {
    let mut args = Vec::new();
    for value in ["--user", "--scope", "--quiet", "--collect"] {
        push(&mut args, value);
    }
    args.push(format!("--unit={unit}").into());
    for property in [
        format!("MemoryMax={}", limits.memory_bytes),
        "MemorySwapMax=0".to_owned(),
        format!("TasksMax={}", limits.max_processes),
        format!("CPUQuota={}%", limits.cpu_percent),
    ] {
        push(&mut args, "--property");
        args.push(property.into());
    }
    push(&mut args, "--");
    args
}

fn cgroup_probe_args_for_limits(limits: ResourceLimits, helper: &Path) -> Vec<OsString> {
    let unit = format!("sandbox-guard-probe-{}", uuid::Uuid::new_v4());
    let mut args = systemd_scope_args_for_unit(limits, &unit);
    args.push(helper.as_os_str().to_owned());
    push(&mut args, "cgroup-probe");
    for (name, value) in [
        ("--memory-bytes", limits.memory_bytes),
        ("--max-processes", limits.max_processes),
        ("--cpu-percent", limits.cpu_percent),
    ] {
        push(&mut args, name);
        args.push(value.to_string().into());
    }
    args
}

pub(crate) fn cgroup_probe_args(request: &RunRequest, helper: &Path) -> Vec<OsString> {
    cgroup_probe_args_for_limits(request.resource_limits, helper)
}

/// Run the exact transient cgroup-v2 probe used by the Linux execution backend.
///
/// Setup uses this public seam rather than maintaining a diagnostic approximation. A false result
/// means required mode must fail closed; callers may choose whether unavailability is optional.
pub fn linux_cgroup_probe_available(
    limits: ResourceLimits,
    helper: &Path,
) -> Result<bool, RunnerError> {
    let Some(program) = which::which("systemd-run").ok() else {
        return Ok(false);
    };
    Command::new(&program)
        .args(cgroup_probe_args_for_limits(limits, helper))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|source| RunnerError::Execute { program, source })
}

fn resolve_cgroup_mode(
    request: &RunRequest,
    helper: &Path,
) -> Result<(bool, Vec<String>), RunnerError> {
    if request.cgroup_mode == CgroupMode::Disabled {
        return Ok((
            false,
            vec!["cgroup enforcement disabled by request".to_owned()],
        ));
    }
    let available = linux_cgroup_probe_available(request.resource_limits, helper).unwrap_or(false);
    if available {
        Ok((true, Vec::new()))
    } else if request.cgroup_mode == CgroupMode::Required {
        Err(RunnerError::CgroupUnavailable)
    } else {
        Ok((
            false,
            vec![
                "cgroup v2 user delegation unavailable; rlimits and seccomp remain enforced"
                    .to_owned(),
            ],
        ))
    }
}

pub(crate) fn guest_helper_path(request: &RunRequest) -> PathBuf {
    request
        .helper_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/guard-helper"))
}

fn resolve_host_helper(request: &RunRequest) -> Result<PathBuf, RunnerError> {
    let candidate = if let Some(path) = &request.helper_path {
        path.clone()
    } else if let Ok(current) = std::env::current_exe() {
        let sibling = current.with_file_name("guard-helper");
        if sibling.is_file() {
            sibling
        } else {
            which::which("guard-helper").map_err(|source| RunnerError::DependencyMissing {
                name: "guard-helper",
                source,
            })?
        }
    } else {
        which::which("guard-helper").map_err(|source| RunnerError::DependencyMissing {
            name: "guard-helper",
            source,
        })?
    };
    let path = fs::canonicalize(&candidate).map_err(|source| RunnerError::Inspect {
        path: candidate,
        source,
    })?;
    if !path.is_file() {
        return Err(RunnerError::InvalidHelperPath(path));
    }
    Ok(path)
}

fn planned_runtime_path(request: &RunRequest, workspace: &Path) -> PathBuf {
    workspace
        .parent()
        .unwrap_or(workspace)
        .join(format!(".sandbox-guard-runtime-{}", request.run_id))
}

fn resolve_host_tool(
    request: &RunRequest,
) -> Result<(OsString, Option<(PathBuf, PathBuf)>), RunnerError> {
    if let Some(root) = &request.tool.tool_root {
        let root = fs::canonicalize(root).map_err(|source| RunnerError::Inspect {
            path: root.clone(),
            source,
        })?;
        if !root.is_dir() || !root.is_absolute() {
            return Err(RunnerError::InvalidToolRoot(root));
        }
        let requested = Path::new(&request.tool.command);
        let host_tool = if requested.is_absolute() {
            fs::canonicalize(requested).map_err(|source| RunnerError::Inspect {
                path: requested.to_path_buf(),
                source,
            })?
        } else {
            fs::canonicalize(root.join(requested)).map_err(|source| RunnerError::Inspect {
                path: root.join(requested),
                source,
            })?
        };
        if !path_is_within(&host_tool, &root) {
            return Err(RunnerError::ToolOutsideRoot {
                tool: host_tool,
                root,
            });
        }
        let relative = host_tool.strip_prefix(&root).expect("checked above");
        let guest = Path::new("/opt/sandbox-guard/tool").join(relative);
        return Ok((
            guest.into_os_string(),
            Some((root, PathBuf::from("/opt/sandbox-guard/tool"))),
        ));
    }

    let resolved =
        which::which(&request.tool.command).map_err(|source| RunnerError::ToolNotFound {
            tool: request.tool.command.clone(),
            source,
        })?;
    let resolved = fs::canonicalize(&resolved).map_err(|source| RunnerError::Inspect {
        path: resolved,
        source,
    })?;
    if [Path::new("/usr"), Path::new("/bin")]
        .iter()
        .any(|root| path_is_within(&resolved, root))
    {
        return Ok((resolved.into_os_string(), None));
    }
    Ok((
        OsString::from("/opt/sandbox-guard/tool"),
        Some((resolved, PathBuf::from("/opt/sandbox-guard/tool"))),
    ))
}

fn bind_if_present(args: &mut Vec<OsString>, source: &str, destination: &str) {
    if Path::new(source).is_dir() {
        push(args, "--ro-bind");
        push(args, source);
        push(args, destination);
    }
}

fn bind_file_if_present(args: &mut Vec<OsString>, source: &str, destination: &str) {
    if Path::new(source).is_file() {
        push(args, "--ro-bind");
        push(args, source);
        push(args, destination);
    }
}

fn push(args: &mut Vec<OsString>, value: impl AsRef<OsStr>) {
    args.push(value.as_ref().to_owned());
}

pub(crate) fn network_warnings(mode: NetworkMode, boundary: &str) -> Vec<String> {
    match mode {
        NetworkMode::Denied | NetworkMode::Controlled => Vec::new(),
        NetworkMode::Unrestricted => vec![format!(
            "UNSAFE NETWORK MODE: sharing the {boundary} network namespace exposes loopback, private and LAN services, cloud metadata (169.254.169.254), and Linux abstract UNIX sockets. Abstract sockets are outside filesystem isolation and may permit code execution in that network namespace. Development use only."
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProcessSpec, ToolSpec, WritableHomeState};

    fn request(workspace: &Path, network: NetworkMode) -> RunRequest {
        RunRequest {
            workspace: workspace.to_path_buf(),
            run_id: "00000000-0000-4000-8000-000000000000".to_owned(),
            tool: ToolSpec {
                command: OsString::from("/bin/echo"),
                args: vec![OsString::from("--version")],
                tool_root: None,
            },
            preflight: None,
            interactive: false,
            interactive_ux: crate::InteractiveUx::default(),
            network,
            allowed_egress_hosts: if network == NetworkMode::Controlled {
                vec!["api.example.com".to_owned()]
            } else {
                vec![]
            },
            interactive_egress_approval: false,
            egress_decision_store: None,
            writable_home_state: None,
            forwarded_env: vec![("GROK_TOKEN".to_owned(), "secret".to_owned())],
            resource_limits: crate::ResourceLimits::default(),
            cgroup_mode: CgroupMode::BestEffort,
            helper_path: Some(PathBuf::from("/bin/true")),
            lima_instance: "sandbox-guard".to_owned(),
        }
    }

    #[test]
    fn guest_plan_clears_environment_and_denies_network() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let runtime = Path::new("/tmp/guard-test/runtime");
        let helper = Path::new("/usr/local/bin/guard-helper");
        let args = guest_bwrap_args(
            &request(workspace, NetworkMode::Denied),
            workspace,
            runtime,
            helper,
        );
        let strings: Vec<_> = args.iter().map(|arg| arg.to_string_lossy()).collect();
        assert!(strings.iter().any(|arg| arg == "--clearenv"));
        assert!(strings.iter().any(|arg| arg == "--unshare-net"));
        assert!(strings.iter().any(|arg| arg == "--unshare-pid"));
        assert!(strings.iter().any(|arg| arg == "--cap-drop"));
        assert!(strings.iter().any(|arg| arg == "/workspace"));
        assert!(strings.iter().any(|arg| arg == "supervise"));
        assert!(!strings.iter().any(|arg| arg.contains("secret")));
        assert!(strings.windows(3).any(|window| {
            window == ["--ro-bind", "/tmp/guard-test/runtime/inbox", SANDBOX_INBOX]
        }));
    }

    #[test]
    fn interactive_guest_plan_sets_only_a_fixed_safe_terminal_type() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let mut request = request(workspace, NetworkMode::Denied);
        request.interactive = true;
        let args = guest_bwrap_args(
            &request,
            workspace,
            Path::new("/tmp/guard-test"),
            Path::new("/usr/local/bin/guard-helper"),
        );
        let strings: Vec<_> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(
            strings
                .windows(3)
                .any(|window| { window == ["--setenv", "TERM", "xterm-256color"] })
        );
    }

    #[test]
    fn controlled_mode_keeps_network_namespace_and_uses_proxy_socket() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let args = guest_bwrap_args(
            &request(workspace, NetworkMode::Controlled),
            workspace,
            Path::new("/tmp/guard-test/runtime"),
            Path::new("/usr/local/bin/guard-helper"),
        );
        let strings: Vec<_> = args.iter().map(|arg| arg.to_string_lossy()).collect();
        assert!(strings.iter().any(|arg| arg == "--unshare-net"));
        assert!(strings.iter().any(|arg| arg == "--proxy-socket"));
        assert!(strings.iter().any(|arg| arg == GUEST_PROXY_SOCKET));
    }

    #[test]
    fn supervisor_plan_encodes_a_preflight_without_a_shell() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let mut request = request(workspace, NetworkMode::Denied);
        request.preflight = Some(ProcessSpec {
            command: OsString::from("grok"),
            args: vec![OsString::from("login")],
        });
        let args = guest_bwrap_args(
            &request,
            workspace,
            Path::new("/tmp/guard-test/runtime"),
            Path::new("/usr/local/bin/guard-helper"),
        );
        let strings: Vec<_> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            strings
                .windows(2)
                .any(|window| { window == ["--preflight-command", "grok"] })
        );
        assert!(
            strings
                .windows(2)
                .any(|window| { window == ["--preflight-arg", "login"] })
        );
    }

    #[test]
    fn writable_session_state_is_bound_only_at_the_narrow_grok_path() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let runtime = Path::new("/tmp/guard-test/runtime");
        let mut request = request(workspace, NetworkMode::Denied);
        request.writable_home_state = Some(WritableHomeState {
            host_source: PathBuf::from("/private/guard-session-stage"),
            guest_target: PathBuf::from("/home/guard/.grok/sessions"),
        });
        let guest_args = guest_bwrap_args(
            &request,
            workspace,
            runtime,
            Path::new("/usr/local/bin/guard-helper"),
        );
        let guest_strings: Vec<_> = guest_args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(guest_strings.windows(3).any(|window| {
            window
                == [
                    "--bind",
                    "/tmp/guard-test/runtime/session-state",
                    "/home/guard/.grok/sessions",
                ]
        }));
        assert!(
            !guest_strings
                .windows(3)
                .any(|window| { window[0] == "--bind" && window[2] == "/home/guard/.grok" })
        );

        let host_args = build_bwrap_args(
            &request,
            workspace,
            runtime,
            Path::new("/usr/local/bin/guard-helper"),
            Path::new("/opt/sandbox-guard/helper"),
            OsString::from("/usr/bin/tool"),
            None,
        );
        let host_strings: Vec<_> = host_args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(host_strings.windows(3).any(|window| {
            window
                == [
                    "--bind",
                    "/private/guard-session-stage",
                    "/home/guard/.grok/sessions",
                ]
        }));
    }

    #[test]
    fn unrestricted_network_is_explicit_in_plan_and_warning() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let args = guest_bwrap_args(
            &request(workspace, NetworkMode::Unrestricted),
            workspace,
            Path::new("/tmp/guard-test/runtime"),
            Path::new("/usr/local/bin/guard-helper"),
        );
        assert!(
            !args
                .iter()
                .any(|arg| arg.to_string_lossy() == "--unshare-net")
        );
        assert!(!network_warnings(NetworkMode::Unrestricted, "test").is_empty());
    }

    #[test]
    fn cgroup_probe_uses_the_same_controller_properties_as_the_real_scope() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let request = request(workspace, NetworkMode::Denied);
        let probe: Vec<_> = cgroup_probe_args(&request, Path::new("/guard-helper"))
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        for expected in ["MemoryMax=", "MemorySwapMax=0", "TasksMax=", "CPUQuota="] {
            assert!(probe.iter().any(|value| value.starts_with(expected)));
        }

        let guest = wrap_guest_cgroup(&request, vec![OsString::from("--version")]);
        assert_eq!(guest.first(), Some(&OsString::from("systemd-run")));
    }

    #[test]
    fn namespace_probe_matches_the_production_namespace_and_clean_environment_shape() {
        let probe: Vec<_> = linux_namespace_probe_args()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        for required in [
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
            "--unshare-net",
            "--cap-drop",
            "--clearenv",
            "--proc",
            "--dev",
        ] {
            assert!(probe.iter().any(|value| value == required));
        }
        assert_eq!(probe.last().map(String::as_str), Some("/usr/bin/true"));
        assert!(probe.windows(2).any(|window| window == ["--tmpfs", "/"]));
        assert!(probe.windows(2).any(|window| window == ["--proc", "/proc"]));
        assert!(probe.windows(2).any(|window| window == ["--dev", "/dev"]));
    }

    fn rendered_strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn host_plan_scrubs_the_bwrap_launcher_environment() {
        let workspace = tempfile::tempdir().unwrap();
        let request = request(workspace.path(), NetworkMode::Denied);

        // Best-effort (no cgroup) route: `env -i` is the launched program and bwrap, passed by
        // absolute path, is its first argument, so bwrap execs with an empty environment.
        let plan = LinuxBwrapRunner::build_plan(
            &request,
            PathBuf::from("/usr/bin/bwrap"),
            PathBuf::from("/bin/true"),
            Path::new("/tmp/runtime"),
            false,
        )
        .unwrap();
        assert_eq!(plan.program, PathBuf::from("/usr/bin/env"));
        assert_eq!(plan.args[0], OsString::from("-i"));
        assert_eq!(plan.args[1], OsString::from("/usr/bin/bwrap"));
        assert!(
            !plan
                .args
                .iter()
                .any(|arg| arg.to_string_lossy().starts_with("PATH=")),
            "host launcher must not re-establish any environment for bwrap"
        );

        // cgroup route: systemd-run keeps the session env it needs, and the clean-env boundary is
        // placed after the scope terminator `--`, immediately before bwrap.
        let scoped = LinuxBwrapRunner::build_plan(
            &request,
            PathBuf::from("/usr/bin/bwrap"),
            PathBuf::from("/bin/true"),
            Path::new("/tmp/runtime"),
            true,
        )
        .unwrap();
        assert_eq!(scoped.program, PathBuf::from("systemd-run"));
        let strings = rendered_strings(&scoped.args);
        let boundary = strings
            .windows(2)
            .position(|window| window == ["/usr/bin/env", "-i"])
            .expect("clean-env boundary present on the cgroup route");
        assert_eq!(strings[boundary + 2], "/usr/bin/bwrap");
        let terminator = strings
            .iter()
            .position(|value| value == "--")
            .expect("systemd scope terminator present");
        assert!(
            terminator < boundary,
            "the clean-env boundary must sit after the systemd-run scope terminator"
        );
    }

    #[test]
    fn interactive_host_plan_still_scrubs_the_bwrap_launcher_environment() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path(), NetworkMode::Denied);
        request.interactive = true;
        let plan = LinuxBwrapRunner::build_plan(
            &request,
            PathBuf::from("/usr/bin/bwrap"),
            PathBuf::from("/bin/true"),
            Path::new("/tmp/runtime"),
            false,
        )
        .unwrap();
        assert_eq!(plan.program, PathBuf::from("/usr/bin/env"));
        assert_eq!(plan.args[0], OsString::from("-i"));
        assert_eq!(plan.args[1], OsString::from("/usr/bin/bwrap"));
    }

    #[test]
    fn guest_bwrap_command_installs_a_clean_env_boundary_on_every_route() {
        let bwrap_args = vec![
            OsString::from("--die-with-parent"),
            OsString::from("supervise"),
        ];

        // Both boundary executables are fixed absolute guest paths and the launcher environment is
        // empty: no `PATH=` assignment is injected.
        let command = guest_bwrap_command(bwrap_args.clone());
        let strings = rendered_strings(&command);
        assert_eq!(strings[0], "/usr/bin/env");
        assert_eq!(strings[1], "-i");
        assert_eq!(strings[2], "/usr/bin/bwrap");
        assert_eq!(strings[3], "--die-with-parent");
        assert!(
            !strings.iter().any(|value| value.starts_with("PATH=")),
            "guest launcher must inherit an empty environment"
        );

        let request = request(Path::new("/tmp/guard-test/workspace"), NetworkMode::Denied);
        let scoped = wrap_guest_cgroup(&request, bwrap_args);
        let scoped_strings = rendered_strings(&scoped);
        assert_eq!(scoped_strings[0], "systemd-run");
        let boundary = scoped_strings
            .windows(3)
            .position(|window| window == ["/usr/bin/env", "-i", "/usr/bin/bwrap"])
            .expect("guest cgroup route installs the clean-env boundary before bwrap");
        let terminator = scoped_strings
            .iter()
            .position(|value| value == "--")
            .expect("systemd scope terminator present");
        assert!(
            terminator < boundary,
            "the guest clean-env boundary must sit after the systemd-run scope terminator"
        );
    }

    #[test]
    fn real_linux_plan_contains_no_forwarded_value() {
        let workspace = tempfile::tempdir().unwrap();
        let request = request(workspace.path(), NetworkMode::Denied);
        let plan = LinuxBwrapRunner::build_plan(
            &request,
            PathBuf::from("/usr/bin/bwrap"),
            PathBuf::from("/bin/true"),
            Path::new("/tmp/runtime"),
            false,
        )
        .unwrap();
        let rendered = plan.rendered();
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("<redacted>"));
    }

    #[test]
    fn private_environment_file_contains_values_but_has_private_mode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("environment.json");
        write_environment_file(
            &path,
            &[("VENDOR_TOKEN".to_owned(), "secret-value".to_owned())],
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(fs::read_to_string(path).unwrap().contains("secret-value"));
    }
}
