use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::approval::ApprovalController;
use crate::clipboard::{read_clipboard_image, write_private_image};
use crate::linux::{
    cgroup_probe_args, cleanup_workspace_inbox, guest_bwrap_args, guest_bwrap_command,
    guest_helper_path, network_warnings, prepare_workspace_inbox, wrap_guest_cgroup,
    write_environment_file,
};
use crate::terminal::{ClipboardPaste, run_interactive};
use crate::{
    BackendKind, CgroupMode, CommandPlan, NetworkMode, RunOutcome, RunRequest, RunnerError,
};

pub struct MacosLimaRunner;

impl MacosLimaRunner {
    pub fn plan(request: &RunRequest) -> Result<CommandPlan, RunnerError> {
        let limactl = which::which("limactl").map_err(|source| RunnerError::DependencyMissing {
            name: "limactl",
            source,
        })?;
        let guest_root = guest_root(request);
        let helper = guest_helper_path(request);
        let bwrap_args = guest_bwrap_args(request, &guest_workspace(request), &guest_root, &helper);
        let guest_command = if request.cgroup_mode == CgroupMode::Disabled {
            guest_bwrap_command(bwrap_args)
        } else {
            wrap_guest_cgroup(request, bwrap_args)
        };
        let mut args = vec![
            OsString::from(lima_main_tty_arg(request)),
            OsString::from("shell"),
            OsString::from(&request.lima_instance),
            OsString::from("--"),
        ];
        args.extend(guest_command);
        Ok(CommandPlan {
            program: limactl,
            args,
            redacted_args: BTreeSet::new(),
            warnings: network_warnings(request.network, "Lima guest"),
        })
    }

    pub fn run(request: &RunRequest) -> Result<RunOutcome, RunnerError> {
        let limactl = which::which("limactl").map_err(|source| RunnerError::DependencyMissing {
            name: "limactl",
            source,
        })?;
        start_mountless_instance(&limactl, &request.lima_instance)?;
        verify_no_host_mounts(&limactl, &request.lima_instance)?;
        let helper = guest_helper_path(request);
        verify_guest_helper(&limactl, request, &helper)?;

        let guest_root = guest_root(request);
        prepare_workspace_inbox(&request.workspace)?;
        prepare_guest_root(&limactl, request, &guest_root)?;
        if let Err(error) = copy_workspace_and_environment(&limactl, request, &guest_root) {
            let _ = cleanup_guest(&limactl, request, &guest_root);
            return Err(error);
        }

        let mut proxy = if request.network == NetworkMode::Controlled {
            match start_guest_proxy(&limactl, request, &guest_root, &helper) {
                Ok(proxy) => Some(proxy),
                Err(error) => {
                    let _ = cleanup_guest(&limactl, request, &guest_root);
                    return Err(error);
                }
            }
        } else {
            None
        };
        let (use_cgroup, mut warnings) = match resolve_guest_cgroup(&limactl, request, &helper) {
            Ok(result) => result,
            Err(error) => {
                stop_proxy(&mut proxy);
                let _ = cleanup_guest(&limactl, request, &guest_root);
                return Err(error);
            }
        };
        warnings.extend(network_warnings(request.network, "Lima guest"));
        let bwrap_args = guest_bwrap_args(request, &guest_workspace(request), &guest_root, &helper);
        let guest_command = if use_cgroup {
            wrap_guest_cgroup(request, bwrap_args)
        } else {
            guest_bwrap_command(bwrap_args)
        };
        let mut shell_args = vec![
            OsString::from(lima_main_tty_arg(request)),
            OsString::from("shell"),
            OsString::from(&request.lima_instance),
            OsString::from("--"),
        ];
        shell_args.extend(guest_command);
        let execution = if request.interactive {
            run_interactive(&limactl, &shell_args, request.interactive_ux, || {
                import_clipboard_into_guest(&limactl, request, &guest_root)
            })
            .map(|outcome| (outcome.status, outcome.clipboard_imports))
        } else {
            Command::new(&limactl)
                .args(&shell_args)
                .status()
                .map(|status| (status, Vec::new()))
                .map_err(|source| RunnerError::Execute {
                    program: limactl.clone(),
                    source,
                })
        };
        let (status, clipboard_imports) = match execution {
            Ok(execution) => execution,
            Err(error) => {
                stop_proxy(&mut proxy);
                let _ = cleanup_guest(&limactl, request, &guest_root);
                return Err(error);
            }
        };
        let retrieve_result = (|| {
            let guest_workspace = guest_root.join("workspace");
            let workspace_canary =
                create_retrieval_canary(&limactl, request, &guest_workspace, "workspace")?;
            retrieve_guest_directory(
                &limactl,
                request,
                &guest_workspace,
                &request.workspace,
                "workspace",
            )?;
            verify_retrieval_canary(&request.workspace, &workspace_canary)?;

            if let Some(state) = &request.writable_home_state {
                let guest_state = guest_root.join("session-state");
                let state_canary =
                    create_retrieval_canary(&limactl, request, &guest_state, "session-state")?;
                retrieve_guest_directory(
                    &limactl,
                    request,
                    &guest_state,
                    &state.host_source,
                    "session-state",
                )?;
                verify_retrieval_canary(&state.host_source, &state_canary)?;
            }
            Ok(())
        })();
        let egress_audit = read_guest_egress_audit(&limactl, request, &guest_root);
        let egress_approvals = stop_proxy(&mut proxy);
        let cleanup_result = cleanup_guest(&limactl, request, &guest_root);
        retrieve_result?;
        cleanup_result?;
        cleanup_workspace_inbox(&request.workspace)?;

        Ok(RunOutcome {
            backend: BackendKind::MacosLima,
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

fn import_clipboard_into_guest(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
) -> Result<ClipboardPaste, RunnerError> {
    let image = read_clipboard_image()?;
    let local = tempfile::Builder::new()
        .prefix("sandbox-guard-clipboard-delivery-")
        .tempdir()
        .map_err(|source| RunnerError::SetupFailed(source.to_string()))?;
    fs::set_permissions(local.path(), fs::Permissions::from_mode(0o700)).map_err(|source| {
        RunnerError::Inspect {
            path: local.path().to_path_buf(),
            source,
        }
    })?;
    let local_image = write_private_image(local.path(), &image)?;
    let remote = format!(
        "{}:{}",
        request.lima_instance,
        guest_root.join("inbox").join(&image.filename).display()
    );
    run_checked(
        limactl,
        [
            OsString::from("--tty=false"),
            OsString::from("copy"),
            OsString::from("--backend=rsync"),
            local_image.into_os_string(),
            OsString::from(remote),
        ],
        "deliver clipboard image to Lima inbox",
    )?;
    run_checked(
        limactl,
        shell_command(
            request,
            [
                OsString::from("test"),
                OsString::from("-f"),
                guest_root
                    .join("inbox")
                    .join(&image.filename)
                    .into_os_string(),
            ],
        ),
        "verify Lima clipboard image type",
    )?;
    let mode = run_checked(
        limactl,
        shell_command(
            request,
            [
                OsString::from("stat"),
                OsString::from("--format=%a:%s"),
                guest_root
                    .join("inbox")
                    .join(&image.filename)
                    .into_os_string(),
            ],
        ),
        "verify Lima clipboard image",
    )?;
    let expected = format!("600:{}", image.png.len());
    if String::from_utf8_lossy(&mode.stdout).trim() != expected {
        return Err(RunnerError::ClipboardUnavailable(
            "Lima clipboard image failed private mode or size verification".to_owned(),
        ));
    }
    Ok(ClipboardPaste {
        text: image.attachment_reference(),
        audit: image.audit_entry(),
    })
}

fn retrieve_guest_directory(
    limactl: &Path,
    request: &RunRequest,
    guest_directory: &Path,
    host_directory: &Path,
    label: &'static str,
) -> Result<(), RunnerError> {
    let host_parent = host_directory
        .parent()
        .ok_or_else(|| RunnerError::SetupFailed(format!("{label} has no parent")))?;
    let returned = tempfile::tempdir_in(host_parent)
        .map_err(|source| RunnerError::SetupFailed(source.to_string()))?;
    fs::set_permissions(returned.path(), fs::Permissions::from_mode(0o700)).map_err(|source| {
        RunnerError::Inspect {
            path: returned.path().to_path_buf(),
            source,
        }
    })?;
    let remote = format!("{}:{}", request.lima_instance, guest_directory.display());
    let returned_directory = returned.path().join("returned");
    run_checked(
        limactl,
        [
            OsString::from("--tty=false"),
            OsString::from("copy"),
            OsString::from("--backend=rsync"),
            OsString::from("--recursive"),
            OsString::from(remote),
            returned_directory.as_os_str().to_owned(),
        ],
        "retrieve disposable Lima directory",
    )?;
    let metadata =
        fs::symlink_metadata(&returned_directory).map_err(|source| RunnerError::Inspect {
            path: returned_directory.clone(),
            source,
        })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RunnerError::SetupFailed(format!(
            "Lima returned {label} is not a real directory"
        )));
    }
    let backup = host_parent.join(format!(".baseline-{}-{label}", request.run_id));
    fs::rename(host_directory, &backup).map_err(|source| RunnerError::Inspect {
        path: host_directory.to_path_buf(),
        source,
    })?;
    if let Err(source) = fs::rename(&returned_directory, host_directory) {
        let _ = fs::rename(&backup, host_directory);
        return Err(RunnerError::Inspect {
            path: returned_directory,
            source,
        });
    }
    fs::remove_dir_all(&backup).map_err(|source| RunnerError::Inspect {
        path: backup,
        source,
    })?;
    Ok(())
}

fn create_retrieval_canary(
    limactl: &Path,
    request: &RunRequest,
    guest_directory: &Path,
    label: &str,
) -> Result<(String, String), RunnerError> {
    let name = format!(".sandbox-guard-rsync-canary-{label}-{}", request.run_id);
    let target = format!(".sandbox-guard-rsync-target-{label}-{}", request.run_id);
    run_checked(
        limactl,
        shell_command(
            request,
            [
                OsString::from("ln"),
                OsString::from("-s"),
                OsString::from("--"),
                OsString::from(&target),
                guest_directory.join(&name).into_os_string(),
            ],
        ),
        "create Lima retrieval link canary",
    )?;
    Ok((name, target))
}

fn verify_retrieval_canary(
    host_directory: &Path,
    (name, target): &(String, String),
) -> Result<(), RunnerError> {
    let canary = host_directory.join(name);
    let metadata = fs::symlink_metadata(&canary).map_err(|source| RunnerError::Inspect {
        path: canary.clone(),
        source,
    })?;
    if !metadata.file_type().is_symlink()
        || fs::read_link(&canary).ok().as_deref() != Some(Path::new(target))
    {
        return Err(RunnerError::SetupFailed(
            "Lima rsync retrieval did not preserve a hostile-link canary".to_owned(),
        ));
    }
    fs::remove_file(&canary).map_err(|source| RunnerError::Inspect {
        path: canary,
        source,
    })
}

fn start_mountless_instance(limactl: &Path, instance: &str) -> Result<(), RunnerError> {
    run_checked(
        limactl,
        [
            OsString::from("--tty=false"),
            OsString::from("start"),
            OsString::from("--mount-none"),
            OsString::from(instance),
        ],
        "start mountless Lima instance",
    )?;
    Ok(())
}

fn verify_no_host_mounts(limactl: &Path, instance: &str) -> Result<(), RunnerError> {
    let output = Command::new(limactl)
        .args([
            OsStr::new("--tty=false"),
            OsStr::new("shell"),
            OsStr::new(instance),
            OsStr::new("--"),
            OsStr::new("findmnt"),
            OsStr::new("--noheadings"),
            OsStr::new("--output"),
            OsStr::new("TARGET,FSTYPE"),
        ])
        .output()
        .map_err(|source| RunnerError::Execute {
            program: limactl.to_path_buf(),
            source,
        })?;
    ensure_success("inspect Lima mounts", &output)?;
    let mounts = String::from_utf8_lossy(&output.stdout);
    for line in mounts.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("9p")
            || lower.contains("virtiofs")
            || lower.contains("sshfs")
            || lower.contains("reverse-sshfs")
        {
            return Err(RunnerError::UnsafeLimaMount(line.trim().to_owned()));
        }
    }
    Ok(())
}

fn verify_guest_helper(
    limactl: &Path,
    request: &RunRequest,
    helper: &Path,
) -> Result<(), RunnerError> {
    run_checked(
        limactl,
        shell_command(
            request,
            [OsString::from("test"), OsString::from("-x"), helper.into()],
        ),
        "verify the Lima guest runtime helper",
    )?;
    Ok(())
}

fn prepare_guest_root(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
) -> Result<(), RunnerError> {
    let workspace = guest_root.join("workspace");
    let mut directories = vec![
        OsString::from("mkdir"),
        OsString::from("-m"),
        OsString::from("700"),
        OsString::from("--"),
        guest_root.into(),
        workspace.into_os_string(),
        guest_root.join("inbox").into_os_string(),
    ];
    if request.writable_home_state.is_some() {
        directories.push(guest_root.join("session-state").into_os_string());
    }
    run_checked(
        limactl,
        shell_command(request, directories),
        "create private Lima guest runtime and workspace",
    )?;
    Ok(())
}

fn copy_workspace_and_environment(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
) -> Result<(), RunnerError> {
    let copy_target = guest_workspace_copy_target(request, guest_root);
    run_checked(
        limactl,
        [
            OsString::from("--tty=false"),
            OsString::from("copy"),
            OsString::from("--backend=rsync"),
            OsString::from("--recursive"),
            request.workspace.as_os_str().to_owned(),
            OsString::from(&copy_target),
        ],
        "copy sanitized workspace to Lima",
    )?;

    if let Some(state) = &request.writable_home_state {
        let state_target = format!(
            "{}:{}",
            request.lima_instance,
            guest_root.join("session-state").display()
        );
        run_checked(
            limactl,
            [
                OsString::from("--tty=false"),
                OsString::from("copy"),
                OsString::from("--backend=rsync"),
                OsString::from("--recursive"),
                state.host_source.as_os_str().to_owned(),
                OsString::from(state_target),
            ],
            "copy private session state to Lima",
        )?;
        run_checked(
            limactl,
            shell_command(
                request,
                [
                    OsString::from("chmod"),
                    OsString::from("700"),
                    guest_root.join("session-state").into_os_string(),
                ],
            ),
            "secure private Lima session state",
        )?;
    }

    let stage_root = request
        .workspace
        .parent()
        .ok_or_else(|| RunnerError::SetupFailed("staged workspace has no parent".to_owned()))?;
    let local = tempfile::tempdir_in(stage_root)
        .map_err(|source| RunnerError::SetupFailed(source.to_string()))?;
    let environment = local.path().join("environment.json");
    write_environment_file(&environment, &request.forwarded_env)?;
    let environment_target = format!(
        "{}:{}/environment.json",
        request.lima_instance,
        guest_root.display()
    );
    run_checked(
        limactl,
        [
            OsString::from("--tty=false"),
            OsString::from("copy"),
            OsString::from("--backend=rsync"),
            environment.into_os_string(),
            OsString::from(environment_target),
        ],
        "copy private environment to Lima",
    )?;
    run_checked(
        limactl,
        shell_command(
            request,
            [
                OsString::from("chmod"),
                OsString::from("600"),
                guest_root.join("environment.json").into_os_string(),
            ],
        ),
        "secure private Lima environment",
    )?;
    let delivered_mode = run_checked(
        limactl,
        shell_command(
            request,
            [
                OsString::from("stat"),
                OsString::from("--format=%a"),
                guest_root.join("environment.json").into_os_string(),
            ],
        ),
        "verify private Lima environment mode",
    )?;
    if String::from_utf8_lossy(&delivered_mode.stdout).trim() != "600" {
        return Err(RunnerError::SetupFailed(
            "Lima environment file was not delivered with mode 0600".to_owned(),
        ));
    }
    Ok(())
}

fn start_guest_proxy(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
    helper: &Path,
) -> Result<GuestProxyProcess, RunnerError> {
    let mut args = shell_command(
        request,
        [
            helper.as_os_str().to_owned(),
            OsString::from("proxy"),
            OsString::from("--socket"),
            guest_root.join("egress.sock").into_os_string(),
            OsString::from("--audit-log"),
            guest_root.join("egress-audit.log").into_os_string(),
        ],
    );
    for host in &request.allowed_egress_hosts {
        args.push(OsString::from("--allow-host"));
        args.push(host.into());
    }
    if request.interactive_egress_approval {
        args.push(OsString::from("--approval-stdio"));
    }
    let mut command = Command::new(limactl);
    command
        .args(args)
        // Lima launches an SSH child. A private process group lets Drop terminate both processes
        // if a run exits normally, errors, or is interrupted.
        .process_group(0);
    if request.interactive_egress_approval {
        // This private pipe carries only the trusted helper's approval protocol. It never shares
        // terminal input with the untrusted interactive command.
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
    } else {
        command.stdin(Stdio::null()).stdout(Stdio::null());
    }
    let mut child = command.spawn().map_err(|source| RunnerError::Execute {
        program: limactl.to_path_buf(),
        source,
    })?;
    let approval = if request.interactive_egress_approval {
        let requests = child.stdout.take().ok_or_else(|| {
            RunnerError::SetupFailed("Lima approval request pipe was not created".to_owned())
        })?;
        let responses = child.stdin.take().ok_or_else(|| {
            RunnerError::SetupFailed("Lima approval response pipe was not created".to_owned())
        })?;
        let decision_store = request.egress_decision_store.clone().ok_or_else(|| {
            RunnerError::SetupFailed("egress decision store was not configured".to_owned())
        })?;
        match ApprovalController::start(requests, responses, decision_store) {
            Ok(controller) => Some(controller),
            Err(error) => {
                let process_group = -(child.id() as i32);
                // SAFETY: the child was spawned as the leader of its own process group.
                unsafe {
                    libc::kill(process_group, libc::SIGKILL);
                }
                let _ = child.wait();
                return Err(error);
            }
        }
    } else {
        None
    };
    let mut proxy = GuestProxyProcess {
        child,
        approval,
        stopped: false,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = proxy
            .child
            .try_wait()
            .map_err(|source| RunnerError::Execute {
                program: limactl.to_path_buf(),
                source,
            })?
        {
            return Err(RunnerError::HelperFailed(format!(
                "Lima egress proxy exited with {status}"
            )));
        }
        let socket_ready = Command::new(limactl)
            .args(shell_command(
                request,
                [
                    OsString::from("test"),
                    OsString::from("-S"),
                    guest_root.join("egress.sock").into_os_string(),
                ],
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        let audit_ready = Command::new(limactl)
            .args(shell_command(
                request,
                [
                    OsString::from("test"),
                    OsString::from("-f"),
                    guest_root.join("egress-audit.log").into_os_string(),
                ],
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if socket_ready && audit_ready {
            return Ok(proxy);
        }
        if Instant::now() >= deadline {
            return Err(RunnerError::HelperFailed(
                "Lima egress proxy did not become ready".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

struct GuestProxyProcess {
    child: Child,
    approval: Option<ApprovalController>,
    stopped: bool,
}

impl GuestProxyProcess {
    fn stop(&mut self) -> Vec<String> {
        if self.stopped {
            return Vec::new();
        }
        self.stopped = true;
        let process_group = -(self.child.id() as i32);
        // SAFETY: the child was spawned as the leader of its own process group. Killing the group
        // prevents Lima's SSH transport from surviving after the limactl parent is reaped.
        unsafe {
            libc::kill(process_group, libc::SIGKILL);
        }
        let _ = self.child.wait();
        self.approval
            .take()
            .map(ApprovalController::finish)
            .unwrap_or_default()
    }
}

impl Drop for GuestProxyProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn stop_proxy(proxy: &mut Option<GuestProxyProcess>) -> Vec<String> {
    proxy
        .as_mut()
        .map(GuestProxyProcess::stop)
        .unwrap_or_default()
}

fn resolve_guest_cgroup(
    limactl: &Path,
    request: &RunRequest,
    helper: &Path,
) -> Result<(bool, Vec<String>), RunnerError> {
    if request.cgroup_mode == CgroupMode::Disabled {
        return Ok((
            false,
            vec!["cgroup enforcement disabled by request".to_owned()],
        ));
    }
    let status = Command::new(limactl)
        .args(shell_command(request, {
            let mut command = vec![OsString::from("systemd-run")];
            command.extend(cgroup_probe_args(request, helper));
            command
        }))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| RunnerError::Execute {
            program: limactl.to_path_buf(),
            source,
        })?;
    if status.success() {
        Ok((true, Vec::new()))
    } else if request.cgroup_mode == CgroupMode::Required {
        Err(RunnerError::CgroupUnavailable)
    } else {
        Ok((
            false,
            vec![
                "Lima guest cgroup v2 user delegation unavailable; rlimits and seccomp remain enforced"
                    .to_owned(),
            ],
        ))
    }
}

fn read_guest_egress_audit(limactl: &Path, request: &RunRequest, guest_root: &Path) -> Vec<String> {
    if request.network != NetworkMode::Controlled {
        return Vec::new();
    }
    Command::new(limactl)
        .args(shell_command(
            request,
            [
                OsString::from("cat"),
                guest_root.join("egress-audit.log").into_os_string(),
            ],
        ))
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn cleanup_guest(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
) -> Result<(), RunnerError> {
    run_checked(
        limactl,
        shell_command(
            request,
            [
                OsString::from("rm"),
                OsString::from("-rf"),
                OsString::from("--"),
                guest_root.into(),
            ],
        ),
        "remove Lima guest runtime",
    )?;
    Ok(())
}

fn shell_command<I>(request: &RunRequest, command: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = vec![
        OsString::from("--tty=false"),
        OsString::from("shell"),
        OsString::from(&request.lima_instance),
        OsString::from("--"),
    ];
    args.extend(command);
    args
}

fn lima_main_tty_arg(request: &RunRequest) -> &'static str {
    if request.interactive {
        "--tty=true"
    } else {
        "--tty=false"
    }
}

fn run_checked<I>(program: &Path, args: I, context: &'static str) -> Result<Output, RunnerError>
where
    I: IntoIterator<Item = OsString>,
{
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| RunnerError::Execute {
            program: program.to_path_buf(),
            source,
        })?;
    ensure_success(context, &output)?;
    Ok(output)
}

fn ensure_success(context: &str, output: &Output) -> Result<(), RunnerError> {
    if output.status.success() {
        Ok(())
    } else {
        Err(RunnerError::SetupFailed(format!(
            "{context}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn guest_root(request: &RunRequest) -> PathBuf {
    PathBuf::from(format!("/dev/shm/sandbox-guard-{}", request.run_id))
}

fn guest_workspace(request: &RunRequest) -> PathBuf {
    guest_root(request).join("workspace")
}

fn guest_workspace_copy_target(request: &RunRequest, guest_root: &Path) -> String {
    format!(
        "{}:{}",
        request.lima_instance,
        guest_root.join("workspace").display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResourceLimits, ToolSpec};

    fn request() -> RunRequest {
        RunRequest {
            workspace: PathBuf::from("/host/stage/workspace"),
            run_id: "00000000-0000-4000-8000-000000000000".to_owned(),
            tool: ToolSpec {
                command: OsString::from("/usr/bin/tool"),
                args: Vec::new(),
                tool_root: None,
            },
            preflight: None,
            interactive: false,
            interactive_ux: crate::InteractiveUx::default(),
            network: NetworkMode::Denied,
            allowed_egress_hosts: Vec::new(),
            interactive_egress_approval: false,
            egress_decision_store: None,
            writable_home_state: None,
            forwarded_env: Vec::new(),
            resource_limits: ResourceLimits::default(),
            cgroup_mode: CgroupMode::BestEffort,
            helper_path: None,
            lima_instance: "sandbox-guard".to_owned(),
        }
    }

    #[test]
    fn recursive_copy_target_is_the_workspace_consumed_by_bubblewrap() {
        let request = request();
        let root = guest_root(&request);
        let workspace = guest_workspace(&request);

        assert_eq!(workspace, root.join("workspace"));
        assert_eq!(
            guest_workspace_copy_target(&request, &root),
            format!("sandbox-guard:{}", workspace.display())
        );
    }

    #[test]
    fn lima_guest_command_scrubs_the_bwrap_launcher_environment_on_both_cgroup_routes() {
        // Mirror the exact guest-command assembly in MacosLimaRunner::{plan,run}; plan() itself
        // needs limactl on PATH and is exercised end-to-end by the release Linux live probe.
        let request = request();
        let bwrap_args = guest_bwrap_args(
            &request,
            &guest_workspace(&request),
            &guest_root(&request),
            &guest_helper_path(&request),
        );

        let disabled = guest_bwrap_command(bwrap_args.clone());
        let disabled_strings: Vec<_> = disabled
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            &disabled_strings[..3],
            &["/usr/bin/env", "-i", "/usr/bin/bwrap"]
        );
        assert!(
            !disabled_strings
                .iter()
                .any(|value| value.starts_with("PATH=")),
            "guest launcher must inherit an empty environment"
        );

        let enabled = wrap_guest_cgroup(&request, bwrap_args);
        let enabled_strings: Vec<_> = enabled
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(enabled_strings[0], "systemd-run");
        let boundary = enabled_strings
            .windows(3)
            .position(|window| window == ["/usr/bin/env", "-i", "/usr/bin/bwrap"])
            .expect("guest cgroup route installs env -i before bwrap");
        assert_eq!(enabled_strings[boundary], "/usr/bin/env");
    }

    #[test]
    fn main_lima_transport_allocates_a_tty_only_for_interactive_runs() {
        let mut request = request();
        assert_eq!(lima_main_tty_arg(&request), "--tty=false");

        request.interactive = true;
        assert_eq!(lima_main_tty_arg(&request), "--tty=true");
    }
}
