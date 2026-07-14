use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::linux::{
    guest_bwrap_args, guest_helper_path, network_warnings, wrap_guest_cgroup,
    write_environment_file,
};
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
            let mut command = vec![OsString::from("bwrap")];
            command.extend(bwrap_args);
            command
        } else {
            wrap_guest_cgroup(request, bwrap_args)
        };
        let mut args = vec![
            OsString::from("--tty=false"),
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
        let (use_cgroup, mut warnings) = match resolve_guest_cgroup(&limactl, request) {
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
            let mut command = vec![OsString::from("bwrap")];
            command.extend(bwrap_args);
            command
        };
        let mut shell_args = vec![
            OsString::from("--tty=false"),
            OsString::from("shell"),
            OsString::from(&request.lima_instance),
            OsString::from("--"),
        ];
        shell_args.extend(guest_command);
        let status_result = Command::new(&limactl)
            .args(&shell_args)
            .status()
            .map_err(|source| RunnerError::Execute {
                program: limactl.clone(),
                source,
            });
        let status = status_result?;
        let retrieve_result = retrieve_guest_workspace(&limactl, request, &guest_root);
        let egress_audit = read_guest_egress_audit(&limactl, request, &guest_root);
        stop_proxy(&mut proxy);
        let cleanup_result = cleanup_guest(&limactl, request, &guest_root);
        retrieve_result?;
        cleanup_result?;

        Ok(RunOutcome {
            backend: BackendKind::MacosLima,
            status,
            warnings,
            cgroup_enforced: use_cgroup,
            seccomp_enforced: true,
            egress_audit,
        })
    }
}

fn retrieve_guest_workspace(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
) -> Result<(), RunnerError> {
    let workspace_parent = request
        .workspace
        .parent()
        .ok_or_else(|| RunnerError::SetupFailed("staged workspace has no parent".to_owned()))?;
    let returned = tempfile::tempdir_in(workspace_parent)
        .map_err(|source| RunnerError::SetupFailed(source.to_string()))?;
    fs::set_permissions(returned.path(), fs::Permissions::from_mode(0o700)).map_err(|source| {
        RunnerError::Inspect {
            path: returned.path().to_path_buf(),
            source,
        }
    })?;
    let remote = format!(
        "{}:{}",
        request.lima_instance,
        guest_root.join("workspace").display()
    );
    let returned_workspace = returned.path().join("workspace");
    run_checked(
        limactl,
        [
            OsString::from("--tty=false"),
            OsString::from("copy"),
            OsString::from("--backend=rsync"),
            OsString::from("--recursive"),
            OsString::from(remote),
            returned_workspace.as_os_str().to_owned(),
        ],
        "retrieve disposable Lima workspace",
    )?;
    let metadata =
        fs::symlink_metadata(&returned_workspace).map_err(|source| RunnerError::Inspect {
            path: returned_workspace.clone(),
            source,
        })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RunnerError::SetupFailed(
            "Lima returned workspace is not a real directory".to_owned(),
        ));
    }
    let backup = workspace_parent.join(format!(".baseline-{}", request.run_id));
    fs::rename(&request.workspace, &backup).map_err(|source| RunnerError::Inspect {
        path: request.workspace.clone(),
        source,
    })?;
    if let Err(source) = fs::rename(&returned_workspace, &request.workspace) {
        let _ = fs::rename(&backup, &request.workspace);
        return Err(RunnerError::Inspect {
            path: returned_workspace,
            source,
        });
    }
    fs::remove_dir_all(&backup).map_err(|source| RunnerError::Inspect {
        path: backup,
        source,
    })?;
    Ok(())
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
    run_checked(
        limactl,
        shell_command(
            request,
            [
                OsString::from("mkdir"),
                OsString::from("-m"),
                OsString::from("700"),
                guest_root.into(),
            ],
        ),
        "create private Lima guest runtime",
    )?;
    Ok(())
}

fn copy_workspace_and_environment(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
) -> Result<(), RunnerError> {
    let copy_target = format!("{}:{}", request.lima_instance, guest_root.display());
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
    Ok(())
}

fn start_guest_proxy(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
    helper: &Path,
) -> Result<Child, RunnerError> {
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
    let mut child = Command::new(limactl)
        .args(args)
        .stdout(Stdio::null())
        .spawn()
        .map_err(|source| RunnerError::Execute {
            program: limactl.to_path_buf(),
            source,
        })?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().map_err(|source| RunnerError::Execute {
            program: limactl.to_path_buf(),
            source,
        })? {
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
            return Ok(child);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunnerError::HelperFailed(
                "Lima egress proxy did not become ready".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn stop_proxy(proxy: &mut Option<Child>) {
    if let Some(child) = proxy {
        let _ = child.kill();
        let _ = child.wait();
    }
    *proxy = None;
}

fn resolve_guest_cgroup(
    limactl: &Path,
    request: &RunRequest,
) -> Result<(bool, Vec<String>), RunnerError> {
    if request.cgroup_mode == CgroupMode::Disabled {
        return Ok((
            false,
            vec!["cgroup enforcement disabled by request".to_owned()],
        ));
    }
    let status = Command::new(limactl)
        .args(shell_command(
            request,
            [
                OsString::from("systemd-run"),
                OsString::from("--user"),
                OsString::from("--scope"),
                OsString::from("--quiet"),
                OsString::from("--collect"),
                OsString::from("--"),
                OsString::from("true"),
            ],
        ))
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
