use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::linux::{guest_bwrap_args, network_warnings};
use crate::{BackendKind, CommandPlan, RunOutcome, RunRequest, RunnerError};

pub struct MacosLimaRunner;

impl MacosLimaRunner {
    pub fn plan(request: &RunRequest) -> Result<CommandPlan, RunnerError> {
        let limactl = which::which("limactl").map_err(|source| RunnerError::DependencyMissing {
            name: "limactl",
            source,
        })?;
        let guest_workspace = guest_workspace(request);
        let bwrap_args = guest_bwrap_args(request, &guest_workspace);
        let mut args = vec![
            OsString::from("--tty=false"),
            OsString::from("shell"),
            OsString::from(&request.lima_instance),
            OsString::from("--"),
            OsString::from("bwrap"),
        ];
        args.extend(bwrap_args);

        let mut redacted = BTreeSet::new();
        for (index, argument) in args.iter().enumerate() {
            if request
                .forwarded_env
                .iter()
                .any(|(_, value)| argument == OsStr::new(value))
            {
                redacted.insert(index);
            }
        }

        Ok(CommandPlan {
            program: limactl,
            args,
            redacted_args: redacted,
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

        let guest_root = guest_root(request);
        run_checked(
            &limactl,
            [
                OsString::from("--tty=false"),
                OsString::from("shell"),
                OsString::from(&request.lima_instance),
                OsString::from("--"),
                OsString::from("mkdir"),
                OsString::from("-m"),
                OsString::from("700"),
                guest_root.as_os_str().to_owned(),
            ],
        )?;

        let copy_target = format!("{}:{}", request.lima_instance, guest_root.display());
        let copy_result = run_checked(
            &limactl,
            [
                OsString::from("--tty=false"),
                OsString::from("copy"),
                OsString::from("--backend=scp"),
                OsString::from("--recursive"),
                request.workspace.as_os_str().to_owned(),
                OsString::from(copy_target),
            ],
        );
        if let Err(error) = copy_result {
            let _ = cleanup_guest(&limactl, request, &guest_root);
            return Err(error);
        }

        let plan = Self::plan(request)?;
        let status_result = Command::new(&plan.program)
            .args(&plan.args)
            .status()
            .map_err(|source| RunnerError::Execute {
                program: plan.program.clone(),
                source,
            });
        let cleanup_result = cleanup_guest(&limactl, request, &guest_root);
        let status = status_result?;
        cleanup_result?;

        Ok(RunOutcome {
            backend: BackendKind::MacosLima,
            status,
            warnings: plan.warnings,
        })
    }
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

fn cleanup_guest(
    limactl: &Path,
    request: &RunRequest,
    guest_root: &Path,
) -> Result<(), RunnerError> {
    run_checked(
        limactl,
        [
            OsString::from("--tty=false"),
            OsString::from("shell"),
            OsString::from(&request.lima_instance),
            OsString::from("--"),
            OsString::from("rm"),
            OsString::from("-rf"),
            OsString::from("--"),
            guest_root.as_os_str().to_owned(),
        ],
    )?;
    Ok(())
}

fn run_checked<I>(program: &Path, args: I) -> Result<Output, RunnerError>
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
    ensure_success("prepare Lima guest", &output)?;
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
    PathBuf::from(format!("/tmp/sandbox-guard-{}", request.run_id))
}

fn guest_workspace(request: &RunRequest) -> PathBuf {
    guest_root(request).join("workspace")
}
