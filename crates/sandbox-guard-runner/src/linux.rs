use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{
    BackendKind, CommandPlan, NetworkMode, RunOutcome, RunRequest, RunnerError, path_is_within,
};

pub struct LinuxBwrapRunner;

impl LinuxBwrapRunner {
    pub fn plan(request: &RunRequest) -> Result<CommandPlan, RunnerError> {
        let bwrap = which::which("bwrap").map_err(|source| RunnerError::DependencyMissing {
            name: "bwrap",
            source,
        })?;
        Self::build_plan(request, bwrap)
    }

    fn build_plan(request: &RunRequest, bwrap: PathBuf) -> Result<CommandPlan, RunnerError> {
        let workspace =
            fs::canonicalize(&request.workspace).map_err(|source| RunnerError::Inspect {
                path: request.workspace.clone(),
                source,
            })?;

        let (tool_command, tool_mount) = resolve_host_tool(request)?;
        let mut args = Vec::<OsString>::new();
        let mut redacted = BTreeSet::new();

        push(&mut args, "--die-with-parent");
        push(&mut args, "--new-session");
        push(&mut args, "--unshare-user");
        push(&mut args, "--unshare-pid");
        push(&mut args, "--unshare-ipc");
        push(&mut args, "--unshare-uts");
        push(&mut args, "--unshare-cgroup");
        if request.network == NetworkMode::Denied {
            push(&mut args, "--unshare-net");
        }
        push(&mut args, "--hostname");
        push(&mut args, "sandbox-guard");
        push(&mut args, "--cap-drop");
        push(&mut args, "ALL");
        push(&mut args, "--clearenv");
        push(&mut args, "--close-fds");
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
        push(&mut args, "--dir");
        push(&mut args, "/home");
        push(&mut args, "--dir");
        push(&mut args, "/home/guard");
        push(&mut args, "--dir");
        push(&mut args, "/opt");
        push(&mut args, "--dir");
        push(&mut args, "/opt/sandbox-guard");
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
        if let Some((host, guest)) = tool_mount {
            push(&mut args, "--ro-bind");
            args.push(host.into_os_string());
            args.push(guest.into_os_string());
        }
        push(&mut args, "--bind");
        args.push(workspace.into_os_string());
        push(&mut args, "/workspace");
        push(&mut args, "--chdir");
        push(&mut args, "/workspace");
        push(&mut args, "--setenv");
        push(&mut args, "HOME");
        push(&mut args, "/home/guard");
        push(&mut args, "--setenv");
        push(&mut args, "PATH");
        push(
            &mut args,
            "/opt/sandbox-guard/tool:/usr/local/bin:/usr/bin:/bin",
        );
        push(&mut args, "--setenv");
        push(&mut args, "LANG");
        push(&mut args, "C.UTF-8");
        for (name, value) in &request.forwarded_env {
            push(&mut args, "--setenv");
            args.push(name.into());
            redacted.insert(args.len());
            args.push(value.into());
        }
        push(&mut args, "--");
        args.push(tool_command);
        args.extend(request.tool.args.iter().cloned());

        let warnings = network_warnings(request.network, "host");
        Ok(CommandPlan {
            program: bwrap,
            args,
            redacted_args: redacted,
            warnings,
        })
    }

    pub fn run(request: &RunRequest) -> Result<RunOutcome, RunnerError> {
        let plan = Self::plan(request)?;
        let status = Command::new(&plan.program)
            .args(&plan.args)
            .status()
            .map_err(|source| RunnerError::Execute {
                program: plan.program.clone(),
                source,
            })?;
        Ok(RunOutcome {
            backend: BackendKind::LinuxBwrap,
            status,
            warnings: plan.warnings,
        })
    }
}

pub(crate) fn guest_bwrap_args(request: &RunRequest, workspace: &Path) -> Vec<OsString> {
    let mut args = Vec::new();
    push(&mut args, "--die-with-parent");
    push(&mut args, "--new-session");
    push(&mut args, "--unshare-user");
    push(&mut args, "--unshare-pid");
    push(&mut args, "--unshare-ipc");
    push(&mut args, "--unshare-uts");
    push(&mut args, "--unshare-cgroup");
    if request.network == NetworkMode::Denied {
        push(&mut args, "--unshare-net");
    }
    push(&mut args, "--hostname");
    push(&mut args, "sandbox-guard");
    push(&mut args, "--cap-drop");
    push(&mut args, "ALL");
    push(&mut args, "--clearenv");
    push(&mut args, "--close-fds");
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
    push(&mut args, "--dir");
    push(&mut args, "/home");
    push(&mut args, "--dir");
    push(&mut args, "/home/guard");
    push(&mut args, "--dir");
    push(&mut args, "/opt");
    push(&mut args, "--dir");
    push(&mut args, "/opt/sandbox-guard");
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
    push(&mut args, "--bind");
    args.push(workspace.as_os_str().to_owned());
    push(&mut args, "/workspace");
    push(&mut args, "--chdir");
    push(&mut args, "/workspace");
    push(&mut args, "--setenv");
    push(&mut args, "HOME");
    push(&mut args, "/home/guard");
    push(&mut args, "--setenv");
    push(&mut args, "PATH");
    push(
        &mut args,
        "/opt/sandbox-guard/tools:/usr/local/bin:/usr/bin:/bin",
    );
    push(&mut args, "--setenv");
    push(&mut args, "LANG");
    push(&mut args, "C.UTF-8");
    for (name, value) in &request.forwarded_env {
        push(&mut args, "--setenv");
        args.push(name.into());
        args.push(value.into());
    }
    push(&mut args, "--");
    args.push(request.tool.command.clone());
    args.extend(request.tool.args.iter().cloned());
    args
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
    if mode == NetworkMode::Unrestricted {
        vec![format!(
            "UNSAFE NETWORK MODE: sharing the {boundary} network namespace exposes loopback, private and LAN services, cloud metadata (169.254.169.254), and Linux abstract UNIX sockets. Abstract sockets are outside filesystem isolation and may permit code execution in that network namespace. Development use only."
        )]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ToolSpec;

    fn request(workspace: &Path, network: NetworkMode) -> RunRequest {
        RunRequest {
            workspace: workspace.to_path_buf(),
            run_id: "00000000-0000-4000-8000-000000000000".to_owned(),
            tool: ToolSpec {
                command: OsString::from("tool"),
                args: vec![OsString::from("--version")],
                tool_root: None,
            },
            network,
            forwarded_env: vec![("GROK_TOKEN".to_owned(), "secret".to_owned())],
            lima_instance: "sandbox-guard".to_owned(),
        }
    }

    #[test]
    fn guest_plan_clears_environment_and_denies_network() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let args = guest_bwrap_args(&request(workspace, NetworkMode::Denied), workspace);
        let strings: Vec<_> = args.iter().map(|arg| arg.to_string_lossy()).collect();
        assert!(strings.iter().any(|arg| arg == "--clearenv"));
        assert!(strings.iter().any(|arg| arg == "--close-fds"));
        assert!(strings.iter().any(|arg| arg == "--unshare-net"));
        assert!(strings.iter().any(|arg| arg == "--unshare-pid"));
        assert!(strings.iter().any(|arg| arg == "--cap-drop"));
        assert!(strings.iter().any(|arg| arg == "/workspace"));
        assert!(!strings.iter().any(|arg| arg.contains("/Users/")));
    }

    #[test]
    fn unrestricted_network_is_explicit_in_plan_and_warning() {
        let workspace = Path::new("/tmp/guard-test/workspace");
        let args = guest_bwrap_args(&request(workspace, NetworkMode::Unrestricted), workspace);
        assert!(
            !args
                .iter()
                .any(|arg| arg.to_string_lossy() == "--unshare-net")
        );
        assert!(!network_warnings(NetworkMode::Unrestricted, "test").is_empty());
    }

    #[test]
    fn real_linux_plan_redacts_forwarded_values() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path(), NetworkMode::Denied);
        request.tool.command = OsString::from("/bin/echo");
        let plan = LinuxBwrapRunner::build_plan(&request, PathBuf::from("/usr/bin/bwrap")).unwrap();
        let rendered = plan.rendered();
        assert!(!rendered.contains("secret"));
        assert!(rendered.contains("<redacted>"));
    }
}
