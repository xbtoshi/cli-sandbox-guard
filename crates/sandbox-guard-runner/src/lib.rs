//! Platform execution backends.
//!
//! Both backends run against a disposable staged workspace. Network access is denied by default;
//! unrestricted networking is deliberately noisy and is recorded in the audit manifest.

mod linux;
mod macos;

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use linux::LinuxBwrapRunner;
pub use macos::MacosLimaRunner;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    Auto,
    LinuxBwrap,
    MacosLima,
}

impl BackendKind {
    pub fn resolve(self) -> Result<Self, RunnerError> {
        match self {
            Self::Auto if cfg!(target_os = "linux") => Ok(Self::LinuxBwrap),
            Self::Auto if cfg!(target_os = "macos") => Ok(Self::MacosLima),
            Self::Auto => Err(RunnerError::UnsupportedPlatform(
                std::env::consts::OS.to_owned(),
            )),
            explicit => Ok(explicit),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    Denied,
    Unrestricted,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Unrestricted => "unrestricted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub command: OsString,
    pub args: Vec<OsString>,
    /// On Linux this is a host directory mounted read-only at `/opt/sandbox-guard/tool`.
    /// On macOS this is an absolute directory already installed inside the managed Lima guest.
    pub tool_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub workspace: PathBuf,
    pub run_id: String,
    pub tool: ToolSpec,
    pub network: NetworkMode,
    pub forwarded_env: Vec<(String, String)>,
    pub lima_instance: String,
}

#[derive(Debug)]
pub struct RunOutcome {
    pub backend: BackendKind,
    pub status: ExitStatus,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CommandPlan {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub redacted_args: BTreeSet<usize>,
    pub warnings: Vec<String>,
}

impl CommandPlan {
    pub fn rendered(&self) -> String {
        let mut values = Vec::with_capacity(self.args.len() + 1);
        values.push(render_os(self.program.as_os_str()));
        for (index, value) in self.args.iter().enumerate() {
            if self.redacted_args.contains(&index) {
                values.push("<redacted>".to_owned());
            } else {
                values.push(render_os(value));
            }
        }
        values.join(" ")
    }
}

pub fn plan(request: &RunRequest, backend: BackendKind) -> Result<CommandPlan, RunnerError> {
    validate_request(request)?;
    match backend.resolve()? {
        BackendKind::LinuxBwrap => LinuxBwrapRunner::plan(request),
        BackendKind::MacosLima => MacosLimaRunner::plan(request),
        BackendKind::Auto => unreachable!("auto backend must resolve"),
    }
}

pub fn run(request: &RunRequest, backend: BackendKind) -> Result<RunOutcome, RunnerError> {
    validate_request(request)?;
    match backend.resolve()? {
        BackendKind::LinuxBwrap => LinuxBwrapRunner::run(request),
        BackendKind::MacosLima => MacosLimaRunner::run(request),
        BackendKind::Auto => unreachable!("auto backend must resolve"),
    }
}

fn validate_request(request: &RunRequest) -> Result<(), RunnerError> {
    if !request.workspace.is_dir() {
        return Err(RunnerError::WorkspaceMissing(request.workspace.clone()));
    }
    if request.tool.command.is_empty() {
        return Err(RunnerError::EmptyToolCommand);
    }
    if let Some(root) = &request.tool.tool_root
        && !root.is_absolute()
    {
        return Err(RunnerError::InvalidToolRoot(root.clone()));
    }
    for (name, _) in &request.forwarded_env {
        validate_forwarded_environment_name(name)?;
    }
    Ok(())
}

fn validate_forwarded_environment_name(name: &str) -> Result<(), RunnerError> {
    let valid = !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| match byte {
            b'A'..=b'Z' | b'_' => true,
            b'0'..=b'9' => index > 0,
            _ => false,
        });
    if !valid {
        return Err(RunnerError::UnsafeEnvironmentName(name.to_owned()));
    }

    let execution_controls = [
        "PATH",
        "HOME",
        "SHELL",
        "ENV",
        "BASH_ENV",
        "CDPATH",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_EXEC_PATH",
        "PYTHONHOME",
        "PYTHONPATH",
        "NODE_OPTIONS",
        "NODE_PATH",
        "GOPATH",
        "RUSTC_WRAPPER",
        "RUSTFLAGS",
    ];
    let unsafe_prefixes = [
        "GIT_",
        "LD_",
        "DYLD_",
        "NODE_",
        "PYTHON",
        "PERL5",
        "RUBY",
        "JAVA_",
        "JDK_JAVA_",
        "LUA_",
    ];
    if execution_controls.contains(&name)
        || unsafe_prefixes
            .iter()
            .any(|prefix| name.starts_with(prefix))
    {
        return Err(RunnerError::UnsafeEnvironmentName(name.to_owned()));
    }
    Ok(())
}

fn render_os(value: &OsStr) -> String {
    let lossy = value.to_string_lossy();
    if lossy
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/_.,:=+@%-".contains(&byte))
    {
        lossy.into_owned()
    } else {
        format!("{:?}", lossy)
    }
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).is_ok()
}

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
    #[error("staged workspace does not exist: {0}")]
    WorkspaceMissing(PathBuf),
    #[error("tool command cannot be empty")]
    EmptyToolCommand,
    #[error("environment variable {0:?} is unsafe to forward")]
    UnsafeEnvironmentName(String),
    #[error("required executable {name} was not found: {source}")]
    DependencyMissing {
        name: &'static str,
        #[source]
        source: which::Error,
    },
    #[error("failed to resolve tool {tool:?}: {source}")]
    ToolNotFound {
        tool: OsString,
        #[source]
        source: which::Error,
    },
    #[error("tool path {tool} is outside the declared tool root {root}")]
    ToolOutsideRoot { tool: PathBuf, root: PathBuf },
    #[error("tool root must be an absolute directory: {0}")]
    InvalidToolRoot(PathBuf),
    #[error("failed to inspect {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to execute {program}: {source}")]
    Execute {
        program: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("backend setup command failed: {0}")]
    SetupFailed(String),
    #[error("managed Lima instance exposes a host filesystem mount: {0}")]
    UnsafeLimaMount(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(workspace: &Path) -> RunRequest {
        RunRequest {
            workspace: workspace.to_path_buf(),
            run_id: "00000000-0000-4000-8000-000000000000".to_owned(),
            tool: ToolSpec {
                command: OsString::from("tool"),
                args: vec![],
                tool_root: None,
            },
            network: NetworkMode::Denied,
            forwarded_env: vec![],
            lima_instance: "sandbox-guard".to_owned(),
        }
    }

    #[test]
    fn blocks_execution_control_environment_variables() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path());
        for name in [
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "GIT_CONFIG_COUNT",
            "GIT_SSH_COMMAND",
            "NODE_OPTIONS",
            "PERL5LIB",
            "RUBYOPT",
            "JAVA_TOOL_OPTIONS",
            "PATH",
        ] {
            request.forwarded_env = vec![(name.to_owned(), "attacker".to_owned())];
            assert!(
                matches!(
                    validate_request(&request),
                    Err(RunnerError::UnsafeEnvironmentName(ref rejected)) if rejected == name
                ),
                "{name} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_explicit_credential_environment_names() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path());
        request.forwarded_env = vec![
            ("OPENAI_API_KEY".to_owned(), "secret".to_owned()),
            ("GROK_TOKEN".to_owned(), "secret".to_owned()),
        ];
        validate_request(&request).unwrap();
    }

    #[test]
    fn tool_root_must_be_absolute_on_every_backend() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path());
        request.tool.tool_root = Some(PathBuf::from("relative/tool-root"));
        assert!(matches!(
            validate_request(&request),
            Err(RunnerError::InvalidToolRoot(_))
        ));
    }

    #[test]
    fn rendered_plan_never_prints_redacted_values() {
        let plan = CommandPlan {
            program: PathBuf::from("/bin/tool"),
            args: vec![
                OsString::from("--token"),
                OsString::from("top-secret-value"),
            ],
            redacted_args: BTreeSet::from([1]),
            warnings: vec![],
        };
        let rendered = plan.rendered();
        assert!(!rendered.contains("top-secret-value"));
        assert!(rendered.contains("<redacted>"));
    }
}
