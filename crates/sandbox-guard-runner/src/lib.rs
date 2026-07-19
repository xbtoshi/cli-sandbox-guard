//! Platform execution backends.
//!
//! Both backends run against a disposable staged workspace. Network access is denied by default;
//! controlled proxy egress or deliberately noisy unrestricted networking is recorded in audit.

mod approval;
mod clipboard;
mod linux;
mod macos;
mod terminal;

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use approval::{
    RememberedEgressDecision, clear_remembered_egress_decisions, forget_remembered_egress_decision,
    list_remembered_egress_decisions,
};
pub use linux::{LinuxBwrapRunner, linux_cgroup_probe_available, linux_namespace_probe_available};
pub use macos::MacosLimaRunner;
pub use sandbox_guard_helper::ResourceLimits;

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
    Controlled,
    Unrestricted,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Controlled => "controlled",
            Self::Unrestricted => "unrestricted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CgroupMode {
    Required,
    BestEffort,
    Disabled,
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
pub struct ProcessSpec {
    pub command: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone)]
pub struct WritableHomeState {
    /// Private Guard-owned directory on the host (or copied into the Lima guest runtime).
    pub host_source: PathBuf,
    /// Narrow writable mount target inside the synthetic sandbox home.
    pub guest_target: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractiveUx {
    /// Enable the tool's mouse-reporting modes until the user enters host selection mode.
    pub mouse_reporting_default: bool,
    /// Allow an explicit Ctrl+V to import one sanitized host clipboard image.
    pub clipboard_image_import: bool,
}

impl Default for InteractiveUx {
    fn default() -> Self {
        Self {
            mouse_reporting_default: true,
            clipboard_image_import: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub workspace: PathBuf,
    pub run_id: String,
    pub tool: ToolSpec,
    /// Optional setup command executed under the same isolation and limits before the tool.
    pub preflight: Option<ProcessSpec>,
    /// Allocate an interactive terminal for backends whose transport requires an explicit PTY.
    pub interactive: bool,
    /// Convenience capabilities; terminal boundary filtering remains unconditional.
    pub interactive_ux: InteractiveUx,
    pub network: NetworkMode,
    pub allowed_egress_hosts: Vec<String>,
    /// Ask through a trusted host-native dialog for exact HTTPS destinations not pre-allowed.
    pub interactive_egress_approval: bool,
    /// Private host-side file used for remembered exact-host allow and deny choices.
    pub egress_decision_store: Option<PathBuf>,
    /// Guard-owned writable state exposed at an independently validated guest-home target.
    pub writable_home_state: Option<WritableHomeState>,
    pub forwarded_env: Vec<(String, String)>,
    pub resource_limits: ResourceLimits,
    pub cgroup_mode: CgroupMode,
    /// Linux host helper path or absolute helper path inside the managed Lima guest.
    pub helper_path: Option<PathBuf>,
    pub lima_instance: String,
}

#[derive(Debug)]
pub struct RunOutcome {
    pub backend: BackendKind,
    pub status: ExitStatus,
    pub warnings: Vec<String>,
    pub cgroup_enforced: bool,
    pub seccomp_enforced: bool,
    pub egress_audit: Vec<String>,
    pub egress_approvals: Vec<String>,
    pub clipboard_imports: Vec<String>,
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
    if request
        .preflight
        .as_ref()
        .is_some_and(|preflight| preflight.command.is_empty())
    {
        return Err(RunnerError::EmptyPreflightCommand);
    }
    if uuid::Uuid::parse_str(&request.run_id)
        .ok()
        .is_none_or(|run_id| run_id.to_string() != request.run_id)
    {
        return Err(RunnerError::InvalidRunId(request.run_id.clone()));
    }
    if request.lima_instance.is_empty()
        || request.lima_instance.len() > 64
        || !request
            .lima_instance
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') && index > 0
            })
    {
        return Err(RunnerError::InvalidLimaInstance(
            request.lima_instance.clone(),
        ));
    }
    let limits = request.resource_limits;
    if limits.memory_bytes == 0
        || limits.max_file_bytes == 0
        || limits.cpu_seconds == 0
        || limits.open_files < 16
        || limits.max_processes == 0
        || limits.cpu_percent == 0
    {
        return Err(RunnerError::InvalidResourceLimits);
    }
    if let Some(root) = &request.tool.tool_root
        && !root.is_absolute()
    {
        return Err(RunnerError::InvalidToolRoot(root.clone()));
    }
    if let Some(helper) = &request.helper_path
        && !helper.is_absolute()
    {
        return Err(RunnerError::InvalidHelperPath(helper.clone()));
    }
    if let Some(state) = &request.writable_home_state {
        if !state.host_source.is_absolute() {
            return Err(RunnerError::InvalidWritableState(state.host_source.clone()));
        }
        let metadata =
            fs::symlink_metadata(&state.host_source).map_err(|source| RunnerError::Inspect {
                path: state.host_source.clone(),
                source,
            })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != current_uid()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RunnerError::InvalidWritableState(state.host_source.clone()));
        }
        let host_source =
            fs::canonicalize(&state.host_source).map_err(|source| RunnerError::Inspect {
                path: state.host_source.clone(),
                source,
            })?;
        let workspace =
            fs::canonicalize(&request.workspace).map_err(|source| RunnerError::Inspect {
                path: request.workspace.clone(),
                source,
            })?;
        if path_is_within(&host_source, &workspace) || path_is_within(&workspace, &host_source) {
            return Err(RunnerError::InvalidWritableState(host_source));
        }
        validate_writable_state_guest_target(&state.guest_target)?;
    }
    match request.network {
        NetworkMode::Controlled if request.allowed_egress_hosts.is_empty() => {
            return Err(RunnerError::ControlledEgressWithoutHosts);
        }
        NetworkMode::Denied | NetworkMode::Unrestricted
            if !request.allowed_egress_hosts.is_empty() =>
        {
            return Err(RunnerError::EgressHostsWithoutControlledMode);
        }
        _ => {}
    }
    if request.interactive_egress_approval
        && (request.network != NetworkMode::Controlled || !request.interactive)
    {
        return Err(RunnerError::InvalidInteractiveEgressApproval);
    }
    if let Some(path) = &request.egress_decision_store {
        let Some(parent) = path.parent() else {
            return Err(RunnerError::InvalidEgressDecisionStore(path.clone()));
        };
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|source| RunnerError::Inspect {
                path: parent.to_path_buf(),
                source,
            })?;
        let parent = fs::canonicalize(parent).map_err(|source| RunnerError::Inspect {
            path: parent.to_path_buf(),
            source,
        })?;
        let resolved_path = parent.join(
            path.file_name()
                .ok_or_else(|| RunnerError::InvalidEgressDecisionStore(path.clone()))?,
        );
        let workspace =
            fs::canonicalize(&request.workspace).map_err(|source| RunnerError::Inspect {
                path: request.workspace.clone(),
                source,
            })?;
        if !path.is_absolute()
            || !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != current_uid()
            || parent_metadata.permissions().mode() & 0o077 != 0
            || path_is_within(&parent, &workspace)
            || path_is_within(&workspace, &parent)
            || request.writable_home_state.as_ref().is_some_and(|state| {
                fs::canonicalize(&state.host_source)
                    .is_ok_and(|state| path_is_within(&resolved_path, &state))
            })
        {
            return Err(RunnerError::InvalidEgressDecisionStore(path.clone()));
        }
        if !request.interactive_egress_approval {
            return Err(RunnerError::InvalidInteractiveEgressApproval);
        }
    } else if request.interactive_egress_approval {
        return Err(RunnerError::InvalidInteractiveEgressApproval);
    }
    for (name, _) in &request.forwarded_env {
        validate_forwarded_environment_name(name)?;
    }
    Ok(())
}

fn validate_writable_state_guest_target(target: &Path) -> Result<(), RunnerError> {
    const SYNTHETIC_HOME: &str = "/home/guard";
    const RESERVED_TARGETS: [&str; 4] = [
        "/workspace",
        clipboard::SANDBOX_INBOX,
        "/opt/sandbox-guard",
        linux::GUEST_RUNTIME,
    ];

    // Path::components intentionally erases `.` and repeated separators. Validate the raw Unix
    // syntax first, then use components only for containment of that exact accepted spelling.
    let raw = target.as_os_str().as_bytes();
    if !raw.starts_with(b"/")
        || raw.len() == 1
        || raw[1..].split(|byte| *byte == b'/').any(|component| {
            component.is_empty()
                || component == b"."
                || component == b".."
                || component.contains(&0)
        })
    {
        return Err(RunnerError::InvalidWritableStateTarget(
            target.to_path_buf(),
        ));
    }

    let mut normalized = PathBuf::from("/");
    let mut saw_root = false;
    for component in target.components() {
        match component {
            Component::RootDir if !saw_root => saw_root = true,
            Component::Normal(value) if !value.as_bytes().contains(&0) => normalized.push(value),
            _ => {
                return Err(RunnerError::InvalidWritableStateTarget(
                    target.to_path_buf(),
                ));
            }
        }
    }
    let home = Path::new(SYNTHETIC_HOME);
    if !saw_root
        || normalized == home
        || !path_is_within(&normalized, home)
        || RESERVED_TARGETS.iter().any(|reserved| {
            let reserved = Path::new(reserved);
            path_is_within(&normalized, reserved) || path_is_within(reserved, &normalized)
        })
    {
        return Err(RunnerError::InvalidWritableStateTarget(
            target.to_path_buf(),
        ));
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

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot invalidate Rust state.
    unsafe { libc::geteuid() }
}

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
    #[error("staged workspace does not exist: {0}")]
    WorkspaceMissing(PathBuf),
    #[error("tool command cannot be empty")]
    EmptyToolCommand,
    #[error("preflight command cannot be empty")]
    EmptyPreflightCommand,
    #[error("run ID must be a canonical UUID: {0:?}")]
    InvalidRunId(String),
    #[error("invalid Lima instance name: {0:?}")]
    InvalidLimaInstance(String),
    #[error("resource limits must be positive and the open-file limit must be at least 16")]
    InvalidResourceLimits,
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
    #[error("runtime helper path must be absolute: {0}")]
    InvalidHelperPath(PathBuf),
    #[error(
        "writable home state must be a private, owner-owned directory outside the workspace: {0}"
    )]
    InvalidWritableState(PathBuf),
    #[error(
        "writable home state guest target must be a normalized path strictly below /home/guard and disjoint from other sandbox mounts: {0}"
    )]
    InvalidWritableStateTarget(PathBuf),
    #[error("controlled network mode requires at least one --allow-host")]
    ControlledEgressWithoutHosts,
    #[error("--allow-host is valid only with controlled network mode")]
    EgressHostsWithoutControlledMode,
    #[error("interactive egress approval requires an interactive controlled-network run")]
    InvalidInteractiveEgressApproval,
    #[error("remembered egress decision store must be an absolute host path: {0}")]
    InvalidEgressDecisionStore(PathBuf),
    #[error("required cgroup v2 delegation through systemd-run is unavailable")]
    CgroupUnavailable,
    #[error("required fixed dependency {name} is unavailable at {path}")]
    FixedDependencyMissing { name: &'static str, path: PathBuf },
    #[error("runtime helper failed before the sandbox started: {0}")]
    HelperFailed(String),
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
    #[error("clipboard image import failed: {0}")]
    ClipboardUnavailable(String),
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
            preflight: None,
            interactive: false,
            interactive_ux: InteractiveUx::default(),
            network: NetworkMode::Denied,
            allowed_egress_hosts: vec![],
            interactive_egress_approval: false,
            egress_decision_store: None,
            writable_home_state: None,
            forwarded_env: vec![],
            resource_limits: ResourceLimits::default(),
            cgroup_mode: CgroupMode::BestEffort,
            helper_path: None,
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
    fn interactive_egress_approval_requires_an_interactive_controlled_run() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path());
        request.interactive_egress_approval = true;
        assert!(matches!(
            validate_request(&request),
            Err(RunnerError::InvalidInteractiveEgressApproval)
        ));

        request.interactive = true;
        request.network = NetworkMode::Controlled;
        request.allowed_egress_hosts = vec!["api.example.com".to_owned()];
        let decisions = tempfile::tempdir().unwrap();
        fs::set_permissions(decisions.path(), fs::Permissions::from_mode(0o700)).unwrap();
        request.egress_decision_store = Some(decisions.path().join("egress-decisions.json"));
        validate_request(&request).unwrap();
    }

    #[test]
    fn decision_store_cannot_be_inside_a_sandbox_writable_tree() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path());
        request.interactive = true;
        request.network = NetworkMode::Controlled;
        request.allowed_egress_hosts = vec!["api.example.com".to_owned()];
        request.interactive_egress_approval = true;
        request.egress_decision_store = Some(workspace.path().join("decisions.json"));
        assert!(matches!(
            validate_request(&request),
            Err(RunnerError::InvalidEgressDecisionStore(_))
        ));

        let state = tempfile::tempdir().unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        request.writable_home_state = Some(WritableHomeState {
            host_source: state.path().to_path_buf(),
            guest_target: PathBuf::from("/home/guard/.grok/sessions"),
        });
        request.egress_decision_store = Some(state.path().join("decisions.json"));
        assert!(matches!(
            validate_request(&request),
            Err(RunnerError::InvalidEgressDecisionStore(_))
        ));
    }

    #[test]
    fn writable_state_guest_target_is_independently_confined_to_synthetic_home() {
        let workspace = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut request = request(workspace.path());
        request.writable_home_state = Some(WritableHomeState {
            host_source: state.path().to_path_buf(),
            guest_target: PathBuf::from("/home/guard/.grok/sessions"),
        });
        validate_request(&request).unwrap();

        for hostile in [
            "home/guard/.grok/sessions",
            "/home/guard",
            "/home/guard/..",
            "/home/guard/../../etc",
            "/home/guard/.grok/./sessions",
            "/home/guard/.grok/sessions/",
            "/home/guard//sessions",
            "/etc/passwd",
            "/workspace",
            "/workspace/sandbox-guard-inputs",
            "/opt/sandbox-guard/tool",
            "/run/sandbox-guard/environment.json",
        ] {
            request.writable_home_state.as_mut().unwrap().guest_target = PathBuf::from(hostile);
            assert!(
                matches!(
                    validate_request(&request),
                    Err(RunnerError::InvalidWritableStateTarget(ref rejected))
                        if rejected == Path::new(hostile)
                ),
                "unsafe guest target {hostile:?} was accepted"
            );
        }
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
    fn path_shaping_identifiers_are_strictly_validated() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path());
        request.run_id = "../../host".to_owned();
        assert!(matches!(
            validate_request(&request),
            Err(RunnerError::InvalidRunId(_))
        ));

        request.run_id = "00000000-0000-4000-8000-000000000000".to_owned();
        request.lima_instance = "--debug".to_owned();
        assert!(matches!(
            validate_request(&request),
            Err(RunnerError::InvalidLimaInstance(_))
        ));
    }

    #[test]
    fn invalid_resource_limits_fail_before_backend_setup() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path());
        request.resource_limits.max_processes = 0;
        assert!(matches!(
            validate_request(&request),
            Err(RunnerError::InvalidResourceLimits)
        ));
    }

    #[test]
    fn empty_preflight_command_fails_before_backend_setup() {
        let workspace = tempfile::tempdir().unwrap();
        let mut request = request(workspace.path());
        request.preflight = Some(ProcessSpec {
            command: OsString::new(),
            args: Vec::new(),
        });
        assert!(matches!(
            validate_request(&request),
            Err(RunnerError::EmptyPreflightCommand)
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
