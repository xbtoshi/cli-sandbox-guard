use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const VENDOR_PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorProfile {
    pub schema_version: u32,
    pub name: String,
    pub tool: ToolLaunchProfile,
    pub egress: EgressProfile,
    pub credentials: CredentialProfile,
    pub sessions: Option<SessionProfile>,
    pub terminal: TerminalProfile,
    pub clipboard: ClipboardProfile,
    pub seccomp: SeccompCompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLaunchProfile {
    pub command: String,
    pub guest_executable: PathBuf,
    pub forced_arguments: Vec<String>,
    pub scrollback_arguments: Vec<String>,
    pub forbidden_passthrough: Vec<ArgumentRule>,
    pub preflight: Option<CommandProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandProfile {
    pub command: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgumentRule {
    pub kind: ArgumentMatch,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentMatch {
    Exact,
    Prefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressProfile {
    pub mode: EgressMode,
    pub allowed_https_hosts: Vec<HostRule>,
    pub interactive_approval_default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    ControlledHttps,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRule {
    pub hostname: String,
    /// Whether subdomains are also trusted. Future tightening overlays may only change true to
    /// false; enabling this for an exact built-in rule would widen egress.
    pub include_subdomains: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfile {
    pub host_auth_file: PathBuf,
    pub value_environment: String,
    pub provider_command_environment: String,
    pub provider_command: String,
    pub minimum_validity_minutes: u64,
    pub max_auth_file_bytes: u64,
    pub scrubbed_host_environment: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionProfile {
    pub guest_mount_path: PathBuf,
    pub workspace_key: String,
    pub index_file: String,
    pub prompt_history_file: String,
    pub max_total_bytes: u64,
    pub max_files: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalProfile {
    pub mouse_reporting_default: bool,
    pub native_scrollback_opt_in: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardProfile {
    pub image_import: bool,
}

/// Descriptive compatibility assertions for the fixed Guard seccomp policy.
///
/// Version 1 profiles cannot modify the filter. This value is a reviewed workload expectation,
/// not a switch consumed by the runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompCompatibility {
    pub clone3_enosys_shim_expected: bool,
}

impl VendorProfile {
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != VENDOR_PROFILE_SCHEMA_VERSION {
            return Err(ProfileError::UnsupportedSchema(self.schema_version));
        }
        validate_component("name", &self.name)?;
        validate_component("tool.command", &self.tool.command)?;
        validate_guest_path(
            "tool.guest_executable",
            &self.tool.guest_executable,
            Path::new("/opt/sandbox-guard/tools"),
        )?;
        validate_arguments("tool.forced_arguments", &self.tool.forced_arguments, true)?;
        validate_arguments(
            "tool.scrollback_arguments",
            &self.tool.scrollback_arguments,
            true,
        )?;
        if self.sessions.is_some() && self.tool.forbidden_passthrough.is_empty() {
            return invalid(
                "tool.forbidden_passthrough",
                "managed sessions require at least one forbidden passthrough rule",
            );
        }
        for rule in &self.tool.forbidden_passthrough {
            if rule.value.is_empty() || !rule.value.starts_with('-') {
                return invalid(
                    "tool.forbidden_passthrough.value",
                    "rules must be non-empty option strings",
                );
            }
        }
        if let Some(preflight) = &self.tool.preflight {
            validate_component("tool.preflight.command", &preflight.command)?;
            validate_arguments("tool.preflight.arguments", &preflight.arguments, false)?;
        }

        if self.egress.allowed_https_hosts.is_empty() {
            return invalid(
                "egress.allowed_https_hosts",
                "controlled HTTPS requires at least one host",
            );
        }
        let mut hosts = BTreeSet::new();
        for host in &self.egress.allowed_https_hosts {
            validate_hostname(&host.hostname)?;
            if !hosts.insert(host.clone()) {
                return invalid("egress.allowed_https_hosts", "duplicate host rule");
            }
        }

        validate_home_relative_path(
            "credentials.host_auth_file",
            &self.credentials.host_auth_file,
        )?;
        validate_environment_name(
            "credentials.value_environment",
            &self.credentials.value_environment,
        )?;
        validate_environment_name(
            "credentials.provider_command_environment",
            &self.credentials.provider_command_environment,
        )?;
        if self.credentials.value_environment == self.credentials.provider_command_environment {
            return invalid(
                "credentials.provider_command_environment",
                "credential environment names must be distinct",
            );
        }
        if self.credentials.provider_command.is_empty()
            || self.credentials.provider_command.len() > 4096
            || self.credentials.provider_command.contains('\0')
        {
            return invalid(
                "credentials.provider_command",
                "provider command must contain 1 to 4096 bytes",
            );
        }
        if self.credentials.minimum_validity_minutes == 0 {
            return invalid(
                "credentials.minimum_validity_minutes",
                "minimum validity must be non-zero",
            );
        }
        if self.credentials.max_auth_file_bytes == 0
            || self.credentials.max_auth_file_bytes > 16 * 1024 * 1024
        {
            return invalid(
                "credentials.max_auth_file_bytes",
                "auth file limit must be between 1 byte and 16 MiB",
            );
        }
        let mut scrubbed = BTreeSet::new();
        for name in &self.credentials.scrubbed_host_environment {
            validate_environment_name("credentials.scrubbed_host_environment", name)?;
            if !scrubbed.insert(name.as_str()) {
                return invalid(
                    "credentials.scrubbed_host_environment",
                    "duplicate environment name",
                );
            }
        }
        for required in [
            self.credentials.value_environment.as_str(),
            self.credentials.provider_command_environment.as_str(),
        ] {
            if !scrubbed.contains(required) {
                return invalid(
                    "credentials.scrubbed_host_environment",
                    "credential environment names must be scrubbed from host auth commands",
                );
            }
        }

        if let Some(sessions) = &self.sessions {
            validate_guest_path(
                "sessions.guest_mount_path",
                &sessions.guest_mount_path,
                Path::new("/home/guard"),
            )?;
            for (field, value) in [
                ("sessions.workspace_key", sessions.workspace_key.as_str()),
                ("sessions.index_file", sessions.index_file.as_str()),
                (
                    "sessions.prompt_history_file",
                    sessions.prompt_history_file.as_str(),
                ),
            ] {
                validate_single_component(field, value)?;
            }
            if sessions.max_total_bytes == 0 || sessions.max_total_bytes > 8 * 1024 * 1024 * 1024 {
                return invalid(
                    "sessions.max_total_bytes",
                    "session byte limit must be between 1 byte and 8 GiB",
                );
            }
            if sessions.max_files == 0 || sessions.max_files > 1_000_000 {
                return invalid(
                    "sessions.max_files",
                    "session file limit must be between 1 and 1,000,000",
                );
            }
        }
        Ok(())
    }
}

/// Return the compiled Grok profile. It is not loaded from owner- or project-controlled storage.
pub fn builtin_grok_profile() -> VendorProfile {
    VendorProfile {
        schema_version: VENDOR_PROFILE_SCHEMA_VERSION,
        name: "grok".to_owned(),
        tool: ToolLaunchProfile {
            command: "grok".to_owned(),
            guest_executable: PathBuf::from("/opt/sandbox-guard/tools/grok"),
            forced_arguments: vec![
                "--disable-web-search".to_owned(),
                "--no-memory".to_owned(),
                "--no-alt-screen".to_owned(),
            ],
            scrollback_arguments: vec!["--minimal".to_owned()],
            forbidden_passthrough: vec![
                argument_rule(ArgumentMatch::Exact, "--resume"),
                argument_rule(ArgumentMatch::Exact, "-r"),
                argument_rule(ArgumentMatch::Exact, "--continue"),
                argument_rule(ArgumentMatch::Exact, "-c"),
                argument_rule(ArgumentMatch::Prefix, "--resume="),
            ],
            preflight: Some(CommandProfile {
                command: "grok".to_owned(),
                arguments: vec!["login".to_owned()],
            }),
        },
        egress: EgressProfile {
            mode: EgressMode::ControlledHttps,
            allowed_https_hosts: vec![HostRule {
                hostname: "cli-chat-proxy.grok.com".to_owned(),
                include_subdomains: false,
            }],
            interactive_approval_default: true,
        },
        credentials: CredentialProfile {
            host_auth_file: PathBuf::from(".grok/auth.json"),
            value_environment: "GROK_SESSION_TOKEN".to_owned(),
            provider_command_environment: "GROK_AUTH_PROVIDER_COMMAND".to_owned(),
            provider_command: "printf '%s\\n' \"$GROK_SESSION_TOKEN\"".to_owned(),
            minimum_validity_minutes: 10,
            max_auth_file_bytes: 1024 * 1024,
            scrubbed_host_environment: vec![
                "XAI_API_KEY".to_owned(),
                "GROK_SESSION_TOKEN".to_owned(),
                "GROK_AUTH_PROVIDER_COMMAND".to_owned(),
                "GROK_SANDBOX".to_owned(),
            ],
        },
        sessions: Some(SessionProfile {
            guest_mount_path: PathBuf::from("/home/guard/.grok/sessions"),
            workspace_key: "%2Fworkspace".to_owned(),
            index_file: "session_search.sqlite".to_owned(),
            prompt_history_file: "prompt_history.jsonl".to_owned(),
            max_total_bytes: 512 * 1024 * 1024,
            max_files: 10_000,
        }),
        terminal: TerminalProfile {
            mouse_reporting_default: true,
            native_scrollback_opt_in: true,
        },
        clipboard: ClipboardProfile { image_import: true },
        seccomp: SeccompCompatibility {
            clone3_enosys_shim_expected: true,
        },
    }
}

fn argument_rule(kind: ArgumentMatch, value: &str) -> ArgumentRule {
    ArgumentRule {
        kind,
        value: value.to_owned(),
    }
}

fn validate_component(field: &'static str, value: &str) -> Result<(), ProfileError> {
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        invalid(field, "must be a portable ASCII component")
    } else {
        Ok(())
    }
}

fn validate_arguments(
    field: &'static str,
    values: &[String],
    require_option: bool,
) -> Result<(), ProfileError> {
    for value in values {
        if value.is_empty() || value.contains('\0') || (require_option && !value.starts_with('-')) {
            return invalid(field, "contains an invalid argument");
        }
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<(), ProfileError> {
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname != hostname.to_ascii_lowercase()
        || hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        invalid(
            "egress.allowed_https_hosts.hostname",
            "must be an exact lowercase ASCII hostname",
        )
    } else {
        Ok(())
    }
}

fn validate_environment_name(field: &'static str, value: &str) -> Result<(), ProfileError> {
    let mut bytes = value.bytes();
    let first = bytes.next();
    if !first.is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        invalid(field, "must be an uppercase portable environment name")
    } else {
        Ok(())
    }
}

fn validate_home_relative_path(field: &'static str, path: &Path) -> Result<(), ProfileError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        invalid(field, "must be a strict home-relative path")
    } else {
        Ok(())
    }
}

fn validate_guest_path(
    field: &'static str,
    path: &Path,
    required_root: &Path,
) -> Result<(), ProfileError> {
    if !path.is_absolute()
        || path == required_root
        || !path.starts_with(required_root)
        || !path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        invalid(field, "must be an absolute child of its trusted guest root")
    } else {
        Ok(())
    }
}

fn validate_single_component(field: &'static str, value: &str) -> Result<(), ProfileError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\0')
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        invalid(field, "must be one relative path component")
    } else {
        Ok(())
    }
}

fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T, ProfileError> {
    Err(ProfileError::InvalidField { field, reason })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("unsupported vendor profile schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid vendor profile field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_grok_profile_is_valid_and_toml_round_trips() {
        let profile = builtin_grok_profile();
        profile.validate().unwrap();
        let encoded = toml::to_string_pretty(&profile).unwrap();
        let decoded: VendorProfile = toml::from_str(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, profile);
        assert_eq!(toml::to_string_pretty(&decoded).unwrap(), encoded);
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_structural_level() {
        for table_path in [
            &[][..],
            &["tool"][..],
            &["tool", "preflight"][..],
            &["tool", "forbidden_passthrough", "0"][..],
            &["egress"][..],
            &["egress", "allowed_https_hosts", "0"][..],
            &["credentials"][..],
            &["sessions"][..],
            &["terminal"][..],
            &["clipboard"][..],
            &["seccomp"][..],
        ] {
            let mut value = toml::Value::try_from(builtin_grok_profile()).unwrap();
            insert_unknown(&mut value, table_path);
            let encoded = toml::to_string(&value).unwrap();
            assert!(
                toml::from_str::<VendorProfile>(&encoded).is_err(),
                "unknown field at {table_path:?} was accepted"
            );
        }
    }

    #[test]
    fn invalid_schema_missing_fields_and_unsafe_values_fail_closed() {
        let mut profile = builtin_grok_profile();
        profile.schema_version = 2;
        assert_eq!(profile.validate(), Err(ProfileError::UnsupportedSchema(2)));

        let mut value = toml::Value::try_from(builtin_grok_profile()).unwrap();
        value.as_table_mut().unwrap().remove("credentials");
        assert!(toml::from_str::<VendorProfile>(&toml::to_string(&value).unwrap()).is_err());

        let mut profile = builtin_grok_profile();
        profile.egress.allowed_https_hosts.clear();
        assert!(profile.validate().is_err());

        let mut profile = builtin_grok_profile();
        profile.credentials.host_auth_file = PathBuf::from("../auth.json");
        assert!(profile.validate().is_err());

        let mut profile = builtin_grok_profile();
        profile.tool.forced_arguments = vec!["unsafe-positional".to_owned()];
        assert!(profile.validate().is_err());

        let mut profile = builtin_grok_profile();
        profile.sessions.as_mut().unwrap().max_files = 0;
        assert!(profile.validate().is_err());
    }

    fn insert_unknown(value: &mut toml::Value, path: &[&str]) {
        let mut current = value;
        for component in path {
            current = if let Ok(index) = component.parse::<usize>() {
                &mut current.as_array_mut().unwrap()[index]
            } else {
                current.as_table_mut().unwrap().get_mut(*component).unwrap()
            };
        }
        current
            .as_table_mut()
            .unwrap()
            .insert("unexpected".to_owned(), toml::Value::Boolean(true));
    }
}
