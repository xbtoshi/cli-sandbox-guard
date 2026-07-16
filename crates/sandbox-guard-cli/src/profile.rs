use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sandbox_guard_core::{BUILTIN_VENDOR_PROFILE_NAMES, VendorProfile, builtin_vendor_profile};
use serde::Serialize;

const PROFILE_LIST_SCHEMA_VERSION: u32 = 1;
const PROFILE_LINT_SCHEMA_VERSION: u32 = 1;
const PROFILE_EXPLAIN_SCHEMA_VERSION: u32 = 1;
const MAX_LINT_PROFILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Args)]
pub(super) struct ProfileArgs {
    #[command(subcommand)]
    command: ProfileCommand,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// List compiled trusted vendor profiles.
    List(ProfileListArgs),
    /// Show every field in one compiled trusted vendor profile.
    Show(ProfileShowArgs),
    /// Parse and validate an external profile without trusting or enabling it.
    Lint(ProfileLintArgs),
    /// Explain how one compiled profile maps to Guard trust boundaries.
    Explain(ProfileExplainArgs),
}

#[derive(Debug, Args)]
struct ProfileListArgs {
    /// Emit a versioned machine-readable registry report.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProfileShowArgs {
    /// Exact built-in profile name.
    name: String,

    /// Emit the profile as JSON instead of TOML.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProfileLintArgs {
    /// TOML profile to validate. Linting never installs or enables it.
    file: PathBuf,

    /// Emit a versioned machine-readable lint report.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProfileExplainArgs {
    /// Exact built-in profile name.
    name: String,

    /// Emit a versioned machine-readable explanation report.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileListReport {
    schema: u32,
    profiles: Vec<ProfileSummary>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileSummary {
    name: String,
    source: &'static str,
    profile_schema: u32,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileLintReport {
    schema: u32,
    valid: bool,
    source: &'static str,
    trusted: bool,
    executable: bool,
    profile_name: String,
    profile_schema: u32,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileExplainReport {
    schema: u32,
    profile_name: String,
    source: &'static str,
    runtime_consumed: bool,
    sections: Vec<ProfileExplanation>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileExplanation {
    fields: &'static str,
    trust: &'static str,
    effect: &'static str,
}

/// A successfully parsed external document that intentionally has no conversion into a trusted
/// built-in profile. Keep this wrapper private to the inspection-only CLI module.
#[derive(Debug)]
struct LintedProfile(VendorProfile);

pub(super) fn profile_command(args: ProfileArgs) -> Result<i32> {
    match args.command {
        ProfileCommand::List(args) => {
            let report = profile_list_report()?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for profile in report.profiles {
                    println!(
                        "{}\t{}\tschema={}",
                        profile.name, profile.source, profile.profile_schema
                    );
                }
            }
        }
        ProfileCommand::Show(args) => {
            let profile = resolve_builtin_profile(&args.name)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&profile)?);
            } else {
                print!("{}", toml::to_string_pretty(&profile)?);
            }
        }
        ProfileCommand::Lint(args) => {
            let linted = lint_external_profile(&args.file)?;
            let report = lint_report(linted);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "valid untrusted profile document: {} (schema {})",
                    report.profile_name, report.profile_schema
                );
                println!("linting does not install, trust, or enable this profile");
            }
        }
        ProfileCommand::Explain(args) => {
            let profile = resolve_builtin_profile(&args.name)?;
            let report = explain_report(&profile);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("profile: {} ({})", report.profile_name, report.source);
                println!(
                    "runtime source: hardcoded adapter (compiled profile metadata is not consumed yet)"
                );
                for section in report.sections {
                    println!(
                        "{}\n  trust: {}\n  effect: {}",
                        section.fields, section.trust, section.effect
                    );
                }
            }
        }
    }
    Ok(0)
}

fn lint_external_profile(path: &Path) -> Result<LintedProfile> {
    let initial = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect lint-only profile {path:?}"))?;
    if !initial.is_file() || initial.file_type().is_symlink() {
        bail!("lint input must be a regular non-symlink file");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open lint-only profile {path:?}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened lint-only profile {path:?}"))?;
    if !metadata.is_file() {
        bail!("lint input must be a regular non-symlink file");
    }
    if metadata.len() > MAX_LINT_PROFILE_BYTES {
        bail!("lint input exceeds the 1 MiB profile limit");
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_LINT_PROFILE_BYTES + 1)
        .read_to_end(&mut body)
        .context("read lint-only profile")?;
    if body.len() as u64 > MAX_LINT_PROFILE_BYTES {
        bail!("lint input grew beyond the 1 MiB profile limit while reading");
    }
    let body = std::str::from_utf8(&body).context("lint input is not UTF-8 TOML")?;
    let profile: VendorProfile =
        toml::from_str(body).map_err(|error| anyhow::anyhow!(safe_toml_error(&error)))?;
    profile.validate().context("validate lint-only profile")?;
    Ok(LintedProfile(profile))
}

fn safe_toml_error(error: &toml::de::Error) -> String {
    let escaped = error
        .message()
        .chars()
        .flat_map(char::escape_default)
        .take(512)
        .collect::<String>();
    match error.span() {
        Some(span) => format!(
            "lint-only profile TOML error near byte {}: {escaped}",
            span.start
        ),
        None => format!("lint-only profile TOML error: {escaped}"),
    }
}

fn lint_report(linted: LintedProfile) -> ProfileLintReport {
    ProfileLintReport {
        schema: PROFILE_LINT_SCHEMA_VERSION,
        valid: true,
        source: "external-file",
        trusted: false,
        executable: false,
        profile_name: linted.0.name,
        profile_schema: linted.0.schema_version,
    }
}

fn explain_report(profile: &VendorProfile) -> ProfileExplainReport {
    ProfileExplainReport {
        schema: PROFILE_EXPLAIN_SCHEMA_VERSION,
        profile_name: profile.name.clone(),
        source: "built-in",
        runtime_consumed: false,
        sections: vec![
            explanation(
                "tool.*",
                "compiled trusted-only",
                "defines the guest executable, mandatory arguments, preflight, and session-control arguments that the adapter must reject from passthrough",
            ),
            explanation(
                "egress.*",
                "compiled trusted-only; future policy may only remove access",
                "defines controlled HTTPS destinations and whether trusted native approval is offered by default",
            ),
            explanation(
                "credentials.*",
                "compiled trusted-only",
                "defines host auth location, private sandbox environment names, provider indirection, refresh freshness, and host-auth environment scrubbing; it contains no credential value",
            ),
            explanation(
                "sessions.*",
                "compiled trusted-only; future policy may lower quotas",
                "defines the only writable guest home mount plus the validated snapshot layout and limits",
            ),
            explanation(
                "terminal.* and clipboard.*",
                "compiled defaults; future policy may disable optional capabilities",
                "describes trusted PTY behavior and explicit user-triggered clipboard image import",
            ),
            explanation(
                "seccomp.*",
                "descriptive compatibility assertion only",
                "records workload expectations for Guard's fixed seccomp filter and cannot change that filter",
            ),
        ],
    }
}

fn explanation(
    fields: &'static str,
    trust: &'static str,
    effect: &'static str,
) -> ProfileExplanation {
    ProfileExplanation {
        fields,
        trust,
        effect,
    }
}

fn profile_list_report() -> Result<ProfileListReport> {
    let mut profiles = Vec::with_capacity(BUILTIN_VENDOR_PROFILE_NAMES.len());
    for name in BUILTIN_VENDOR_PROFILE_NAMES {
        let profile = resolve_builtin_profile(name)?;
        profiles.push(ProfileSummary {
            name: profile.name,
            source: "built-in",
            profile_schema: profile.schema_version,
        });
    }
    Ok(ProfileListReport {
        schema: PROFILE_LIST_SCHEMA_VERSION,
        profiles,
    })
}

fn resolve_builtin_profile(name: &str) -> Result<VendorProfile> {
    let Some(profile) = builtin_vendor_profile(name) else {
        bail!(
            "unknown built-in profile {name:?}; available profiles: {}",
            BUILTIN_VENDOR_PROFILE_NAMES.join(", ")
        );
    };
    profile
        .validate()
        .with_context(|| format!("compiled built-in profile {name:?} is invalid"))?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    use clap::Parser;

    use super::*;
    use crate::{Cli, Command};

    #[test]
    fn profile_list_report_is_stable_and_compiled_only() {
        let report = profile_list_report().unwrap();
        assert_eq!(report.schema, 1);
        assert_eq!(
            report.profiles,
            [ProfileSummary {
                name: "grok".to_owned(),
                source: "built-in",
                profile_schema: 1,
            }]
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema"], 1);
        assert_eq!(json["profiles"][0]["source"], "built-in");
    }

    #[test]
    fn profile_show_serializes_the_full_validated_profile() {
        let profile = resolve_builtin_profile("grok").unwrap();
        let json = serde_json::to_string_pretty(&profile).unwrap();
        let from_json: VendorProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json, profile);
        let toml = toml::to_string_pretty(&profile).unwrap();
        let from_toml: VendorProfile = toml::from_str(&toml).unwrap();
        assert_eq!(from_toml, profile);
        assert!(resolve_builtin_profile("../grok").is_err());
    }

    #[test]
    fn clap_accepts_only_the_read_only_profile_subcommands() {
        for arguments in [
            &["guard", "profile", "list", "--json"][..],
            &["guard", "profile", "show", "grok", "--json"][..],
            &["guard", "profile", "lint", "profile.toml", "--json"][..],
            &["guard", "profile", "explain", "grok", "--json"][..],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(cli.command, Command::Profile(_)));
        }
        assert!(Cli::try_parse_from(["guard", "profile", "install"]).is_err());
    }

    #[test]
    fn lint_accepts_only_bounded_regular_valid_documents() {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("valid.toml");
        fs::write(
            &valid,
            toml::to_string_pretty(&resolve_builtin_profile("grok").unwrap()).unwrap(),
        )
        .unwrap();
        let report = lint_report(lint_external_profile(&valid).unwrap());
        assert!(report.valid);
        assert!(!report.trusted);
        assert!(!report.executable);
        assert_eq!(report.source, "external-file");

        let unknown = directory.path().join("unknown.toml");
        let mut document = fs::read_to_string(&valid).unwrap();
        document.push_str("\nunexpected = true\n");
        fs::write(&unknown, document).unwrap();
        assert!(lint_external_profile(&unknown).is_err());

        let semantically_invalid = directory.path().join("schema-2.toml");
        let mut document: toml::Value =
            toml::from_str(&fs::read_to_string(&valid).unwrap()).unwrap();
        document
            .as_table_mut()
            .unwrap()
            .insert("schema_version".to_owned(), toml::Value::Integer(2));
        fs::write(&semantically_invalid, toml::to_string(&document).unwrap()).unwrap();
        assert!(
            format!(
                "{:#}",
                lint_external_profile(&semantically_invalid).unwrap_err()
            )
            .contains("unsupported vendor profile schema version 2")
        );

        let link = directory.path().join("linked.toml");
        symlink(&valid, &link).unwrap();
        assert!(lint_external_profile(&link).is_err());

        let fifo = directory.path().join("profile.fifo");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo receives a valid NUL-terminated path into the private test directory.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        assert!(lint_external_profile(&fifo).is_err());

        let oversized = directory.path().join("oversized.toml");
        fs::write(&oversized, vec![b' '; MAX_LINT_PROFILE_BYTES as usize + 1]).unwrap();
        assert!(lint_external_profile(&oversized).is_err());

        let hostile_error = directory.path().join("hostile-error.toml");
        let mut document = fs::read_to_string(&valid).unwrap();
        document.push_str("\n\"\\u001b]52;c;hostile\" = true\n");
        fs::write(&hostile_error, document).unwrap();
        let rendered = format!("{:#}", lint_external_profile(&hostile_error).unwrap_err());
        assert!(!rendered.contains('\x1b'));
        assert!(rendered.contains("\\u{1b}"));
    }

    #[test]
    fn explanation_is_versioned_and_honest_about_runtime_reachability() {
        let profile = resolve_builtin_profile("grok").unwrap();
        let report = explain_report(&profile);
        assert_eq!(report.schema, 1);
        assert_eq!(report.profile_name, "grok");
        assert_eq!(report.source, "built-in");
        assert!(!report.runtime_consumed);
        assert_eq!(report.sections.len(), 6);
        assert!(
            report
                .sections
                .iter()
                .any(|section| section.fields == "seccomp.*"
                    && section.trust.contains("descriptive"))
        );
    }
}
