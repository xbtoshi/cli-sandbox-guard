use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use directories::{BaseDirs, ProjectDirs};
use sandbox_guard_core::{
    BUILTIN_VENDOR_PROFILE_NAMES, ProfileOverlayDocument, VendorProfile, apply_profile_overlay,
    builtin_vendor_profile,
};
use serde::Serialize;

const PROFILE_LIST_SCHEMA_VERSION: u32 = 1;
const PROFILE_LINT_SCHEMA_VERSION: u32 = 1;
const PROFILE_EXPLAIN_SCHEMA_VERSION: u32 = 3;
const PROFILE_EFFECTIVE_SCHEMA_VERSION: u32 = 1;
const MAX_LINT_PROFILE_BYTES: u64 = 1024 * 1024;
const MAX_PROFILE_OVERLAY_BYTES: u64 = 64 * 1024;

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
    /// Show one built-in profile after applying fixed-location owner tightening.
    Effective(ProfileEffectiveArgs),
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

#[derive(Debug, Args)]
struct ProfileEffectiveArgs {
    /// Exact built-in profile name.
    name: String,

    /// Emit a versioned machine-readable effective-profile report.
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
    runtime_status: &'static str,
    runtime_consumed_sections: Vec<&'static str>,
    runtime_not_consumed_sections: Vec<&'static str>,
    overlay_path: String,
    overlay_present: bool,
    tightened_fields: Vec<String>,
    sections: Vec<ProfileExplanation>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileEffectiveReport {
    schema: u32,
    base: &'static str,
    overlay_path: String,
    overlay_present: bool,
    tightened_fields: Vec<String>,
    profile: VendorProfile,
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
            let report = effective_profile_report(&args.name)?;
            let explanation = explain_report(
                &report.profile,
                report.overlay_path,
                report.overlay_present,
                report.tightened_fields,
            );
            if args.json {
                println!("{}", serde_json::to_string_pretty(&explanation)?);
            } else {
                println!(
                    "profile: {} ({})",
                    explanation.profile_name, explanation.source
                );
                println!(
                    "owner overlay: {} ({})",
                    explanation.overlay_path,
                    if explanation.overlay_present {
                        if explanation.tightened_fields.is_empty() {
                            "present; no effective changes"
                        } else {
                            "present; tightening applied"
                        }
                    } else {
                        "absent"
                    }
                );
                println!(
                    "runtime source: compiled profile projection with seccomp compatibility kept descriptive and cross-pinned to the fixed helper filter by tests"
                );
                for section in explanation.sections {
                    println!(
                        "{}\n  trust: {}\n  effect: {}",
                        section.fields, section.trust, section.effect
                    );
                }
            }
        }
        ProfileCommand::Effective(args) => {
            let report = effective_profile_report(&args.name)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("base: {}", report.base);
                println!("overlay: {}", report.overlay_path);
                println!("overlay present: {}", report.overlay_present);
                println!(
                    "tightened fields: {}",
                    if report.tightened_fields.is_empty() {
                        "none".to_owned()
                    } else {
                        report.tightened_fields.join(", ")
                    }
                );
                print!("{}", toml::to_string_pretty(&report.profile)?);
            }
        }
    }
    Ok(0)
}

fn effective_profile_report(name: &str) -> Result<ProfileEffectiveReport> {
    let path = default_profile_overlay_path()?;
    let document = load_profile_overlay_at(&path)?;
    effective_profile_report_from(name, &path, document.as_ref())
}

/// Load one compiled profile plus the optional fixed-location owner tightening.
///
/// Runtime callers deliberately receive only the validated effective profile. Inspection-only
/// provenance remains private to this module, and no caller can select an alternate overlay path.
pub(super) fn load_effective_builtin_profile(name: &str) -> Result<VendorProfile> {
    Ok(effective_profile_report(name)?.profile)
}

fn effective_profile_report_from(
    name: &str,
    overlay_path: &Path,
    document: Option<&ProfileOverlayDocument>,
) -> Result<ProfileEffectiveReport> {
    let base = resolve_builtin_profile(name)?;
    if let Some(document) = document {
        // Revalidate at the merge boundary even when the fixed-path loader already did so; tests
        // and future trusted consumers may supply an in-memory document directly.
        document
            .validate()
            .context("validate owner profile overlays")?;
    }
    let overlay = document
        .and_then(|document| document.profiles.get(name))
        .cloned()
        .unwrap_or_default();
    let profile = apply_profile_overlay(&base, &overlay)
        .with_context(|| format!("apply owner tightening to built-in profile {name:?}"))?;
    Ok(ProfileEffectiveReport {
        schema: PROFILE_EFFECTIVE_SCHEMA_VERSION,
        base: "built-in",
        overlay_path: overlay_path.display().to_string(),
        overlay_present: document.is_some(),
        tightened_fields: tightened_fields(&base, &profile),
        profile,
    })
}

fn default_profile_overlay_path() -> Result<PathBuf> {
    let project = ProjectDirs::from("com", "xbtoshi", "sandbox-guard")
        .ok_or_else(|| anyhow::anyhow!("could not determine the user configuration directory"))?;
    Ok(project.config_dir().join("profile-overlays.toml"))
}

fn load_profile_overlay_at(path: &Path) -> Result<Option<ProfileOverlayDocument>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect owner profile overlay {path:?}"));
        }
    }
    let home = BaseDirs::new()
        .context("could not determine the user home directory")?
        .home_dir()
        .to_path_buf();
    let parent = path
        .parent()
        .context("owner profile overlay path has no parent")?;
    super::setup::validate_existing_path_components(parent, &home)
        .context("validate owner profile overlay directory")?;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open owner profile overlay {path:?}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened owner profile overlay {path:?}"))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("owner profile overlay must be a singly linked owner-only regular file");
    }
    if metadata.len() > MAX_PROFILE_OVERLAY_BYTES {
        bail!("owner profile overlay exceeds the 64 KiB limit");
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_PROFILE_OVERLAY_BYTES + 1)
        .read_to_end(&mut body)
        .context("read owner profile overlay")?;
    if body.len() as u64 > MAX_PROFILE_OVERLAY_BYTES {
        bail!("owner profile overlay grew beyond the 64 KiB limit while reading");
    }
    let body = std::str::from_utf8(&body).context("owner profile overlay is not UTF-8 TOML")?;
    let document: ProfileOverlayDocument = toml::from_str(body)
        .map_err(|error| anyhow::anyhow!(safe_toml_error("profile overlay", &error)))?;
    document
        .validate()
        .context("validate owner profile overlay")?;
    Ok(Some(document))
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the current process's effective uid.
    unsafe { libc::geteuid() }
}

fn tightened_fields(base: &VendorProfile, effective: &VendorProfile) -> Vec<String> {
    let mut fields = Vec::new();
    for rule in &base.egress.allowed_https_hosts {
        match effective
            .egress
            .allowed_https_hosts
            .iter()
            .find(|candidate| candidate.hostname == rule.hostname)
        {
            None => fields.push(format!(
                "egress.allowed_https_hosts.remove:{}",
                rule.hostname
            )),
            Some(candidate) if rule.include_subdomains && !candidate.include_subdomains => fields
                .push(format!(
                    "egress.allowed_https_hosts.exact:{}",
                    rule.hostname
                )),
            _ => {}
        }
    }
    for (field, changed) in [
        (
            "egress.interactive_approval_default",
            base.egress.interactive_approval_default
                != effective.egress.interactive_approval_default,
        ),
        (
            "clipboard.image_import",
            base.clipboard.image_import != effective.clipboard.image_import,
        ),
        (
            "terminal.mouse_reporting_default",
            base.terminal.mouse_reporting_default != effective.terminal.mouse_reporting_default,
        ),
        (
            "terminal.native_scrollback_opt_in",
            base.terminal.native_scrollback_opt_in != effective.terminal.native_scrollback_opt_in,
        ),
    ] {
        if changed {
            fields.push(field.to_owned());
        }
    }
    if let (Some(base), Some(effective)) = (&base.sessions, &effective.sessions) {
        if base.max_total_bytes != effective.max_total_bytes {
            fields.push("sessions.max_total_bytes".to_owned());
        }
        if base.max_files != effective.max_files {
            fields.push("sessions.max_files".to_owned());
        }
    }
    fields
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
    let profile: VendorProfile = toml::from_str(body)
        .map_err(|error| anyhow::anyhow!(safe_toml_error("lint-only profile", &error)))?;
    profile.validate().context("validate lint-only profile")?;
    Ok(LintedProfile(profile))
}

fn safe_toml_error(label: &str, error: &toml::de::Error) -> String {
    let escaped = error
        .message()
        .chars()
        .flat_map(char::escape_default)
        .take(512)
        .collect::<String>();
    match error.span() {
        Some(span) => format!("{label} TOML error near byte {}: {escaped}", span.start),
        None => format!("{label} TOML error: {escaped}"),
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

fn explain_report(
    profile: &VendorProfile,
    overlay_path: String,
    overlay_present: bool,
    tightened_fields: Vec<String>,
) -> ProfileExplainReport {
    ProfileExplainReport {
        schema: PROFILE_EXPLAIN_SCHEMA_VERSION,
        profile_name: profile.name.clone(),
        source: "built-in",
        runtime_status: "partial",
        runtime_consumed_sections: vec![
            "tool.command_and_arguments",
            "tool.guest_executable",
            "tool.preflight",
            "tool.forbidden_passthrough",
            "egress",
            "credentials",
            "sessions.layout_and_quotas",
            "sessions.guest_mount_path",
            "clipboard.image_import",
            "terminal.mouse_reporting_default",
            "terminal.native_scrollback_opt_in",
        ],
        runtime_not_consumed_sections: vec!["seccomp"],
        overlay_path,
        overlay_present,
        tightened_fields,
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

    use sandbox_guard_core::{PROFILE_OVERLAY_SCHEMA_VERSION, ProfileOverlay};

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
            &["guard", "profile", "effective", "grok", "--json"][..],
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
    fn explanation_is_versioned_and_honest_about_partial_runtime_reachability() {
        let profile = resolve_builtin_profile("grok").unwrap();
        let report = explain_report(
            &profile,
            "/private/profile-overlays.toml".to_owned(),
            false,
            Vec::new(),
        );
        assert_eq!(report.schema, 3);
        assert_eq!(report.profile_name, "grok");
        assert_eq!(report.source, "built-in");
        assert_eq!(report.runtime_status, "partial");
        assert!(!report.overlay_present);
        assert!(report.tightened_fields.is_empty());
        assert!(report.runtime_consumed_sections.contains(&"credentials"));
        assert!(
            report
                .runtime_consumed_sections
                .contains(&"sessions.layout_and_quotas")
        );
        assert!(
            report
                .runtime_consumed_sections
                .contains(&"tool.guest_executable")
        );
        assert!(
            report
                .runtime_consumed_sections
                .contains(&"sessions.guest_mount_path")
        );
        assert!(
            report
                .runtime_consumed_sections
                .contains(&"clipboard.image_import")
        );
        assert!(
            report
                .runtime_consumed_sections
                .contains(&"terminal.mouse_reporting_default")
        );
        assert!(
            report
                .runtime_consumed_sections
                .contains(&"terminal.native_scrollback_opt_in")
        );
        assert_eq!(report.sections.len(), 6);
        assert!(
            report
                .sections
                .iter()
                .any(|section| section.fields == "seccomp.*"
                    && section.trust.contains("descriptive"))
        );
    }

    #[test]
    fn effective_report_applies_only_declared_tightening_and_reports_exact_diffs() {
        let overlay = ProfileOverlay {
            interactive_approval: Some(false),
            clipboard_image_import: Some(false),
            mouse_reporting_default: Some(false),
            native_scrollback_opt_in: Some(false),
            max_session_total_bytes: Some(1024),
            max_session_files: Some(10),
            ..ProfileOverlay::default()
        };
        let document = ProfileOverlayDocument {
            schema_version: PROFILE_OVERLAY_SCHEMA_VERSION,
            profiles: std::collections::BTreeMap::from([("grok".to_owned(), overlay)]),
        };
        let path = Path::new("/private/profile-overlays.toml");
        let report = effective_profile_report_from("grok", path, Some(&document)).unwrap();
        assert_eq!(report.schema, 1);
        assert_eq!(report.base, "built-in");
        assert!(report.overlay_present);
        assert_eq!(report.overlay_path, path.display().to_string());
        assert_eq!(
            report.tightened_fields,
            [
                "egress.interactive_approval_default",
                "clipboard.image_import",
                "terminal.mouse_reporting_default",
                "terminal.native_scrollback_opt_in",
                "sessions.max_total_bytes",
                "sessions.max_files",
            ]
        );
        assert!(!report.profile.egress.interactive_approval_default);
        assert!(!report.profile.clipboard.image_import);
        assert!(!report.profile.terminal.mouse_reporting_default);
        assert!(!report.profile.terminal.native_scrollback_opt_in);
        assert_eq!(report.profile.sessions.as_ref().unwrap().max_files, 10);

        let identity = effective_profile_report_from("grok", path, None).unwrap();
        assert!(!identity.overlay_present);
        assert!(identity.tightened_fields.is_empty());
        assert_eq!(identity.profile, resolve_builtin_profile("grok").unwrap());
    }

    #[test]
    fn owner_overlay_loader_accepts_only_private_bounded_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("profile-overlays.toml");
        let document = ProfileOverlayDocument {
            schema_version: PROFILE_OVERLAY_SCHEMA_VERSION,
            profiles: std::collections::BTreeMap::from([(
                "grok".to_owned(),
                ProfileOverlay {
                    clipboard_image_import: Some(false),
                    ..ProfileOverlay::default()
                },
            )]),
        };
        fs::write(&valid, toml::to_string_pretty(&document).unwrap()).unwrap();
        fs::set_permissions(&valid, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_profile_overlay_at(&valid).unwrap(), Some(document));
        assert_eq!(
            load_profile_overlay_at(&directory.path().join("missing.toml")).unwrap(),
            None
        );

        let broad = directory.path().join("broad.toml");
        fs::copy(&valid, &broad).unwrap();
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_profile_overlay_at(&broad).is_err());

        let link = directory.path().join("linked.toml");
        symlink(&valid, &link).unwrap();
        assert!(load_profile_overlay_at(&link).is_err());

        let hardlink = directory.path().join("hardlink.toml");
        fs::hard_link(&valid, &hardlink).unwrap();
        assert!(load_profile_overlay_at(&valid).is_err());
        fs::remove_file(&hardlink).unwrap();
        assert!(load_profile_overlay_at(&valid).unwrap().is_some());

        let oversized = directory.path().join("oversized.toml");
        fs::write(
            &oversized,
            vec![b' '; MAX_PROFILE_OVERLAY_BYTES as usize + 1],
        )
        .unwrap();
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_profile_overlay_at(&oversized).is_err());

        let fifo = directory.path().join("overlay.fifo");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo receives a valid NUL-terminated path into the private test directory.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        assert!(load_profile_overlay_at(&fifo).is_err());

        let non_utf8 = directory.path().join("non-utf8.toml");
        fs::write(&non_utf8, [0xff]).unwrap();
        fs::set_permissions(&non_utf8, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_profile_overlay_at(&non_utf8).is_err());
    }

    #[test]
    fn owner_overlay_loader_rejects_a_symlinked_configuration_parent() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        let linked = directory.path().join("linked");
        fs::create_dir(&real).unwrap();
        symlink(&real, &linked).unwrap();
        let path = real.join("profile-overlays.toml");
        fs::write(&path, "schema_version = 1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_profile_overlay_at(&linked.join("profile-overlays.toml")).is_err());
    }
}
