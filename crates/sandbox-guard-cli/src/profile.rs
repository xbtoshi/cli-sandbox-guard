use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use directories::{BaseDirs, ProjectDirs};
use sandbox_guard_core::{
    BUILTIN_VENDOR_PROFILE_NAMES, InstalledProfile, ProfileOverlayDocument, VendorProfile,
    apply_profile_overlay, builtin_vendor_profile, install_verified_profile,
    list_installed_profiles, remove_installed_profile, verify_installed_profile,
};
use serde::Serialize;

const PROFILE_LIST_SCHEMA_VERSION: u32 = 2;
const PROFILE_INSTALLED_SCHEMA_VERSION: u32 = 1;
const PROFILE_INSTALL_RECEIPT_SCHEMA_VERSION: u32 = 1;
const PROFILE_REMOVE_SCHEMA_VERSION: u32 = 1;
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
    /// List compiled built-in and installed signed vendor profiles.
    List(ProfileListArgs),
    /// Show a built-in profile, or an installed signed profile with --version.
    Show(ProfileShowArgs),
    /// Verify a signed profile package and install it into the owner-private store.
    Install(ProfileInstallArgs),
    /// Remove exactly one installed signed profile name and version.
    Remove(ProfileRemoveArgs),
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
    /// Exact profile name.
    name: String,

    /// Exact installed distribution version. Selects the signed store instead of a built-in;
    /// there is no latest-version fallback.
    #[arg(long)]
    version: Option<String>,

    /// Emit the profile as JSON instead of TOML.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProfileInstallArgs {
    /// Signed profile package (the exact bytes that were signed).
    #[arg(long)]
    package: PathBuf,

    /// Detached Ed25519 signature over the package bytes, in hexadecimal.
    #[arg(long)]
    signature: PathBuf,

    /// Raw Ed25519 public key, in hexadecimal.
    #[arg(long)]
    public_key: PathBuf,

    /// SHA-256 fingerprint of the raw public key, pinning the trusted signer.
    #[arg(long)]
    signer_sha256: String,

    /// Emit a versioned machine-readable install receipt.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProfileRemoveArgs {
    /// Installed profile name.
    name: String,

    /// Exact installed distribution version to remove.
    version: String,

    /// Emit a versioned machine-readable removal report.
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
    /// Sanitized reason the installed signed store could not be enumerated, if any. Built-in
    /// entries are always listed regardless of installed-store health.
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_error: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileSummary {
    name: String,
    source: &'static str,
    profile_schema: u32,
    /// Exact distribution version. Present only for installed signed profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    /// SHA-256 fingerprint of the raw signer public key. Present only for installed profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_fingerprint_sha256: Option<String>,
    /// SHA-256 of the exact signed package bytes. Present only for installed profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    package_sha256: Option<String>,
}

/// A re-verified installed signed profile with provenance and its exact distribution version.
/// The profile body is content-only; installing it never makes it runtime-effective.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct InstalledProfileReport {
    schema: u32,
    source: &'static str,
    name: String,
    version: String,
    signer_fingerprint_sha256: String,
    package_sha256: String,
    package_bytes: u64,
    installed_at: String,
    manifest_schema: u32,
    runtime_effective: bool,
    profile: VendorProfile,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileInstallReceipt {
    schema: u32,
    source: &'static str,
    name: String,
    version: String,
    signer_fingerprint_sha256: String,
    package_sha256: String,
    package_bytes: u64,
    runtime_effective: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ProfileRemoveReport {
    schema: u32,
    name: String,
    version: String,
    removed: bool,
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
            let store = default_profile_store()?;
            let report = profile_list_report(&store)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for profile in &report.profiles {
                    match (&profile.version, &profile.signer_fingerprint_sha256) {
                        (Some(version), Some(signer)) => println!(
                            "{}\t{}\tversion={}\tschema={}\tsigner={}",
                            profile.name, profile.source, version, profile.profile_schema, signer
                        ),
                        _ => println!(
                            "{}\t{}\tschema={}",
                            profile.name, profile.source, profile.profile_schema
                        ),
                    }
                }
            }
            if let Some(error) = &report.installed_error {
                eprintln!("guard: could not list installed signed profiles: {error}");
                return Ok(1);
            }
        }
        ProfileCommand::Show(args) => {
            if let Some(version) = args.version {
                let store = default_profile_store()?;
                let report = installed_profile_report(&store, &args.name, &version)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("name: {}", report.name);
                    println!("version: {}", report.version);
                    println!("source: {}", report.source);
                    println!("signer sha256: {}", report.signer_fingerprint_sha256);
                    println!("package sha256: {}", report.package_sha256);
                    println!("installed at: {}", report.installed_at);
                    println!("runtime effective: {}", report.runtime_effective);
                    print!("{}", toml::to_string_pretty(&report.profile)?);
                }
            } else {
                let profile = resolve_builtin_profile(&args.name)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&profile)?);
                } else {
                    print!("{}", toml::to_string_pretty(&profile)?);
                }
            }
        }
        ProfileCommand::Install(args) => {
            let store = default_profile_store()?;
            let receipt = install_profile(
                &store,
                &args.package,
                &args.signature,
                &args.public_key,
                &args.signer_sha256,
            )?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            } else {
                println!(
                    "installed signed profile: {} {}",
                    receipt.name, receipt.version
                );
                println!(
                    "verified signer sha256: {}",
                    receipt.signer_fingerprint_sha256
                );
                println!("package sha256: {}", receipt.package_sha256);
                println!(
                    "runtime effective: {} (installed profiles are content-only this milestone)",
                    receipt.runtime_effective
                );
            }
        }
        ProfileCommand::Remove(args) => {
            let store = default_profile_store()?;
            let removed = remove_profile(&store, &args.name, &args.version)?;
            let report = ProfileRemoveReport {
                schema: PROFILE_REMOVE_SCHEMA_VERSION,
                name: args.name.clone(),
                version: args.version.clone(),
                removed,
            };
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if removed {
                println!(
                    "removed installed profile {} {}",
                    report.name, report.version
                );
            } else {
                println!(
                    "no installed profile {} {} to remove",
                    report.name, report.version
                );
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

/// Build the combined registry report. Built-in profiles are always listed; a corrupt or
/// unreadable installed signed store never hides them, but is surfaced as a sanitized
/// `installed_error` so the caller can fail closed on the installed portion.
fn profile_list_report(store_root: &Path) -> Result<ProfileListReport> {
    let mut profiles = Vec::with_capacity(BUILTIN_VENDOR_PROFILE_NAMES.len());
    for name in BUILTIN_VENDOR_PROFILE_NAMES {
        let profile = resolve_builtin_profile(name)?;
        profiles.push(ProfileSummary {
            name: profile.name,
            source: "built-in",
            profile_schema: profile.schema_version,
            version: None,
            signer_fingerprint_sha256: None,
            package_sha256: None,
        });
    }
    let installed_error = match list_installed_profiles(store_root) {
        Ok(installed) => {
            for profile in installed {
                profiles.push(installed_summary(&profile));
            }
            None
        }
        Err(error) => Some(sanitize_terminal(&error.to_string())),
    };
    Ok(ProfileListReport {
        schema: PROFILE_LIST_SCHEMA_VERSION,
        profiles,
        installed_error,
    })
}

fn installed_summary(installed: &InstalledProfile) -> ProfileSummary {
    ProfileSummary {
        name: installed.manifest.name.clone(),
        source: "installed-signed",
        profile_schema: installed.envelope.profile.schema_version,
        version: Some(installed.manifest.profile_version.clone()),
        signer_fingerprint_sha256: Some(installed.manifest.signer_fingerprint_sha256.clone()),
        package_sha256: Some(installed.manifest.package_sha256.clone()),
    }
}

fn default_profile_store() -> Result<PathBuf> {
    let project = ProjectDirs::from("com", "xbtoshi", "sandbox-guard")
        .ok_or_else(|| anyhow::anyhow!("could not determine the user data directory"))?;
    Ok(project.data_local_dir().join("profiles"))
}

/// Verify and install one signed profile package into the fixed owner-private store.
///
/// The store root is derived internally; tests inject an alternate root, production always uses
/// [`default_profile_store`]. All core errors are rendered terminal-safe because the package name,
/// version, and manifest content originate from signer-controlled bytes.
fn install_profile(
    store_root: &Path,
    package: &Path,
    signature: &Path,
    public_key: &Path,
    signer_sha256: &str,
) -> Result<ProfileInstallReceipt> {
    let installed =
        install_verified_profile(package, signature, public_key, signer_sha256, store_root)
            .map_err(store_error)?;
    Ok(ProfileInstallReceipt {
        schema: PROFILE_INSTALL_RECEIPT_SCHEMA_VERSION,
        source: "installed-signed",
        name: installed.manifest.name,
        version: installed.manifest.profile_version,
        signer_fingerprint_sha256: installed.manifest.signer_fingerprint_sha256,
        package_sha256: installed.manifest.package_sha256,
        package_bytes: installed.manifest.package_bytes,
        runtime_effective: false,
    })
}

/// Re-verify and render exactly one installed signed profile selected by name and exact version.
///
/// The name and version are validated as store components before a path is constructed, then the
/// core verification API re-checks bytes, signature, signer pin, manifest, and path identity.
fn installed_profile_report(
    store_root: &Path,
    name: &str,
    version: &str,
) -> Result<InstalledProfileReport> {
    validate_installed_component("profile name", name)?;
    validate_installed_component("profile version", version)?;
    let root = store_root.join(name).join(version);
    match std::fs::symlink_metadata(&root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("no installed signed profile {name:?} version {version:?}");
        }
        Err(error) => {
            return Err(error).context("inspect installed signed profile");
        }
    }
    let installed = verify_installed_profile(&root).map_err(store_error)?;
    // Defend against a component collision that resolves to a different installation than asked.
    if installed.manifest.name != name || installed.manifest.profile_version != version {
        bail!("installed profile identity did not match the requested name and version");
    }
    Ok(InstalledProfileReport {
        schema: PROFILE_INSTALLED_SCHEMA_VERSION,
        source: "installed-signed",
        name: installed.manifest.name,
        version: installed.manifest.profile_version,
        signer_fingerprint_sha256: installed.manifest.signer_fingerprint_sha256,
        package_sha256: installed.manifest.package_sha256,
        package_bytes: installed.manifest.package_bytes,
        installed_at: installed.manifest.installed_at.to_rfc3339(),
        manifest_schema: installed.manifest.schema_version,
        runtime_effective: false,
        profile: installed.envelope.profile,
    })
}

fn remove_profile(store_root: &Path, name: &str, version: &str) -> Result<bool> {
    remove_installed_profile(store_root, name, version).map_err(store_error)
}

/// Convert a signer-influenced core error into a fully sanitized, source-free anyhow error so no
/// raw control byte from an untrusted filename or TOML message can reach the terminal through the
/// top-level `{error:#}` renderer.
fn store_error(error: sandbox_guard_core::ProfileStoreError) -> anyhow::Error {
    anyhow::anyhow!("{}", sanitize_terminal(&error.to_string()))
}

/// Escape control and non-ASCII characters so untrusted profile names, versions, filenames, and
/// TOML parser messages cannot emit raw escape sequences, newlines, or bidirectional formatting
/// characters to the terminal.
fn sanitize_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_control() || !ch.is_ascii() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Reject a name or version before it is joined into a store path. This mirrors the core store
/// component grammar (leading ASCII alphanumeric, then alphanumeric/`.`/`_`/`-`, max 64) so a
/// traversal or dot-prefixed internal name can never form a lookup path.
fn validate_installed_component(label: &str, value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let first = bytes.next();
    if !first.is_some_and(|byte| byte.is_ascii_alphanumeric())
        || value.len() > 64
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("invalid {label} {:?}", sanitize_terminal(value));
    }
    Ok(())
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
    fn profile_list_report_lists_builtins_first_and_tolerates_a_missing_store() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("profiles");
        let report = profile_list_report(&store).unwrap();
        assert_eq!(report.schema, 2);
        assert_eq!(
            report.profiles,
            [ProfileSummary {
                name: "grok".to_owned(),
                source: "built-in",
                profile_schema: 1,
                version: None,
                signer_fingerprint_sha256: None,
                package_sha256: None,
            }]
        );
        assert!(report.installed_error.is_none());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema"], 2);
        assert_eq!(json["profiles"][0]["source"], "built-in");
        // Provenance fields are omitted, not null, for built-ins.
        assert!(json["profiles"][0].get("version").is_none());
        assert!(json.get("installed_error").is_none());
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
    fn clap_accepts_only_the_inspection_and_signed_store_subcommands() {
        for arguments in [
            &["guard", "profile", "list", "--json"][..],
            &["guard", "profile", "show", "grok", "--json"][..],
            &[
                "guard",
                "profile",
                "show",
                "vendor",
                "--version",
                "1.0.0",
                "--json",
            ][..],
            &[
                "guard",
                "profile",
                "install",
                "--package",
                "p.toml",
                "--signature",
                "s.hex",
                "--public-key",
                "k.hex",
                "--signer-sha256",
                "00",
            ][..],
            &["guard", "profile", "remove", "vendor", "1.0.0"][..],
            &["guard", "profile", "lint", "profile.toml", "--json"][..],
            &["guard", "profile", "explain", "grok", "--json"][..],
            &["guard", "profile", "effective", "grok", "--json"][..],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(cli.command, Command::Profile(_)));
        }
        // install requires the full signed input set; no store-path override exists.
        assert!(Cli::try_parse_from(["guard", "profile", "install"]).is_err());
        assert!(
            Cli::try_parse_from([
                "guard",
                "profile",
                "install",
                "--package",
                "p.toml",
                "--store",
                "/tmp/x",
            ])
            .is_err()
        );
        // remove requires an exact version; no name-only or --latest form is accepted.
        assert!(Cli::try_parse_from(["guard", "profile", "remove", "vendor"]).is_err());
        assert!(Cli::try_parse_from(["guard", "profile", "show", "vendor", "--version"]).is_err());
        // there is deliberately no runtime execution surface under `guard profile`.
        assert!(Cli::try_parse_from(["guard", "profile", "run", "grok"]).is_err());
        assert!(Cli::try_parse_from(["guard", "profile", "execute", "grok"]).is_err());
        assert!(
            Cli::try_parse_from(["guard", "profile", "effective", "grok", "--version", "1"])
                .is_err()
        );
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

    /// The overlay loader validates every ancestor of the overlay, so fixtures must live under
    /// an owner-controlled anchor. The system temporary directory does not qualify on CI hosts
    /// (root-owned world-writable /tmp on Linux runners), so anchor fixtures in the home
    /// directory, which the validator trusts by construction.
    fn private_home_tempdir() -> tempfile::TempDir {
        let home = BaseDirs::new().unwrap().home_dir().to_path_buf();
        tempfile::Builder::new()
            .prefix(".sandbox-guard-overlay-test-")
            .tempdir_in(home)
            .unwrap()
    }

    #[test]
    fn owner_overlay_loader_accepts_only_private_bounded_regular_files() {
        let directory = private_home_tempdir();
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
        // Anchor under the home directory so the rejection below is attributable to the
        // symlinked parent component itself, not to an untrusted temporary-directory ancestor.
        let directory = private_home_tempdir();
        let real = directory.path().join("real");
        let linked = directory.path().join("linked");
        fs::create_dir(&real).unwrap();
        symlink(&real, &linked).unwrap();
        let path = real.join("profile-overlays.toml");
        fs::write(&path, "schema_version = 1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_profile_overlay_at(&linked.join("profile-overlays.toml")).is_err());
    }

    // ---- signed profile store CLI wiring ----

    use ed25519_dalek::{Signer, SigningKey};
    use sandbox_guard_core::{SIGNED_PROFILE_ENVELOPE_SCHEMA_VERSION, SignedProfileEnvelope};
    use sha2::{Digest, Sha256};

    fn envelope_bytes(name: &str, version: &str) -> Vec<u8> {
        let mut profile = builtin_vendor_profile("grok").unwrap();
        profile.name = name.to_owned();
        let envelope = SignedProfileEnvelope {
            schema_version: SIGNED_PROFILE_ENVELOPE_SCHEMA_VERSION,
            profile_version: version.to_owned(),
            profile,
        };
        toml::to_string_pretty(&envelope).unwrap().into_bytes()
    }

    /// Write a signed package plus its detached signature and public key into `dir`, returning the
    /// three input paths and the signer fingerprint the CLI must be given.
    fn write_material(
        dir: &Path,
        key: &SigningKey,
        bytes: &[u8],
    ) -> (PathBuf, PathBuf, PathBuf, String) {
        let public_key = key.verifying_key().to_bytes();
        let signature = key.sign(bytes).to_bytes();
        let package = dir.join("package.toml");
        let signature_path = dir.join("signature.hex");
        let public_key_path = dir.join("public-key.hex");
        fs::write(&package, bytes).unwrap();
        fs::write(&signature_path, hex::encode(signature)).unwrap();
        fs::write(&public_key_path, hex::encode(public_key)).unwrap();
        (
            package,
            signature_path,
            public_key_path,
            hex::encode(Sha256::digest(public_key)),
        )
    }

    #[test]
    fn signed_store_round_trip_install_list_show_remove() {
        let store = tempfile::tempdir().unwrap();
        let store = &store.path().join("profiles");
        let input = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let bytes = envelope_bytes("vendor", "1.0.0");
        let (package, signature, public_key, fingerprint) =
            write_material(input.path(), &key, &bytes);

        let receipt =
            install_profile(store, &package, &signature, &public_key, &fingerprint).unwrap();
        assert_eq!(receipt.name, "vendor");
        assert_eq!(receipt.version, "1.0.0");
        assert_eq!(receipt.source, "installed-signed");
        assert!(!receipt.runtime_effective);
        assert_eq!(receipt.signer_fingerprint_sha256, fingerprint);
        assert_eq!(receipt.package_sha256, hex::encode(Sha256::digest(&bytes)));

        let report = profile_list_report(store).unwrap();
        assert!(report.installed_error.is_none());
        let builtin = report
            .profiles
            .iter()
            .find(|p| p.source == "built-in")
            .unwrap();
        assert_eq!(builtin.name, "grok");
        let installed = report
            .profiles
            .iter()
            .find(|p| p.source == "installed-signed")
            .unwrap();
        assert_eq!(installed.name, "vendor");
        assert_eq!(installed.version.as_deref(), Some("1.0.0"));
        assert_eq!(
            installed.signer_fingerprint_sha256.as_deref(),
            Some(fingerprint.as_str())
        );
        assert_eq!(
            installed.package_sha256.as_deref(),
            Some(hex::encode(Sha256::digest(&bytes)).as_str())
        );

        let shown = installed_profile_report(store, "vendor", "1.0.0").unwrap();
        assert_eq!(shown.schema, PROFILE_INSTALLED_SCHEMA_VERSION);
        assert_eq!(shown.source, "installed-signed");
        assert_eq!(shown.name, "vendor");
        assert_eq!(shown.version, "1.0.0");
        assert!(!shown.runtime_effective);
        assert_eq!(shown.profile.name, "vendor");
        // JSON provenance shape carries no credential values, only public fingerprints/hashes.
        let json = serde_json::to_value(&shown).unwrap();
        assert_eq!(json["source"], "installed-signed");
        assert_eq!(json["runtime_effective"], false);
        assert_eq!(json["signer_fingerprint_sha256"], fingerprint);

        assert!(remove_profile(store, "vendor", "1.0.0").unwrap());
        assert!(!remove_profile(store, "vendor", "1.0.0").unwrap());
        assert!(installed_profile_report(store, "vendor", "1.0.0").is_err());
        let after = profile_list_report(store).unwrap();
        assert!(after.profiles.iter().all(|p| p.source == "built-in"));
    }

    #[test]
    fn install_rejects_wrong_signer_tamper_and_builtin_shadow_without_publishing() {
        let store = tempfile::tempdir().unwrap();
        let store = &store.path().join("profiles");
        let input = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        let bytes = envelope_bytes("vendor", "2.0.0");
        let (package, signature, public_key, fingerprint) =
            write_material(input.path(), &key, &bytes);

        // Wrong pinned signer fingerprint.
        let wrong = "aa".repeat(32);
        assert!(install_profile(store, &package, &signature, &public_key, &wrong).is_err());

        // Signature does not cover the tampered bytes.
        let tampered = input.path().join("tampered.toml");
        let mut mutated = bytes.clone();
        let index = mutated.iter().position(|b| *b == b'v').unwrap();
        mutated[index] = b'V';
        fs::write(&tampered, &mutated).unwrap();
        assert!(install_profile(store, &tampered, &signature, &public_key, &fingerprint).is_err());

        // A signed package whose profile name shadows a built-in is refused.
        let shadow_input = tempfile::tempdir().unwrap();
        let shadow_bytes = envelope_bytes("grok", "2.0.0");
        let (s_pkg, s_sig, s_key, s_fp) = write_material(shadow_input.path(), &key, &shadow_bytes);
        assert!(install_profile(store, &s_pkg, &s_sig, &s_key, &s_fp).is_err());

        // Nothing partially published: only built-ins remain listable.
        let report = profile_list_report(store).unwrap();
        assert!(report.profiles.iter().all(|p| p.source == "built-in"));
        assert_eq!(
            report.installed_error, None,
            "unexpected installed listing failure"
        );
    }

    #[test]
    fn installed_show_and_list_fail_closed_after_stored_tamper_but_builtins_survive() {
        let store = tempfile::tempdir().unwrap();
        let store = &store.path().join("profiles");
        let input = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[11; 32]);
        let bytes = envelope_bytes("vendor", "3.0.0");
        let (package, signature, public_key, fingerprint) =
            write_material(input.path(), &key, &bytes);
        install_profile(store, &package, &signature, &public_key, &fingerprint).unwrap();

        // Corrupt the stored package bytes in place.
        let stored = store
            .join("vendor")
            .join("3.0.0")
            .join("profile-package.toml");
        let mut corrupt = fs::read(&stored).unwrap();
        corrupt[0] ^= 0xff;
        fs::write(&stored, &corrupt).unwrap();

        assert!(installed_profile_report(store, "vendor", "3.0.0").is_err());
        let report = profile_list_report(store).unwrap();
        // Built-ins are still listed even though the installed store now fails re-verification.
        assert!(
            report
                .profiles
                .iter()
                .any(|p| p.name == "grok" && p.source == "built-in")
        );
        assert!(report.installed_error.is_some());
    }

    #[test]
    fn store_error_rendering_and_component_validation_are_terminal_safe() {
        // sanitize_terminal escapes control bytes and bidirectional formatting characters and
        // never passes them through.
        let hostile = "before\u{1b}]52;c;payload\u{7}\n\u{202e}after";
        let safe = sanitize_terminal(hostile);
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\u{7}'));
        assert!(!safe.contains('\n'));
        assert!(!safe.contains('\u{202e}'));
        assert!(safe.contains("\\u{1b}"));
        assert!(safe.contains("\\u{202e}"));

        // A signed-but-malformed package produces a TOML parser error whose hostile key cannot
        // reach the terminal raw.
        let store = tempfile::tempdir().unwrap();
        let store = &store.path().join("profiles");
        let input = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[13; 32]);
        let mut bytes = b"\"\\u001b]52;c;hostile\" = true\n".to_vec();
        bytes.extend_from_slice(&envelope_bytes("vendor", "4.0.0"));
        let (package, signature, public_key, fingerprint) =
            write_material(input.path(), &key, &bytes);
        let error =
            install_profile(store, &package, &signature, &public_key, &fingerprint).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains("\\u{1b}"));

        // Traversal or control-bearing names are rejected before a path is built, with a
        // sanitized message.
        assert!(installed_profile_report(store, "../etc", "4.0.0").is_err());
        let control = installed_profile_report(store, "vendor", "bad\u{1b}version").unwrap_err();
        let control = format!("{control:#}");
        assert!(!control.contains('\u{1b}'));
    }

    #[test]
    fn builtin_inspection_is_unaffected_by_a_corrupt_store() {
        let store = tempfile::tempdir().unwrap();
        let store = &store.path().join("profiles");
        // Hand-assemble a corrupt store: an orphan dotted entry forces list to fail closed.
        fs::create_dir_all(store).unwrap();
        fs::set_permissions(store, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(store.join(".orphan")).unwrap();
        fs::set_permissions(store.join(".orphan"), fs::Permissions::from_mode(0o700)).unwrap();

        // Built-in show and the built-in portion of list still work.
        assert_eq!(resolve_builtin_profile("grok").unwrap().name, "grok");
        let report = profile_list_report(store).unwrap();
        assert!(
            report
                .profiles
                .iter()
                .any(|p| p.name == "grok" && p.source == "built-in")
        );
        assert!(report.installed_error.is_some());
    }

    #[test]
    fn no_runtime_module_consumes_the_profile_store_api() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut sources = Vec::new();
        collect_rust_sources(&manifest.join("../sandbox-guard-runner/src"), &mut sources);
        // Every CLI source except this inspection/store module is also forbidden from importing
        // the signed store. This covers the Grok adapter, generic run wiring, and future adapters
        // rather than relying on a hand-maintained list of runtime modules.
        collect_rust_sources(&manifest.join("src"), &mut sources);
        sources.retain(|source| source != &manifest.join("src/profile.rs"));

        let forbidden = [
            "profile_store",
            "install_verified_profile",
            "list_installed_profiles",
            "remove_installed_profile",
            "verify_installed_profile",
            "InstalledProfile",
            "ProfileInstallManifest",
        ];
        for source in sources {
            let text = fs::read_to_string(&source).unwrap();
            for needle in forbidden {
                assert!(
                    !text.contains(needle),
                    "runtime source {source:?} references profile-store symbol {needle:?}"
                );
            }
        }
    }

    fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
}
