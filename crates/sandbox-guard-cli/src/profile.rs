use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sandbox_guard_core::{BUILTIN_VENDOR_PROFILE_NAMES, VendorProfile, builtin_vendor_profile};
use serde::Serialize;

const PROFILE_LIST_SCHEMA_VERSION: u32 = 1;

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
    }
    Ok(0)
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
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(cli.command, Command::Profile(_)));
        }
        assert!(Cli::try_parse_from(["guard", "profile", "install"]).is_err());
    }
}
