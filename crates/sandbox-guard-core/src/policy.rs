use std::fs;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAX_FILES: u64 = 100_000;

/// Rules that cannot be removed by a user policy.
pub const BUILTIN_DENY_RULES: &[&str] = &[
    ".git",
    ".git/**",
    "**/.git",
    "**/.git/**",
    ".ccb",
    ".ccb/**",
    "**/.ccb",
    "**/.ccb/**",
    ".env*",
    "**/.env*",
    ".dev.vars*",
    "**/.dev.vars*",
    "id_rsa*",
    "**/id_rsa*",
    "id_ed25519*",
    "**/id_ed25519*",
    "id_ecdsa*",
    "**/id_ecdsa*",
    "id_dsa*",
    "**/id_dsa*",
    "credentials.json",
    "**/credentials.json",
    ".ssh",
    ".ssh/**",
    "**/.ssh",
    "**/.ssh/**",
    ".aws/credentials",
    "**/.aws/credentials",
];

#[derive(Debug, Clone, Serialize)]
pub struct EffectivePolicy {
    pub schema_version: u32,
    pub deny: Vec<String>,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: u64,
    pub reject_symlinks: bool,
    pub reject_special_files: bool,
    pub reject_multiple_hard_links: bool,
    pub reject_cross_filesystem: bool,
}

impl Default for EffectivePolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            deny: BUILTIN_DENY_RULES
                .iter()
                .map(|rule| (*rule).to_owned())
                .collect(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_files: DEFAULT_MAX_FILES,
            reject_symlinks: true,
            reject_special_files: true,
            reject_multiple_hard_links: true,
            reject_cross_filesystem: true,
        }
    }
}

/// User policy is intentionally additive. Limits may only be lowered from the built-in ceilings.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserPolicy {
    pub schema_version: Option<u32>,
    pub deny: Vec<String>,
    pub max_file_bytes: Option<u64>,
    pub max_total_bytes: Option<u64>,
    pub max_files: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    effective: EffectivePolicy,
    matcher: GlobSet,
    hash: String,
}

impl CompiledPolicy {
    pub fn builtin() -> Result<Self, PolicyError> {
        Self::compile(EffectivePolicy::default())
    }

    pub fn load(path: Option<&Path>) -> Result<Self, PolicyError> {
        let mut effective = EffectivePolicy::default();

        if let Some(path) = path {
            let body = fs::read_to_string(path).map_err(|source| PolicyError::Read {
                path: path.to_path_buf(),
                source,
            })?;
            let user: UserPolicy = toml::from_str(&body).map_err(|source| PolicyError::Parse {
                path: path.to_path_buf(),
                source,
            })?;

            if let Some(version) = user.schema_version
                && version != 1
            {
                return Err(PolicyError::UnsupportedSchema(version));
            }

            effective.deny.extend(user.deny);
            if let Some(value) = user.max_file_bytes {
                effective.max_file_bytes = effective.max_file_bytes.min(value);
            }
            if let Some(value) = user.max_total_bytes {
                effective.max_total_bytes = effective.max_total_bytes.min(value);
            }
            if let Some(value) = user.max_files {
                effective.max_files = effective.max_files.min(value);
            }
        }

        Self::compile(effective)
    }

    fn compile(effective: EffectivePolicy) -> Result<Self, PolicyError> {
        let mut builder = GlobSetBuilder::new();
        for rule in &effective.deny {
            let glob = GlobBuilder::new(rule)
                .literal_separator(true)
                .backslash_escape(false)
                .case_insensitive(true)
                .build()
                .map_err(|source| PolicyError::InvalidRule {
                    rule: rule.clone(),
                    source,
                })?;
            builder.add(glob);
        }
        let matcher = builder.build().map_err(PolicyError::Build)?;
        let canonical = serde_json::to_vec(&effective).map_err(PolicyError::Serialize)?;
        let hash = hex::encode(Sha256::digest(canonical));

        Ok(Self {
            effective,
            matcher,
            hash,
        })
    }

    pub fn denied_by(&self, relative_path: &Path) -> Option<&str> {
        self.matcher
            .matches(relative_path)
            .into_iter()
            .next()
            .map(|index| self.effective.deny[index].as_str())
    }

    /// Match the path or any of its ancestors. This prevents a denied directory such as `.ssh`
    /// from becoming traversable merely because a child path does not independently match.
    pub fn denied_by_path_or_ancestor(&self, relative_path: &Path) -> Option<&str> {
        let mut candidate = Some(relative_path);
        while let Some(path) = candidate {
            if let Some(rule) = self.denied_by(path) {
                return Some(rule);
            }
            candidate = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty());
        }
        None
    }

    pub fn effective(&self) -> &EffectivePolicy {
        &self.effective
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to read policy {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse policy {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("unsupported policy schema version {0}; supported version is 1")]
    UnsupportedSchema(u32),
    #[error("invalid deny rule {rule:?}: {source}")]
    InvalidRule {
        rule: String,
        #[source]
        source: globset::Error,
    },
    #[error("failed to build deny matcher: {0}")]
    Build(globset::Error),
    #[error("failed to serialize effective policy: {0}")]
    Serialize(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_match_nested_secrets() {
        let policy = CompiledPolicy::builtin().unwrap();
        for path in [
            ".env",
            "app/.env.production",
            "nested/.dev.vars.local",
            "keys/id_rsa.old",
            "keys/ID_ED25519",
            "config/credentials.json",
            ".ssh/config",
            "home/.aws/credentials",
            ".git/config",
        ] {
            assert!(
                policy.denied_by(Path::new(path)).is_some(),
                "{path} was unexpectedly allowed"
            );
        }
        assert!(policy.denied_by(Path::new("src/environment.rs")).is_none());
    }

    #[test]
    fn user_policy_can_only_tighten_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        fs::write(
            &path,
            r#"
                schema_version = 1
                deny = ["**/*.secret"]
                max_file_bytes = 999999999999
                max_total_bytes = 1024
                max_files = 10
            "#,
        )
        .unwrap();

        let policy = CompiledPolicy::load(Some(&path)).unwrap();
        assert_eq!(policy.effective().max_file_bytes, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(policy.effective().max_total_bytes, 1024);
        assert_eq!(policy.effective().max_files, 10);
        assert!(policy.denied_by(Path::new("nested/token.secret")).is_some());
    }
}
