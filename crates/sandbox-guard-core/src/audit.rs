use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::CompiledPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditManifest {
    pub schema_version: u32,
    pub run_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub source_root: String,
    pub policy_sha256: String,
    pub included: Vec<IncludedFile>,
    pub excluded: Vec<ExcludedPath>,
    pub totals: StageTotals,
    pub synthetic_git: bool,
    pub run: Option<RunRecord>,
}

impl AuditManifest {
    pub(crate) fn new(source_root: &Path, policy: &CompiledPolicy) -> Self {
        Self {
            schema_version: 1,
            run_id: Uuid::new_v4(),
            created_at: Utc::now(),
            source_root: crate::staging::display_path(source_root),
            policy_sha256: policy.hash().to_owned(),
            included: Vec::new(),
            excluded: Vec::new(),
            totals: StageTotals::default(),
            synthetic_git: false,
            run: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludedFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludedPath {
    pub path: String,
    pub reason: ExclusionReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExclusionReason {
    Policy { rule: String },
    Symlink,
    SpecialFile,
    MultipleHardLinks { links: u64 },
    CrossFilesystem,
    MissingFromWorktree,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageTotals {
    pub included_files: u64,
    pub included_bytes: u64,
    pub excluded_paths: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub backend: String,
    pub network: String,
    pub tool: String,
    pub forwarded_environment_names: Vec<String>,
    pub allowed_egress_hosts: Vec<String>,
    #[serde(default)]
    pub interactive_egress_approval: bool,
    pub egress_audit: Vec<String>,
    #[serde(default)]
    pub egress_approvals: Vec<String>,
    #[serde(default)]
    pub clipboard_imports: Vec<String>,
    pub resource_limits: ResourceLimitRecord,
    pub cgroup_enforced: bool,
    pub seccomp_enforced: bool,
    pub exit_code: Option<i32>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitRecord {
    pub memory_bytes: u64,
    pub max_file_bytes: u64,
    pub cpu_seconds: u64,
    pub open_files: u64,
    pub max_processes: u64,
    pub cpu_percent: u64,
}
