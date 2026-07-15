//! Trusted policy, staging, synthetic Git, and audit primitives.
//!
//! The untrusted tool must never call into this crate. Staging and audit persistence happen on the
//! host before and after isolated execution.

mod audit;
mod change_apply;
mod export;
mod gc;
mod git;
mod policy;
mod staging;
mod tool_store;

pub use audit::{
    AuditManifest, ExcludedPath, ExclusionReason, IncludedFile, ResourceLimitRecord, RunRecord,
    StageTotals,
};
pub use change_apply::{
    ApplyAuthorization, ApplyError, ApplyReport, apply_exported_changes, decode_change_path,
};
pub use export::{
    ChangeExportManifest, ChangeKind, ChangeRecord, ExportError, ExportReport, RejectedChange,
    export_changes,
};
pub use gc::{GcError, GcReport, garbage_collect};
pub use policy::{CompiledPolicy, EffectivePolicy, PolicyError, UserPolicy};
pub use staging::{
    PersistedStage, Stage, StageError, StageOptions, default_staging_base, display_path,
    is_valid_candidate_path,
};
pub use tool_store::{
    InstalledTool, ToolInstallManifest, ToolStoreError, install_verified_tool,
    verify_installed_tool,
};
