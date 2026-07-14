//! Trusted policy, staging, synthetic Git, and audit primitives.
//!
//! The untrusted tool must never call into this crate. Staging and audit persistence happen on the
//! host before and after isolated execution.

mod audit;
mod gc;
mod git;
mod policy;
mod staging;

pub use audit::{
    AuditManifest, ExcludedPath, ExclusionReason, IncludedFile, RunRecord, StageTotals,
};
pub use gc::{GcError, GcReport, garbage_collect};
pub use policy::{CompiledPolicy, EffectivePolicy, PolicyError, UserPolicy};
pub use staging::{
    PersistedStage, Stage, StageError, StageOptions, default_staging_base, display_path,
    is_valid_candidate_path,
};
