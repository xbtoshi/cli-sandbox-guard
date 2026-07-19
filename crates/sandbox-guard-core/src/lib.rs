//! Trusted policy, staging, synthetic Git, and audit primitives.
//!
//! The untrusted tool must never call into this crate. Staging and audit persistence happen on the
//! host before and after isolated execution.

mod audit;
mod audit_reader;
mod change_apply;
mod events;
mod export;
mod gc;
mod git;
mod policy;
mod profile;
mod profile_store;
mod signed_profile;
mod staging;
mod tool_store;

pub use audit::{
    AuditManifest, ExcludedPath, ExclusionReason, IncludedFile, MAX_AUDIT_MANIFEST_BYTES,
    ResourceLimitRecord, RunRecord, StageTotals,
};
pub use audit_reader::{
    AuditReadError, MAX_AUDIT_TAIL_CANDIDATES, MAX_AUDIT_TAIL_READ_BYTES, PersistedAudit,
    PersistedAuditSummary, find_persisted_audit, tail_persisted_audit_summaries,
};
pub use change_apply::{
    ApplyAuthorization, ApplyError, ApplyReport, apply_exported_changes, decode_change_path,
};
pub use events::{
    ApprovalEventDecision, EVENT_INDEX_SCHEMA_VERSION, EventIndex, EventKind, EventRecord,
    EventStoreError, MAX_EVENT_INDEX_BYTES, MAX_EVENT_QUERY_LIMIT, MAX_EVENTS,
    MAX_EVENTS_PER_AUDIT, append_events, events_from_audit, read_event_index, select_events,
};
pub use export::{
    ChangeExportManifest, ChangeKind, ChangeRecord, ExportError, ExportReport, RejectedChange,
    export_changes,
};
pub use gc::{GcError, GcReport, garbage_collect};
pub use policy::{CompiledPolicy, EffectivePolicy, PolicyError, UserPolicy};
pub use profile::{
    ArgumentMatch, ArgumentRule, BUILTIN_VENDOR_PROFILE_NAMES, ClipboardProfile, CommandProfile,
    CredentialProfile, EgressMode, EgressProfile, HostRule, PROFILE_OVERLAY_SCHEMA_VERSION,
    ProfileError, ProfileOverlay, ProfileOverlayDocument, SeccompCompatibility, SessionProfile,
    TerminalProfile, ToolLaunchProfile, VENDOR_PROFILE_SCHEMA_VERSION, VendorProfile,
    apply_profile_overlay, builtin_grok_profile, builtin_vendor_profile,
};
pub use profile_store::{
    InstalledProfile, MAX_INSTALLED_PROFILE_NAMES, MAX_INSTALLED_PROFILE_VERSIONS,
    PROFILE_STORE_MANIFEST_SCHEMA_VERSION, ProfileInstallManifest, ProfileStoreError,
    install_verified_profile, list_installed_profiles, remove_installed_profile,
    verify_installed_profile,
};
pub use signed_profile::{
    MAX_SIGNED_PROFILE_BYTES, SIGNED_PROFILE_ENVELOPE_SCHEMA_VERSION, SignedProfileEnvelope,
    SignedProfileError, verify_signed_profile_bytes,
};
pub use staging::{
    PersistedStage, Stage, StageError, StageOptions, default_staging_base, display_path,
    is_valid_candidate_path,
};
pub use tool_store::{
    InstalledTool, ToolInstallManifest, ToolStoreError, VerifiedToolSnapshot,
    install_verified_tool, verify_installed_tool, verify_installed_tool_snapshot,
};
