//! Bounded, read-only inspection of persisted audit manifests.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;
use uuid::Uuid;

use crate::{AuditManifest, MAX_AUDIT_MANIFEST_BYTES};

pub const MAX_AUDIT_TAIL_CANDIDATES: usize = 4096;
pub const MAX_AUDIT_TAIL_READ_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PersistedAudit {
    pub path: PathBuf,
    pub manifest: AuditManifest,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PersistedAuditSummary {
    pub run_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub included_files: u64,
    pub included_bytes: u64,
    pub excluded_paths: u64,
    pub backend: Option<String>,
    pub tool: Option<String>,
    pub exit_code: Option<i32>,
    pub success: Option<bool>,
}

impl From<&AuditManifest> for PersistedAuditSummary {
    fn from(manifest: &AuditManifest) -> Self {
        Self {
            run_id: manifest.run_id,
            created_at: manifest.created_at,
            included_files: manifest.totals.included_files,
            included_bytes: manifest.totals.included_bytes,
            excluded_paths: manifest.totals.excluded_paths,
            backend: manifest.run.as_ref().map(|run| run.backend.clone()),
            tool: manifest.run.as_ref().map(|run| run.tool.clone()),
            exit_code: manifest.run.as_ref().and_then(|run| run.exit_code),
            success: manifest.run.as_ref().map(|run| run.success),
        }
    }
}

#[derive(Debug)]
struct AuditFile {
    name: String,
    second: chrono::DateTime<chrono::Utc>,
    run_id: Uuid,
    bytes: u64,
}

/// Read the newest persisted audits. A missing audit directory is an empty history.
pub fn tail_persisted_audit_summaries(
    audit_dir: &Path,
    limit: usize,
) -> Result<Vec<PersistedAuditSummary>, AuditReadError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let Some(directory) = open_audit_directory(audit_dir)? else {
        return Ok(Vec::new());
    };
    let mut newest_seconds = BTreeMap::<chrono::DateTime<chrono::Utc>, usize>::new();
    let mut retained = 0_usize;
    scan_audit_files(audit_dir, |file| {
        let count = newest_seconds.entry(file.second).or_default();
        *count = count
            .checked_add(1)
            .ok_or(AuditReadError::TooManyTailCandidates)?;
        retained = retained
            .checked_add(1)
            .ok_or(AuditReadError::TooManyTailCandidates)?;
        while let Some((_, oldest_count)) = newest_seconds.first_key_value() {
            if retained - *oldest_count < limit {
                break;
            }
            retained -= *oldest_count;
            newest_seconds.pop_first();
        }
        Ok(())
    })?;
    let Some(cutoff) = newest_seconds.first_key_value().map(|(second, _)| *second) else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    scan_audit_files(audit_dir, |file| {
        if file.second < cutoff {
            return Ok(());
        }
        files.push(file);
        if files.len() > MAX_AUDIT_TAIL_CANDIDATES {
            return Err(AuditReadError::TooManyTailCandidates);
        }
        Ok(())
    })?;
    let total_bytes = files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or(AuditReadError::TailReadTooLarge)
    })?;
    if total_bytes > MAX_AUDIT_TAIL_READ_BYTES {
        return Err(AuditReadError::TailReadTooLarge);
    }

    let mut audits = Vec::with_capacity(files.len().min(limit));
    for file in files {
        let audit = read_audit(audit_dir, &file.name)?;
        audits.push(PersistedAuditSummary::from(&audit.manifest));
    }
    ensure_path_matches_directory(audit_dir, &directory)?;
    audits.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    audits.truncate(limit);
    Ok(audits)
}

/// Locate one exact run audit. Duplicate run identifiers fail closed.
pub fn find_persisted_audit(
    audit_dir: &Path,
    run_id: Uuid,
) -> Result<Option<PersistedAudit>, AuditReadError> {
    let Some(directory) = open_audit_directory(audit_dir)? else {
        return Ok(None);
    };
    let mut matched = None;
    scan_audit_files(audit_dir, |file| {
        if file.run_id == run_id && matched.replace(file).is_some() {
            return Err(AuditReadError::DuplicateRun);
        }
        Ok(())
    })?;
    let result = matched
        .as_ref()
        .map(|file| read_audit(audit_dir, &file.name))
        .transpose()?;
    if result
        .as_ref()
        .is_some_and(|audit| audit.manifest.run_id != run_id)
    {
        return Err(AuditReadError::IdentityMismatch);
    }
    ensure_path_matches_directory(audit_dir, &directory)?;
    Ok(result)
}

fn open_audit_directory(audit_dir: &Path) -> Result<Option<File>, AuditReadError> {
    let before = match fs::symlink_metadata(audit_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(AuditReadError::Io("inspect audit directory", source)),
    };
    if before.file_type().is_symlink() {
        return Err(AuditReadError::UnsafeStorage);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(audit_dir)
        .map_err(|source| AuditReadError::Io("open audit directory", source))?;
    let held = directory
        .metadata()
        .map_err(|source| AuditReadError::Io("inspect held audit directory", source))?;
    if !held.is_dir()
        || held.uid() != current_uid()
        || held.permissions().mode() & 0o777 != 0o700
        || held.dev() != before.dev()
        || held.ino() != before.ino()
    {
        return Err(AuditReadError::UnsafeStorage);
    }
    Ok(Some(directory))
}

fn scan_audit_files(
    audit_dir: &Path,
    mut visit: impl FnMut(AuditFile) -> Result<(), AuditReadError>,
) -> Result<(), AuditReadError> {
    for entry in fs::read_dir(audit_dir)
        .map_err(|source| AuditReadError::Io("enumerate audit directory", source))?
    {
        let entry = entry.map_err(|source| AuditReadError::Io("read audit entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| AuditReadError::UnexpectedEntry)?;
        let (second, run_id) = parse_audit_filename(&name)?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| AuditReadError::Io("inspect audit entry", source))?;
        validate_file_metadata(&metadata)?;
        visit(AuditFile {
            name,
            second,
            run_id,
            bytes: metadata.len(),
        })?;
    }
    Ok(())
}

fn parse_audit_filename(
    name: &str,
) -> Result<(chrono::DateTime<chrono::Utc>, Uuid), AuditReadError> {
    if name.len() != 58 || !name.is_ascii() || &name[16..17] != "-" || &name[53..] != ".json" {
        return Err(AuditReadError::UnexpectedEntry);
    }
    let second = chrono::NaiveDateTime::parse_from_str(&name[..16], "%Y%m%dT%H%M%SZ")
        .map_err(|_| AuditReadError::UnexpectedEntry)?
        .and_utc();
    let run_id = Uuid::parse_str(&name[17..53]).map_err(|_| AuditReadError::UnexpectedEntry)?;
    if run_id.to_string() != name[17..53]
        || second.format("%Y%m%dT%H%M%SZ").to_string() != name[..16]
    {
        return Err(AuditReadError::UnexpectedEntry);
    }
    Ok((second, run_id))
}

fn read_audit(audit_dir: &Path, name: &str) -> Result<PersistedAudit, AuditReadError> {
    let path = audit_dir.join(name);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|source| AuditReadError::Io("open audit manifest", source))?;
    let before = file
        .metadata()
        .map_err(|source| AuditReadError::Io("inspect audit manifest", source))?;
    validate_file_metadata(&before)?;

    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_AUDIT_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| AuditReadError::Io("read audit manifest", source))?;
    if bytes.len() as u64 > MAX_AUDIT_MANIFEST_BYTES {
        return Err(AuditReadError::TooLarge);
    }
    let after = file
        .metadata()
        .map_err(|source| AuditReadError::Io("reinspect audit manifest", source))?;
    validate_file_metadata(&after)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != after.len()
    {
        return Err(AuditReadError::ConcurrentMutation);
    }

    let manifest: AuditManifest = serde_json::from_slice(&bytes).map_err(AuditReadError::Parse)?;
    if manifest.schema_version != 1 {
        return Err(AuditReadError::UnsupportedSchema(manifest.schema_version));
    }
    let expected = format!(
        "{}-{}.json",
        manifest.created_at.format("%Y%m%dT%H%M%SZ"),
        manifest.run_id
    );
    if name != expected {
        return Err(AuditReadError::IdentityMismatch);
    }
    Ok(PersistedAudit { path, manifest })
}

fn validate_file_metadata(metadata: &fs::Metadata) -> Result<(), AuditReadError> {
    if !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(AuditReadError::UnsafeStorage);
    }
    if metadata.len() > MAX_AUDIT_MANIFEST_BYTES {
        return Err(AuditReadError::TooLarge);
    }
    Ok(())
}

fn ensure_path_matches_directory(path: &Path, held: &File) -> Result<(), AuditReadError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| AuditReadError::Io("reinspect audit directory", source))?;
    let held_metadata = held
        .metadata()
        .map_err(|source| AuditReadError::Io("reinspect held audit directory", source))?;
    if path_metadata.file_type().is_symlink()
        || path_metadata.dev() != held_metadata.dev()
        || path_metadata.ino() != held_metadata.ino()
    {
        return Err(AuditReadError::ConcurrentMutation);
    }
    Ok(())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[derive(Debug, Error)]
pub enum AuditReadError {
    #[error("unsafe private audit storage")]
    UnsafeStorage,
    #[error("unexpected entry in private audit storage")]
    UnexpectedEntry,
    #[error("one audit-tail query exceeds its same-second candidate bound")]
    TooManyTailCandidates,
    #[error("audit manifest exceeds its size bound")]
    TooLarge,
    #[error("audit tail query exceeds its aggregate read bound")]
    TailReadTooLarge,
    #[error("audit storage changed while it was being inspected")]
    ConcurrentMutation,
    #[error("multiple audit manifests claim the requested run")]
    DuplicateRun,
    #[error("audit filename and manifest identity do not match")]
    IdentityMismatch,
    #[error("unsupported audit schema {0}")]
    UnsupportedSchema(u32),
    #[error("invalid audit manifest: {0}")]
    Parse(serde_json::Error),
    #[error("failed to {0}: {1}")]
    Io(&'static str, std::io::Error),
}
