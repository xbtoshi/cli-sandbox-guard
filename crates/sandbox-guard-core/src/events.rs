//! Bounded, owner-private observational event index.
//!
//! Events are a privacy-reduced derivative of an already-persisted run audit. A failure in this
//! module must be handled observationally by callers: it must never alter sandbox enforcement or
//! the tool's exit status.
//!
//! The event directory is held and identity-checked, but child opens and publication are
//! path-based. A same-UID process able to swap that directory during an operation is outside the
//! threat model; the final identity check prevents a raced operation from reporting success.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::AuditManifest;

pub const EVENT_INDEX_SCHEMA_VERSION: u32 = 1;
pub const MAX_EVENTS: usize = 4096;
pub const MAX_EVENTS_PER_AUDIT: usize = 512;
pub const MAX_EVENT_QUERY_LIMIT: usize = 1000;
pub const MAX_EVENT_INDEX_BYTES: u64 = 4 * 1024 * 1024;
const INDEX_FILE: &str = "events.json";
const LOCK_FILE: &str = ".lock";
const MAX_AUDIT_LINE_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventIndex {
    pub schema_version: u32,
    pub events: Vec<EventRecord>,
}

impl Default for EventIndex {
    fn default() -> Self {
        Self {
            schema_version: EVENT_INDEX_SCHEMA_VERSION,
            events: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub id: Uuid,
    pub run_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub event: EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventKind {
    RunRecorded {
        included_files: u64,
        included_bytes: u64,
        excluded_paths: u64,
        exit_code: Option<i32>,
        success: bool,
    },
    EgressTunnel {
        host: String,
        port: u16,
    },
    EgressApproval {
        host: String,
        port: u16,
        decision: ApprovalEventDecision,
    },
    ObservationTruncated {
        dropped_audit_entries: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalEventDecision {
    Deny,
    DenyAlways,
    AllowOnce,
    AllowSession,
    AllowAlways,
}

/// Derive only bounded, explicitly non-secret records from fields observable in a run audit.
pub fn events_from_audit(manifest: &AuditManifest) -> Vec<EventRecord> {
    let Some(run) = &manifest.run else {
        return Vec::new();
    };
    let audit_entries = run
        .egress_audit
        .len()
        .saturating_add(run.egress_approvals.len());
    let truncated = audit_entries > MAX_EVENTS_PER_AUDIT - 1;
    let detail_budget = if truncated {
        MAX_EVENTS_PER_AUDIT - 2
    } else {
        MAX_EVENTS_PER_AUDIT - 1
    };
    let mut records = Vec::with_capacity(MAX_EVENTS_PER_AUDIT.min(audit_entries.saturating_add(2)));
    let egress_to_read = detail_budget.min(run.egress_audit.len());
    for line in run.egress_audit.iter().take(egress_to_read) {
        if let Some((occurred_at, host, port)) = parse_egress_audit(line) {
            records.push(EventRecord {
                id: Uuid::new_v4(),
                run_id: manifest.run_id,
                occurred_at,
                event: EventKind::EgressTunnel { host, port },
            });
        }
    }
    let approval_to_read = detail_budget.saturating_sub(egress_to_read);
    for line in run.egress_approvals.iter().take(approval_to_read) {
        if let Some((occurred_at, host, port, decision)) = parse_approval_audit(line) {
            records.push(EventRecord {
                id: Uuid::new_v4(),
                run_id: manifest.run_id,
                occurred_at,
                event: EventKind::EgressApproval {
                    host,
                    port,
                    decision,
                },
            });
        }
    }
    if truncated {
        records.push(EventRecord {
            id: Uuid::new_v4(),
            run_id: manifest.run_id,
            occurred_at: Utc::now(),
            event: EventKind::ObservationTruncated {
                dropped_audit_entries: u64::try_from(audit_entries - detail_budget)
                    .unwrap_or(u64::MAX),
            },
        });
    }
    // Keep the per-run summary even if an audit contains enough successful tunnels to fill the
    // whole per-append bound. It is appended last because it is created after those observations.
    records.push(EventRecord {
        id: Uuid::new_v4(),
        run_id: manifest.run_id,
        occurred_at: Utc::now(),
        event: EventKind::RunRecorded {
            included_files: manifest.totals.included_files,
            included_bytes: manifest.totals.included_bytes,
            excluded_paths: manifest.totals.excluded_paths,
            exit_code: run.exit_code,
            success: run.success,
        },
    });
    records
}

/// Read the complete index. A missing store is an empty index; unsafe or corrupt state fails
/// closed and never returns a partial result.
pub fn read_event_index(events_dir: &Path) -> Result<EventIndex, EventStoreError> {
    match fs::symlink_metadata(events_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EventIndex::default());
        }
        Err(source) => return Err(io_error("inspect event directory", events_dir, source)),
        Ok(_) => {}
    }
    let directory = open_private_directory(events_dir)?;
    let index = read_index_file(events_dir)?;
    ensure_path_matches_directory(events_dir, &directory)?;
    Ok(index)
}

/// Select a validated newest-first view, independent of persisted or append order.
pub fn select_events(
    index: &EventIndex,
    limit: usize,
    run_id: Option<Uuid>,
) -> Result<Vec<&EventRecord>, EventStoreError> {
    if !(1..=MAX_EVENT_QUERY_LIMIT).contains(&limit) {
        return Err(EventStoreError::InvalidQueryLimit(limit));
    }
    validate_index(index)?;
    let mut selected: Vec<_> = index
        .events
        .iter()
        .filter(|event| run_id.is_none_or(|run_id| event.run_id == run_id))
        .collect();
    selected.sort_by(|left, right| compare_events(left, right));
    selected.reverse();
    selected.truncate(limit);
    Ok(selected)
}

/// Append records while holding the store lock, evicting the oldest records at the fixed bound,
/// and atomically replacing the complete index.
pub fn append_events(events_dir: &Path, records: &[EventRecord]) -> Result<(), EventStoreError> {
    if records.is_empty() {
        return Ok(());
    }
    if records.len() > MAX_EVENTS_PER_AUDIT {
        return Err(EventStoreError::TooManyAppendEvents(records.len()));
    }
    validate_records(records)?;
    let directory = prepare_private_directory(events_dir)?;
    let _lock = lock_store(events_dir)?;
    let mut index = read_index_file(events_dir)?;
    index.events.extend(records.iter().cloned());
    sort_events(&mut index.events);
    if index.events.len() > MAX_EVENTS {
        index.events.drain(..index.events.len() - MAX_EVENTS);
    }
    validate_index(&index)?;
    write_index(events_dir, &index)?;
    ensure_path_matches_directory(events_dir, &directory)?;
    Ok(())
}

fn parse_egress_audit(line: &str) -> Option<(DateTime<Utc>, String, u16)> {
    if line.len() > MAX_AUDIT_LINE_BYTES || !line.is_ascii() {
        return None;
    }
    let mut fields = line.split('\t');
    let occurred_at = parse_unix_seconds(fields.next()?)?;
    let (host, port) = parse_destination(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    Some((occurred_at, host, port))
}

fn parse_approval_audit(line: &str) -> Option<(DateTime<Utc>, String, u16, ApprovalEventDecision)> {
    if line.len() > MAX_AUDIT_LINE_BYTES || !line.is_ascii() {
        return None;
    }
    let mut fields = line.split('\t');
    let occurred_at = parse_unix_seconds(fields.next()?)?;
    let (host, port) = parse_destination(fields.next()?)?;
    let decision = match fields.next()? {
        "deny" => ApprovalEventDecision::Deny,
        "deny-always" => ApprovalEventDecision::DenyAlways,
        "allow-once" => ApprovalEventDecision::AllowOnce,
        "allow-session" => ApprovalEventDecision::AllowSession,
        "allow-always" => ApprovalEventDecision::AllowAlways,
        _ => return None,
    };
    if fields.next().is_some() {
        return None;
    }
    Some((occurred_at, host, port, decision))
}

fn parse_unix_seconds(value: &str) -> Option<DateTime<Utc>> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let seconds: i64 = value.parse().ok()?;
    Utc.timestamp_opt(seconds, 0).single()
}

fn parse_destination(value: &str) -> Option<(String, u16)> {
    let (host, port) = value.rsplit_once(':')?;
    if port != "443" || !valid_exact_hostname(host) {
        return None;
    }
    Some((host.to_owned(), 443))
}

fn valid_exact_hostname(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn prepare_private_directory(path: &Path) -> Result<File, EventStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|source| io_error("create event directory", path, source))?;
        }
        Err(source) => return Err(io_error("inspect event directory", path, source)),
    }
    open_private_directory(path)
}

fn open_private_directory(path: &Path) -> Result<File, EventStoreError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io_error("open event directory", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect event directory", path, source))?;
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(EventStoreError::UnsafePath(path.to_path_buf()));
    }
    Ok(file)
}

fn lock_store(events_dir: &Path) -> Result<File, EventStoreError> {
    let path = events_dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|source| io_error("open event lock", &path, source))?;
    validate_private_file(&file, &path, 0)?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let source = std::io::Error::last_os_error();
        if source
            .raw_os_error()
            .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
        {
            return Err(EventStoreError::Busy);
        }
        return Err(io_error("lock event store", &path, source));
    }
    Ok(file)
}

fn read_index_file(events_dir: &Path) -> Result<EventIndex, EventStoreError> {
    let path = events_dir.join(INDEX_FILE);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EventIndex::default());
        }
        Err(source) => return Err(io_error("open event index", &path, source)),
    };
    validate_private_file(&file, &path, MAX_EVENT_INDEX_BYTES)?;
    let mut bytes = Vec::new();
    file.take(MAX_EVENT_INDEX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read event index", &path, source))?;
    if bytes.len() as u64 > MAX_EVENT_INDEX_BYTES {
        return Err(EventStoreError::TooLarge(path));
    }
    let mut index: EventIndex = serde_json::from_slice(&bytes).map_err(EventStoreError::Parse)?;
    validate_index(&index)?;
    sort_events(&mut index.events);
    Ok(index)
}

fn validate_index(index: &EventIndex) -> Result<(), EventStoreError> {
    if index.schema_version != EVENT_INDEX_SCHEMA_VERSION {
        return Err(EventStoreError::UnsupportedSchema(index.schema_version));
    }
    if index.events.len() > MAX_EVENTS {
        return Err(EventStoreError::TooManyEvents(index.events.len()));
    }
    validate_records(&index.events)
}

fn validate_records(events: &[EventRecord]) -> Result<(), EventStoreError> {
    let mut ids = BTreeSet::new();
    for event in events {
        if !ids.insert(event.id) {
            return Err(EventStoreError::InvalidRecord);
        }
        match &event.event {
            EventKind::EgressTunnel { host, port }
            | EventKind::EgressApproval { host, port, .. }
                if *port != 443 || !valid_exact_hostname(host) =>
            {
                return Err(EventStoreError::InvalidRecord);
            }
            _ => {}
        }
    }
    Ok(())
}

fn sort_events(events: &mut [EventRecord]) {
    events.sort_by(compare_events);
}

fn compare_events(left: &EventRecord, right: &EventRecord) -> std::cmp::Ordering {
    left.occurred_at
        .cmp(&right.occurred_at)
        .then_with(|| left.id.cmp(&right.id))
}

fn validate_private_file(
    file: &File,
    path: &Path,
    maximum_bytes: u64,
) -> Result<(), EventStoreError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect event file", path, source))?;
    if !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(EventStoreError::UnsafePath(path.to_path_buf()));
    }
    if metadata.len() > maximum_bytes {
        return Err(EventStoreError::TooLarge(path.to_path_buf()));
    }
    Ok(())
}

fn write_index(events_dir: &Path, index: &EventIndex) -> Result<(), EventStoreError> {
    let bytes = serde_json::to_vec_pretty(index).map_err(EventStoreError::Serialize)?;
    if bytes.len() as u64 > MAX_EVENT_INDEX_BYTES {
        return Err(EventStoreError::TooLarge(events_dir.join(INDEX_FILE)));
    }
    let temp_path = events_dir.join(format!(".events-{}.tmp", Uuid::new_v4()));
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp_path)
        .map_err(|source| io_error("create temporary event index", &temp_path, source))?;
    let result = (|| {
        validate_private_file(&temp, &temp_path, MAX_EVENT_INDEX_BYTES)?;
        temp.write_all(&bytes)
            .map_err(|source| io_error("write temporary event index", &temp_path, source))?;
        temp.sync_all()
            .map_err(|source| io_error("sync temporary event index", &temp_path, source))?;
        fs::rename(&temp_path, events_dir.join(INDEX_FILE)).map_err(|source| {
            io_error("publish event index", &events_dir.join(INDEX_FILE), source)
        })?;
        sync_directory(events_dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn sync_directory(path: &Path) -> Result<(), EventStoreError> {
    let directory = open_private_directory(path)?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync event directory", path, source))
}

fn ensure_path_matches_directory(path: &Path, held: &File) -> Result<(), EventStoreError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reinspect event directory", path, source))?;
    let held_metadata = held
        .metadata()
        .map_err(|source| io_error("reinspect held event directory", path, source))?;
    if path_metadata.file_type().is_symlink()
        || path_metadata.dev() != held_metadata.dev()
        || path_metadata.ino() != held_metadata.ino()
    {
        return Err(EventStoreError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> EventStoreError {
    EventStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("unsafe event-store path: {0}")]
    UnsafePath(PathBuf),
    #[error("event-store file exceeds its size bound: {0}")]
    TooLarge(PathBuf),
    #[error("event index contains {0} records, exceeding its bound")]
    TooManyEvents(usize),
    #[error("append contains {0} records, exceeding its per-operation bound")]
    TooManyAppendEvents(usize),
    #[error("event query limit {0} is outside 1..=1000")]
    InvalidQueryLimit(usize),
    #[error("unsupported event-index schema version {0}")]
    UnsupportedSchema(u32),
    #[error("event index contains an invalid record")]
    InvalidRecord,
    #[error("event store is busy")]
    Busy,
    #[error("invalid event-index JSON: {0}")]
    Parse(serde_json::Error),
    #[error("failed to serialize event index: {0}")]
    Serialize(serde_json::Error),
    #[error("{operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResourceLimitRecord, RunRecord, StageTotals};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn manifest() -> AuditManifest {
        AuditManifest {
            schema_version: 1,
            run_id: Uuid::new_v4(),
            created_at: Utc::now(),
            source_root: "/secret/source".to_owned(),
            policy_sha256: "privacy-canary-policy".to_owned(),
            included: Vec::new(),
            excluded: Vec::new(),
            totals: StageTotals {
                included_files: 2,
                included_bytes: 42,
                excluded_paths: 3,
            },
            synthetic_git: true,
            run: Some(RunRecord {
                backend: "secret-backend-arg".to_owned(),
                network: "controlled".to_owned(),
                tool: "/private/tool --secret".to_owned(),
                forwarded_environment_names: vec!["TOKEN".to_owned()],
                allowed_egress_hosts: vec!["configured.example".to_owned()],
                interactive_egress_approval: true,
                egress_audit: vec!["1700000000\tapi.example:443".to_owned()],
                egress_approvals: vec!["1700000001\tnew.example:443\tallow-session".to_owned()],
                clipboard_imports: vec!["/secret/clipboard.png".to_owned()],
                resource_limits: ResourceLimitRecord {
                    memory_bytes: 1,
                    max_file_bytes: 1,
                    cpu_seconds: 1,
                    open_files: 1,
                    max_processes: 1,
                    cpu_percent: 1,
                },
                cgroup_enforced: false,
                seccomp_enforced: true,
                exit_code: Some(0),
                success: true,
            }),
        }
    }

    fn event(run_id: Uuid, number: i64) -> EventRecord {
        EventRecord {
            id: Uuid::new_v4(),
            run_id,
            occurred_at: Utc.timestamp_opt(number, 0).unwrap(),
            event: EventKind::RunRecorded {
                included_files: number as u64,
                included_bytes: 0,
                excluded_paths: 0,
                exit_code: Some(0),
                success: true,
            },
        }
    }

    #[test]
    fn derives_only_allowlisted_privacy_reduced_fields() {
        let manifest = manifest();
        let serialized = serde_json::to_string(&events_from_audit(&manifest)).unwrap();
        for canary in [
            "/secret/source",
            "privacy-canary-policy",
            "/private/tool",
            "TOKEN",
            "configured.example",
            "/secret/clipboard.png",
        ] {
            assert!(!serialized.contains(canary), "leaked {canary}");
        }
        assert!(serialized.contains("api.example"));
        assert!(serialized.contains("new.example"));
    }

    #[test]
    fn one_audit_derivation_is_bounded_and_reports_truncation() {
        let mut manifest = manifest();
        let run = manifest.run.as_mut().unwrap();
        run.egress_audit = (0..MAX_EVENTS_PER_AUDIT + 20)
            .map(|number| format!("{}\thost-{number}.example:443", 1_700_000_000 + number))
            .collect();
        run.egress_approvals = vec!["1700001000\tapproval.example:443\tdeny".to_owned()];
        let records = events_from_audit(&manifest);
        assert_eq!(records.len(), MAX_EVENTS_PER_AUDIT);
        assert!(matches!(
            records[records.len() - 2].event,
            EventKind::ObservationTruncated {
                dropped_audit_entries: 23
            }
        ));
        assert!(matches!(
            records.last().unwrap().event,
            EventKind::RunRecorded { .. }
        ));
    }

    #[test]
    fn selection_orders_interleaved_audit_kinds_newest_first() {
        let mut manifest = manifest();
        let run_id = manifest.run_id;
        let run = manifest.run.as_mut().unwrap();
        run.egress_audit = vec![
            "100\tfirst.example:443".to_owned(),
            "300\tthird.example:443".to_owned(),
        ];
        run.egress_approvals = vec![
            "200\tsecond.example:443\tdeny".to_owned(),
            "400\tfourth.example:443\tallow-once".to_owned(),
        ];
        let index = EventIndex {
            schema_version: EVENT_INDEX_SCHEMA_VERSION,
            events: events_from_audit(&manifest),
        };
        let selected = select_events(&index, 5, Some(run_id)).unwrap();
        let timestamps: Vec<_> = selected
            .iter()
            .map(|event| event.occurred_at.timestamp())
            .collect();
        assert_eq!(&timestamps[1..], &[400, 300, 200, 100]);
        assert!(matches!(
            selected[1].event,
            EventKind::EgressApproval { .. }
        ));
        assert!(matches!(selected[2].event, EventKind::EgressTunnel { .. }));
        assert!(matches!(
            selected[3].event,
            EventKind::EgressApproval { .. }
        ));
        assert!(matches!(selected[4].event, EventKind::EgressTunnel { .. }));
        assert!(matches!(
            select_events(&index, 0, None),
            Err(EventStoreError::InvalidQueryLimit(0))
        ));
    }

    #[test]
    fn audit_parsers_are_strict_and_bounded() {
        assert!(parse_egress_audit("1700000000\ta.example:443").is_some());
        for bad in [
            "-1\ta.example:443",
            "1\tA.example:443",
            "1\ta.example:80",
            "1\ta.example:443\textra",
            "1\t*.example:443",
            "1\ta..example:443",
            "1\ta.example:443\n",
        ] {
            assert!(parse_egress_audit(bad).is_none(), "accepted {bad:?}");
        }
        assert!(parse_approval_audit("1\ta.example:443\tallow-once").is_some());
        assert!(parse_approval_audit("1\ta.example:443\tallow\tonce").is_none());
        assert!(parse_approval_audit("1\ta.example:443\tunknown").is_none());
        assert!(parse_egress_audit(&"x".repeat(MAX_AUDIT_LINE_BYTES + 1)).is_none());
    }

    #[test]
    fn schema_rejects_unknown_fields_and_future_versions() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("events");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join(INDEX_FILE), br#"{"schema_version":2,"events":[]}"#).unwrap();
        fs::set_permissions(dir.join(INDEX_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            read_event_index(&dir),
            Err(EventStoreError::UnsupportedSchema(2))
        ));
        fs::write(
            dir.join(INDEX_FILE),
            br#"{"schema_version":1,"events":[],"future":true}"#,
        )
        .unwrap();
        assert!(matches!(
            read_event_index(&dir),
            Err(EventStoreError::Parse(_))
        ));
        fs::write(
            dir.join(INDEX_FILE),
            format!(
                r#"{{"schema_version":1,"events":[{{"id":"{}","run_id":"{}","occurred_at":"2026-01-01T00:00:00Z","event":{{"kind":"future_event"}}}}]}}"#,
                Uuid::new_v4(),
                Uuid::new_v4()
            ),
        )
        .unwrap();
        assert!(matches!(
            read_event_index(&dir),
            Err(EventStoreError::Parse(_))
        ));
    }

    #[test]
    fn store_enforces_types_modes_links_and_size() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("events");
        let directory_target = root.path().join("directory-target");
        fs::create_dir(&directory_target).unwrap();
        fs::set_permissions(&directory_target, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&directory_target, &dir).unwrap();
        assert!(read_event_index(&dir).is_err());
        fs::remove_file(&dir).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            read_event_index(&dir),
            Err(EventStoreError::UnsafePath(_))
        ));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join(INDEX_FILE), b"{}").unwrap();
        fs::set_permissions(dir.join(INDEX_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_event_index(&dir),
            Err(EventStoreError::UnsafePath(_))
        ));
        fs::remove_file(dir.join(INDEX_FILE)).unwrap();
        let external = root.path().join("external");
        fs::write(&external, b"{}").unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&external, dir.join(INDEX_FILE)).unwrap();
        assert!(matches!(
            read_event_index(&dir),
            Err(EventStoreError::UnsafePath(_))
        ));
        fs::remove_file(dir.join(INDEX_FILE)).unwrap();
        symlink(&external, dir.join(INDEX_FILE)).unwrap();
        assert!(read_event_index(&dir).is_err());
        fs::remove_file(dir.join(INDEX_FILE)).unwrap();
        let oversized = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join(INDEX_FILE))
            .unwrap();
        oversized.set_len(MAX_EVENT_INDEX_BYTES + 1).unwrap();
        assert!(matches!(
            read_event_index(&dir),
            Err(EventStoreError::TooLarge(_))
        ));
    }

    #[test]
    fn append_evicts_oldest_and_preserves_order() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("events");
        let run = Uuid::new_v4();
        let records: Vec<_> = (0..MAX_EVENTS + 3)
            .map(|number| event(run, number as i64))
            .collect();
        for chunk in records.chunks(MAX_EVENTS_PER_AUDIT) {
            append_events(&dir, chunk).unwrap();
        }
        let index = read_event_index(&dir).unwrap();
        assert_eq!(index.events.len(), MAX_EVENTS);
        assert_eq!(index.events[0].occurred_at.timestamp(), 3);
        assert_eq!(
            index.events.last().unwrap().occurred_at.timestamp(),
            (MAX_EVENTS + 2) as i64
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.join(INDEX_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        append_events(&dir, &[event(Uuid::new_v4(), -1)]).unwrap();
        assert_eq!(
            read_event_index(&dir).unwrap(),
            index,
            "a late append of the chronologically oldest record must evict itself"
        );
    }

    #[test]
    fn append_order_across_runs_does_not_change_query_chronology() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("events");
        let newer_run = Uuid::new_v4();
        append_events(&dir, &[event(newer_run, 30), event(newer_run, 20)]).unwrap();
        let older_run = Uuid::new_v4();
        append_events(&dir, &[event(older_run, 10)]).unwrap();

        let index = read_event_index(&dir).unwrap();
        let stored: Vec<_> = index
            .events
            .iter()
            .map(|event| event.occurred_at.timestamp())
            .collect();
        assert_eq!(stored, vec![10, 20, 30]);
        let queried: Vec<_> = select_events(&index, 3, None)
            .unwrap()
            .iter()
            .map(|event| event.occurred_at.timestamp())
            .collect();
        assert_eq!(queried, vec![30, 20, 10]);
        assert_eq!(select_events(&index, 3, Some(older_run)).unwrap().len(), 1);
    }

    #[test]
    fn equal_timestamps_use_event_id_as_a_deterministic_tie_break() {
        let run = Uuid::new_v4();
        let mut lower = event(run, 10);
        lower.id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let mut higher = event(run, 10);
        higher.id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let index = EventIndex {
            schema_version: EVENT_INDEX_SCHEMA_VERSION,
            events: vec![higher.clone(), lower.clone()],
        };
        let selected = select_events(&index, 2, None).unwrap();
        assert_eq!(selected[0].id, higher.id);
        assert_eq!(selected[1].id, lower.id);
    }

    #[test]
    fn append_rejects_an_unbounded_input_before_creating_state() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("events");
        let records: Vec<_> = (0..MAX_EVENTS_PER_AUDIT + 1)
            .map(|number| event(Uuid::new_v4(), number as i64))
            .collect();
        assert!(matches!(
            append_events(&dir, &records),
            Err(EventStoreError::TooManyAppendEvents(count))
                if count == MAX_EVENTS_PER_AUDIT + 1
        ));
        assert!(!dir.exists());
    }

    #[test]
    fn concurrent_appends_are_atomic_and_refuse_contention_without_waiting() {
        let root = tempfile::tempdir().unwrap();
        let dir = Arc::new(root.path().join("events"));
        prepare_private_directory(&dir).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for number in 0..8 {
            let dir = Arc::clone(&dir);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                append_events(&dir, &[event(Uuid::new_v4(), number)])
            }));
        }
        let mut appended = 0;
        let mut busy = 0;
        for thread in threads {
            match thread.join().unwrap() {
                Ok(()) => appended += 1,
                Err(EventStoreError::Busy) => busy += 1,
                Err(error) => panic!("unexpected append error: {error}"),
            }
        }
        assert_eq!(appended + busy, 8);
        assert!(appended >= 1);
        assert_eq!(read_event_index(&dir).unwrap().events.len(), appended);
        assert!(fs::read_dir(&*dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn a_held_lock_is_reported_as_busy_without_mutating_the_index() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("events");
        prepare_private_directory(&dir).unwrap();
        let _lock = lock_store(&dir).unwrap();
        assert!(matches!(
            append_events(&dir, &[event(Uuid::new_v4(), 1)]),
            Err(EventStoreError::Busy)
        ));
        assert!(read_event_index(&dir).unwrap().events.is_empty());
    }

    #[test]
    fn failed_append_does_not_replace_the_previous_index() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("events");
        let original = event(Uuid::new_v4(), 1);
        append_events(&dir, std::slice::from_ref(&original)).unwrap();
        let mut invalid = event(Uuid::new_v4(), 2);
        invalid.event = EventKind::EgressTunnel {
            host: "UPPERCASE.example".to_owned(),
            port: 443,
        };
        assert!(matches!(
            append_events(&dir, &[invalid]),
            Err(EventStoreError::InvalidRecord)
        ));
        assert_eq!(read_event_index(&dir).unwrap().events, vec![original]);
    }
}
