use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use chrono::{TimeZone, Utc};
use sandbox_guard_core::{
    AuditManifest, MAX_AUDIT_MANIFEST_BYTES, MAX_AUDIT_TAIL_CANDIDATES, StageTotals,
    find_persisted_audit, tail_persisted_audit_summaries,
};
use uuid::Uuid;

fn manifest(seconds: i64) -> AuditManifest {
    AuditManifest {
        schema_version: 1,
        run_id: Uuid::new_v4(),
        created_at: Utc.timestamp_opt(seconds, 0).unwrap(),
        source_root: "/redacted/source".to_owned(),
        policy_sha256: "00".repeat(32),
        included: Vec::new(),
        excluded: Vec::new(),
        totals: StageTotals::default(),
        synthetic_git: true,
        run: None,
    }
}

fn write_manifest(directory: &Path, manifest: &AuditManifest) {
    write_bytes(
        directory,
        &format!(
            "{}-{}.json",
            manifest.created_at.format("%Y%m%dT%H%M%SZ"),
            manifest.run_id
        ),
        &serde_json::to_vec(manifest).unwrap(),
    );
}

fn write_bytes(directory: &Path, name: &str, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn manifest_name(manifest: &AuditManifest) -> String {
    format!(
        "{}-{}.json",
        manifest.created_at.format("%Y%m%dT%H%M%SZ"),
        manifest.run_id
    )
}

fn private_directory(root: &Path) -> std::path::PathBuf {
    let directory = root.join("audit");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    directory
}

#[test]
fn missing_history_is_empty_and_tail_is_newest_first() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        tail_persisted_audit_summaries(&root.path().join("missing"), 10)
            .unwrap()
            .is_empty()
    );

    let directory = private_directory(root.path());
    let old = manifest(10);
    let new = manifest(20);
    write_manifest(&directory, &old);
    write_manifest(&directory, &new);
    let audits = tail_persisted_audit_summaries(&directory, 1).unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].run_id, new.run_id);
}

#[test]
fn same_second_tail_uses_exact_manifest_time_before_limiting() {
    let root = tempfile::tempdir().unwrap();
    let directory = private_directory(root.path());
    let mut older = manifest(10);
    older.created_at = Utc.timestamp_opt(10, 1).unwrap();
    older.run_id = Uuid::parse_str("ffffffff-ffff-4fff-8fff-ffffffffffff").unwrap();
    let mut newer = manifest(10);
    newer.created_at = Utc.timestamp_opt(10, 999_999_999).unwrap();
    newer.run_id = Uuid::parse_str("00000000-0000-4000-8000-000000000000").unwrap();
    write_manifest(&directory, &older);
    write_manifest(&directory, &newer);

    let audits = tail_persisted_audit_summaries(&directory, 1).unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].run_id, newer.run_id);
}

#[test]
fn unselected_manifest_contents_are_not_parsed() {
    let root = tempfile::tempdir().unwrap();
    let directory = private_directory(root.path());
    let selected = manifest(20);
    let unrelated = manifest(10);
    write_manifest(&directory, &selected);
    write_bytes(&directory, &manifest_name(&unrelated), b"{corrupt");

    let audits = tail_persisted_audit_summaries(&directory, 1).unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].run_id, selected.run_id);
    assert_eq!(
        find_persisted_audit(&directory, selected.run_id)
            .unwrap()
            .unwrap()
            .manifest
            .run_id,
        selected.run_id
    );
}

#[test]
fn exact_run_lookup_binds_filename_and_manifest_identity() {
    let root = tempfile::tempdir().unwrap();
    let directory = private_directory(root.path());
    let wanted = manifest(10);
    write_manifest(&directory, &wanted);
    assert_eq!(
        find_persisted_audit(&directory, wanted.run_id)
            .unwrap()
            .unwrap()
            .manifest
            .run_id,
        wanted.run_id
    );
    assert!(
        find_persisted_audit(&directory, Uuid::new_v4())
            .unwrap()
            .is_none()
    );

    let wrong = manifest(30);
    let forged_name = format!(
        "{}-{}.json",
        wrong.created_at.format("%Y%m%dT%H%M%SZ"),
        Uuid::new_v4()
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(forged_name))
        .unwrap();
    file.write_all(&serde_json::to_vec(&wrong).unwrap())
        .unwrap();
    assert!(tail_persisted_audit_summaries(&directory, 10).is_err());
}

#[test]
fn canonical_duplicate_run_filenames_fail_closed_before_content_parsing() {
    let root = tempfile::tempdir().unwrap();
    let directory = private_directory(root.path());
    let run_id = Uuid::new_v4();
    for second in [10, 11] {
        write_bytes(
            &directory,
            &format!("19700101T0000{second}Z-{run_id}.json"),
            b"{}",
        );
    }
    assert!(find_persisted_audit(&directory, run_id).is_err());
}

#[test]
fn unsafe_directory_file_and_unexpected_entry_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let directory = private_directory(root.path());
    let audit = manifest(10);
    write_manifest(&directory, &audit);
    fs::set_permissions(
        fs::read_dir(&directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    assert!(tail_persisted_audit_summaries(&directory, 10).is_err());

    let other_root = tempfile::tempdir().unwrap();
    let other = private_directory(other_root.path());
    fs::write(other.join("surprise"), b"x").unwrap();
    assert!(tail_persisted_audit_summaries(&other, 10).is_err());
}

#[test]
fn symlinked_audit_directory_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let real = private_directory(root.path());
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    assert!(tail_persisted_audit_summaries(&linked, 10).is_err());
}

#[test]
fn noncanonical_uuid_symlink_hardlink_fifo_and_future_schema_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let directory = private_directory(root.path());
    let audit = manifest(10);
    let uppercase = manifest_name(&audit).to_ascii_uppercase();
    write_bytes(&directory, &uppercase, &serde_json::to_vec(&audit).unwrap());
    assert!(find_persisted_audit(&directory, audit.run_id).is_err());

    let symlink_root = tempfile::tempdir().unwrap();
    let symlink_dir = private_directory(symlink_root.path());
    let outside = symlink_root.path().join("outside");
    fs::write(&outside, b"{}").unwrap();
    std::os::unix::fs::symlink(&outside, symlink_dir.join(manifest_name(&audit))).unwrap();
    assert!(tail_persisted_audit_summaries(&symlink_dir, 10).is_err());

    let hardlink_root = tempfile::tempdir().unwrap();
    let hardlink_dir = private_directory(hardlink_root.path());
    write_manifest(&hardlink_dir, &audit);
    let other = manifest(11);
    fs::hard_link(
        hardlink_dir.join(manifest_name(&audit)),
        hardlink_dir.join(manifest_name(&other)),
    )
    .unwrap();
    assert!(tail_persisted_audit_summaries(&hardlink_dir, 10).is_err());

    let fifo_root = tempfile::tempdir().unwrap();
    let fifo_dir = private_directory(fifo_root.path());
    let fifo = fifo_dir.join(manifest_name(&audit));
    let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    assert!(tail_persisted_audit_summaries(&fifo_dir, 10).is_err());

    let schema_root = tempfile::tempdir().unwrap();
    let schema_dir = private_directory(schema_root.path());
    let mut future = manifest(20);
    future.schema_version = 2;
    write_manifest(&schema_dir, &future);
    assert!(tail_persisted_audit_summaries(&schema_dir, 10).is_err());
}

#[test]
fn per_file_and_aggregate_tail_bounds_are_enforced_before_parsing() {
    let root = tempfile::tempdir().unwrap();
    let directory = private_directory(root.path());
    let audit = manifest(10);
    let oversized = directory.join(manifest_name(&audit));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&oversized)
        .unwrap();
    file.set_len(MAX_AUDIT_MANIFEST_BYTES + 1).unwrap();
    assert!(tail_persisted_audit_summaries(&directory, 1).is_err());

    let aggregate_root = tempfile::tempdir().unwrap();
    let aggregate_dir = private_directory(aggregate_root.path());
    for index in 0..5_u128 {
        let run_id = Uuid::from_u128(index + 1);
        let name = format!("19700101T000010Z-{run_id}.json");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(aggregate_dir.join(name))
            .unwrap();
        file.set_len(MAX_AUDIT_MANIFEST_BYTES).unwrap();
    }
    assert!(tail_persisted_audit_summaries(&aggregate_dir, 1).is_err());
}

#[test]
fn same_second_tail_candidate_count_is_bounded_before_content_parsing() {
    let root = tempfile::tempdir().unwrap();
    let directory = private_directory(root.path());
    for index in 0..=MAX_AUDIT_TAIL_CANDIDATES {
        let run_id = Uuid::from_u128(index as u128 + 1);
        write_bytes(
            &directory,
            &format!("19700101T000010Z-{run_id}.json"),
            b"{}",
        );
    }
    assert!(tail_persisted_audit_summaries(&directory, 1).is_err());
}
