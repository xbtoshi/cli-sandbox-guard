#![cfg(unix)]

use std::fs;
use std::time::Duration;

use sandbox_guard_core::{CompiledPolicy, Stage, StageOptions, garbage_collect};

#[test]
fn skips_active_stage_then_removes_it_after_lock_release() {
    let source = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let base_path = fs::canonicalize(base.path()).unwrap();
    fs::write(source.path().join("README.md"), "public\n").unwrap();

    let policy = CompiledPolicy::builtin().unwrap();
    let mut options = StageOptions::new(source.path(), policy);
    options.staging_base = Some(base_path.clone());
    options.synthetic_git = false;
    let stage = Stage::build(options).unwrap();
    let root = stage.root().to_path_buf();

    let active = garbage_collect(&base_path, Duration::ZERO, false).unwrap();
    assert_eq!(active.active, vec![root.clone()]);
    assert!(root.is_dir());

    let kept = stage.keep().unwrap();
    let collected = garbage_collect(&base_path, Duration::ZERO, false).unwrap();
    assert_eq!(collected.removed, vec![kept.root.clone()]);
    assert!(!kept.root.exists());
}

#[test]
fn dry_run_reports_but_does_not_remove_an_orphan_without_a_lock() {
    let base = tempfile::tempdir().unwrap();
    let orphan = base.path().join("sandbox-guard-orphan");
    fs::create_dir(&orphan).unwrap();
    fs::write(orphan.join("partial"), "partial\n").unwrap();
    let orphan = fs::canonicalize(orphan).unwrap();

    let report = garbage_collect(base.path(), Duration::ZERO, true).unwrap();
    assert_eq!(report.would_remove, vec![orphan.clone()]);
    assert!(orphan.is_dir());
}
