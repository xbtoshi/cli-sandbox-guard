#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};

use sandbox_guard_core::{ChangeKind, CompiledPolicy, Stage, StageOptions, export_changes};

#[test]
fn exports_only_reopened_regular_changes_and_records_deletions() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("modified.txt"), "before\n").unwrap();
    fs::write(source.path().join("deleted.txt"), "delete me\n").unwrap();
    fs::write(source.path().join("unchanged.txt"), "same\n").unwrap();
    let policy = CompiledPolicy::builtin().unwrap();
    let mut options = StageOptions::new(source.path(), policy.clone());
    options.synthetic_git = false;
    let stage = Stage::build(options).unwrap();

    fs::write(stage.workspace().join("modified.txt"), "after\n").unwrap();
    fs::remove_file(stage.workspace().join("deleted.txt")).unwrap();
    fs::write(stage.workspace().join("added.txt"), "new\n").unwrap();
    fs::write(stage.workspace().join("hardlink-a"), "linked\n").unwrap();
    fs::hard_link(
        stage.workspace().join("hardlink-a"),
        stage.workspace().join("unsafe-hardlink"),
    )
    .unwrap();
    symlink("/etc/passwd", stage.workspace().join("unsafe-link")).unwrap();
    fs::write(stage.workspace().join(".env.exported"), "secret\n").unwrap();

    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("changes");
    let report = export_changes(
        stage.workspace(),
        source.path(),
        stage.manifest(),
        &policy,
        &destination,
    )
    .unwrap();

    assert_eq!(
        fs::read_to_string(destination.join("files/modified.txt")).unwrap(),
        "after\n"
    );
    assert_eq!(
        fs::read_to_string(destination.join("files/added.txt")).unwrap(),
        "new\n"
    );
    assert!(!destination.join("files/unchanged.txt").exists());
    assert!(!destination.join("files/unsafe-link").exists());
    assert!(!destination.join("files/.env.exported").exists());
    assert!(!destination.join("files/unsafe-hardlink").exists());
    assert!(
        report
            .manifest
            .changes
            .iter()
            .any(|change| { change.path == "modified.txt" && change.kind == ChangeKind::Modified })
    );
    assert!(
        report
            .manifest
            .changes
            .iter()
            .any(|change| { change.path == "added.txt" && change.kind == ChangeKind::Added })
    );
    assert!(
        report
            .manifest
            .changes
            .iter()
            .any(|change| { change.path == "deleted.txt" && change.kind == ChangeKind::Deleted })
    );
    assert!(
        report
            .manifest
            .rejected
            .iter()
            .any(|change| change.path == "unsafe-link")
    );
    assert!(
        report
            .manifest
            .rejected
            .iter()
            .any(|change| change.path == ".env.exported")
    );
    assert!(
        report
            .manifest
            .rejected
            .iter()
            .any(|change| change.path == "unsafe-hardlink")
    );
    assert_eq!(fs::metadata(&destination).unwrap().uid(), unsafe {
        libc::geteuid()
    });
}

#[test]
fn refuses_to_publish_an_export_inside_the_source_tree() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("file.txt"), "before\n").unwrap();
    let policy = CompiledPolicy::builtin().unwrap();
    let mut options = StageOptions::new(source.path(), policy.clone());
    options.synthetic_git = false;
    let stage = Stage::build(options).unwrap();
    fs::write(stage.workspace().join("file.txt"), "after\n").unwrap();

    assert!(
        export_changes(
            stage.workspace(),
            source.path(),
            stage.manifest(),
            &policy,
            &source.path().join("unsafe-export"),
        )
        .is_err()
    );

    let nested_parent = source.path().join("must-not-be-created");
    assert!(
        export_changes(
            stage.workspace(),
            source.path(),
            stage.manifest(),
            &policy,
            &nested_parent.join("changes"),
        )
        .is_err()
    );
    assert!(!nested_parent.exists());
}
