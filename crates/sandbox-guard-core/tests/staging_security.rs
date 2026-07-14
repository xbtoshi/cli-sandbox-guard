#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use sandbox_guard_core::{CompiledPolicy, ExclusionReason, Stage, StageError, StageOptions};

fn stage(source: &Path, synthetic_git: bool) -> Result<Stage, StageError> {
    let policy = CompiledPolicy::builtin().unwrap();
    let mut options = StageOptions::new(source, policy);
    options.synthetic_git = synthetic_git;
    Stage::build(options)
}

#[test]
fn excludes_builtin_secrets_symlinks_and_hardlink_aliases() {
    let fixture = tempfile::tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("nested")).unwrap();
    fs::write(fixture.path().join("README.md"), "public\n").unwrap();
    fs::write(fixture.path().join(".env.production"), "TOKEN=secret\n").unwrap();
    fs::write(
        fixture.path().join("nested/credentials.json"),
        "{\"secret\":true}\n",
    )
    .unwrap();

    fs::write(fixture.path().join(".env"), "hard-link-secret\n").unwrap();
    fs::hard_link(
        fixture.path().join(".env"),
        fixture.path().join("innocent-name.txt"),
    )
    .unwrap();

    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(outside.path(), "outside-secret\n").unwrap();
    symlink(outside.path(), fixture.path().join("linked-readme.txt")).unwrap();

    let staged = stage(fixture.path(), false).unwrap();
    assert_eq!(
        fs::read_to_string(staged.workspace().join("README.md")).unwrap(),
        "public\n"
    );
    for denied in [
        ".env",
        ".env.production",
        "nested/credentials.json",
        "innocent-name.txt",
        "linked-readme.txt",
    ] {
        assert!(
            !staged.workspace().join(denied).exists(),
            "{denied} escaped into the staged workspace"
        );
    }

    assert!(staged.manifest().excluded.iter().any(|entry| {
        entry.path == "innocent-name.txt"
            && matches!(
                entry.reason,
                ExclusionReason::MultipleHardLinks { links: 2 }
            )
    }));
    assert!(staged.manifest().excluded.iter().any(|entry| {
        entry.path == "linked-readme.txt" && matches!(entry.reason, ExclusionReason::Symlink)
    }));
}

#[test]
fn tracked_ignored_files_are_included_but_untracked_ignored_files_are_not() {
    let fixture = tempfile::tempdir().unwrap();
    run_git(fixture.path(), &["init", "--quiet"]);
    fs::write(
        fixture.path().join(".gitignore"),
        "tracked.log\nignored.log\n",
    )
    .unwrap();
    fs::write(fixture.path().join("tracked.log"), "tracked\n").unwrap();
    run_git(fixture.path(), &["add", "-f", ".gitignore", "tracked.log"]);
    fs::write(fixture.path().join("ignored.log"), "ignored\n").unwrap();
    fs::write(fixture.path().join("visible.txt"), "visible\n").unwrap();

    let staged = stage(fixture.path(), true).unwrap();
    assert!(staged.workspace().join("tracked.log").is_file());
    assert!(staged.workspace().join("visible.txt").is_file());
    assert!(!staged.workspace().join("ignored.log").exists());
    assert_eq!(
        git_output(staged.workspace(), &["ls-files", "tracked.log"]).trim(),
        "tracked.log"
    );
}

#[test]
fn synthetic_git_has_one_clean_commit_and_no_original_secret_blob() {
    let fixture = tempfile::tempdir().unwrap();
    run_git(fixture.path(), &["init", "--quiet"]);
    run_git(fixture.path(), &["config", "user.name", "Fixture"]);
    run_git(
        fixture.path(),
        &["config", "user.email", "fixture@invalid.local"],
    );
    fs::write(
        fixture.path().join("historical-secret.txt"),
        "UNIQUE_HISTORY_SECRET_6abcb3\n",
    )
    .unwrap();
    run_git(fixture.path(), &["add", "historical-secret.txt"]);
    run_git(fixture.path(), &["commit", "--quiet", "-m", "secret"]);
    let original_hook = fixture.path().join(".git/hooks/post-commit");
    fs::write(&original_hook, "#!/bin/sh\nexit 99\n").unwrap();
    fs::set_permissions(&original_hook, fs::Permissions::from_mode(0o700)).unwrap();
    let original_oid = git_output(fixture.path(), &["hash-object", "historical-secret.txt"]);
    fs::remove_file(fixture.path().join("historical-secret.txt")).unwrap();
    fs::write(fixture.path().join("README.md"), "sanitized\n").unwrap();

    let staged = stage(fixture.path(), true).unwrap();
    let log = git_output(staged.workspace(), &["rev-list", "--all"]);
    assert_eq!(log.lines().count(), 1);
    assert!(git_status(staged.workspace(), &["status", "--porcelain"]).success());
    assert!(
        !git_status(staged.workspace(), &["cat-file", "-e", original_oid.trim()]).success(),
        "an object from the original repository leaked into synthetic history"
    );
    assert!(!staged.workspace().join(".git/hooks/post-commit").exists());
}

#[test]
fn preserves_only_the_executable_permission_class() {
    let fixture = tempfile::tempdir().unwrap();
    let script = fixture.path().join("script.sh");
    fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let staged = stage(fixture.path(), false).unwrap();
    let mode = fs::metadata(staged.workspace().join("script.sh"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn rejects_a_staging_base_inside_the_source_tree() {
    let fixture = tempfile::tempdir().unwrap();
    fs::write(fixture.path().join("README.md"), "public\n").unwrap();
    let policy = CompiledPolicy::builtin().unwrap();
    let mut options = StageOptions::new(fixture.path(), policy);
    options.staging_base = Some(fixture.path().join(".stages"));
    options.synthetic_git = false;

    assert!(matches!(
        Stage::build(options),
        Err(StageError::StagingInsideSource { .. })
    ));
}

#[test]
fn synthetic_git_supports_an_empty_sanitized_workspace() {
    let fixture = tempfile::tempdir().unwrap();
    fs::write(fixture.path().join(".env"), "only-secret=true\n").unwrap();

    let staged = stage(fixture.path(), true).unwrap();
    assert_eq!(
        git_output(staged.workspace(), &["rev-list", "--count", "--all"]).trim(),
        "1"
    );
    assert!(git_status(staged.workspace(), &["status", "--porcelain"]).success());
}

#[test]
fn a_symlinked_git_marker_is_never_followed() {
    let fixture = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(outside.path().join("objects")).unwrap();
    fs::write(outside.path().join("private"), "outside\n").unwrap();
    symlink(outside.path(), fixture.path().join(".git")).unwrap();
    fs::write(fixture.path().join("README.md"), "public\n").unwrap();

    let staged = stage(fixture.path(), false).unwrap();
    assert!(staged.workspace().join("README.md").is_file());
    assert!(!staged.workspace().join(".git").exists());
    assert!(!staged.workspace().join("private").exists());
}

fn run_git(directory: &Path, args: &[&str]) {
    let status = git_status(directory, args);
    assert!(status.success(), "git {args:?} failed with {status}");
}

fn git_status(directory: &Path, args: &[&str]) -> std::process::ExitStatus {
    Command::new("git")
        .args(args)
        .current_dir(directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap()
}

fn git_output(directory: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8(output.stdout).unwrap()
}
