//! Repository CI/release policy checks: every GitHub Actions workflow must
//! pin third-party actions to immutable full commit SHAs, declare explicit
//! least-privilege permissions, and avoid the `pull_request_target` trigger.

use std::fs;
use std::path::PathBuf;

fn workflow_files() -> Vec<(PathBuf, String)> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut found = Vec::new();
    for entry in fs::read_dir(&directory).expect("read .github/workflows") {
        let path = entry.expect("read workflow directory entry").path();
        let is_workflow = path
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml");
        if is_workflow {
            let content = fs::read_to_string(&path).expect("read workflow file");
            found.push((path, content));
        }
    }
    assert!(!found.is_empty(), "no workflow files found");
    found
}

#[test]
fn workflow_actions_are_pinned_to_full_commit_shas() {
    for (path, content) in workflow_files() {
        for line in content.lines() {
            let Some(reference) = line.trim().strip_prefix("- uses:").map(str::trim) else {
                continue;
            };
            let reference = reference
                .split('#')
                .next()
                .expect("split always yields one item")
                .trim();
            if reference.starts_with("./") {
                continue;
            }
            let (_, pinned) = reference
                .split_once('@')
                .unwrap_or_else(|| panic!("{}: unpinned action {reference:?}", path.display()));
            assert!(
                pinned.len() == 40 && pinned.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{}: action {reference:?} must be pinned to a full 40-hex commit SHA",
                path.display()
            );
        }
    }
}

#[test]
fn workflows_declare_top_level_permissions() {
    for (path, content) in workflow_files() {
        assert!(
            content.lines().any(|line| line == "permissions:"),
            "{}: missing an explicit top-level permissions block",
            path.display()
        );
    }
}

#[test]
fn release_publication_requires_a_tag_push_event() {
    // Regression guard for the write-scoped publish job: workflow_dispatch
    // may target a tag ref, so a ref-type check alone is not sufficient.
    // Publication must be double-gated on the push event, both where
    // preflight computes the publish output and in the publish job's own
    // condition.
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml");
    let content = fs::read_to_string(&path).expect("read release workflow");
    let preflight_gate = r#"if [ "${GITHUB_EVENT_NAME}" = "push" ]; then"#;
    assert!(
        content.contains(preflight_gate),
        "{}: preflight must set publish=true only for push events",
        path.display()
    );
    let job_gate = "if: needs.preflight.outputs.publish == 'true' && github.event_name == 'push'";
    assert!(
        content.contains(job_gate),
        "{}: the publish job must independently require a push event",
        path.display()
    );
    assert_eq!(
        content.matches("publish=true").count(),
        1,
        "{}: publish=true must appear exactly once, inside the push-event gate",
        path.display()
    );
}

#[test]
fn workflows_do_not_use_pull_request_target() {
    for (path, content) in workflow_files() {
        assert!(
            !content.contains("pull_request_target"),
            "{}: pull_request_target grants secrets to untrusted pull requests",
            path.display()
        );
    }
}
