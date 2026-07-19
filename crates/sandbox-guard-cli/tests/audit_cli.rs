use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{TimeZone, Utc};
use sandbox_guard_core::{
    AuditManifest, ExcludedPath, ExclusionReason, IncludedFile, ResourceLimitRecord, RunRecord,
    StageTotals,
};
use uuid::Uuid;

fn guard_data_root(home: &Path, xdg_data: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let _ = xdg_data;
        home.join("Library")
            .join("Application Support")
            .join("com.xbtoshi.sandbox-guard")
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = home;
        xdg_data.join("sandbox-guard")
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, AuditManifest) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let xdg_data = temp.path().join("data");
    fs::create_dir(&home).unwrap();
    let audit_dir = guard_data_root(&home, &xdg_data).join("audit");
    fs::create_dir_all(&audit_dir).unwrap();
    fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let manifest = AuditManifest {
        schema_version: 1,
        run_id: Uuid::new_v4(),
        created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
        source_root: "/workspace/\u{1b}]0;hostile\u{7}\u{202e}".to_owned(),
        policy_sha256: "00".repeat(32),
        included: vec![IncludedFile {
            path: "src/main.rs".to_owned(),
            bytes: 7,
            sha256: "11".repeat(32),
            executable: false,
        }],
        excluded: vec![ExcludedPath {
            path: ".env".to_owned(),
            reason: ExclusionReason::Policy {
                rule: "*.env".to_owned(),
            },
        }],
        totals: StageTotals {
            included_files: 1,
            included_bytes: 7,
            excluded_paths: 1,
        },
        synthetic_git: true,
        run: Some(RunRecord {
            backend: "LinuxBwrap".to_owned(),
            network: "controlled".to_owned(),
            tool: "hostile\u{202e}tool".to_owned(),
            forwarded_environment_names: vec!["TOKEN_NAME".to_owned()],
            allowed_egress_hosts: vec!["api.example".to_owned()],
            interactive_egress_approval: true,
            egress_audit: vec!["1800000000\tapi.example:443".to_owned()],
            egress_approvals: vec!["1800000000\tapi.example:443\tallow-once".to_owned()],
            clipboard_imports: vec!["sandbox-guard-inputs/image.png".to_owned()],
            resource_limits: ResourceLimitRecord {
                memory_bytes: 1,
                max_file_bytes: 2,
                cpu_seconds: 3,
                open_files: 4,
                max_processes: 5,
                cpu_percent: 6,
            },
            cgroup_enforced: true,
            seccomp_enforced: true,
            exit_code: Some(0),
            success: true,
        }),
    };
    (temp, home, xdg_data, audit_dir, manifest)
}

fn write_manifest(directory: &Path, manifest: &AuditManifest, bytes: &[u8]) {
    let name = format!(
        "{}-{}.json",
        manifest.created_at.format("%Y%m%dT%H%M%SZ"),
        manifest.run_id
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn audit_tail_and_exact_inspection_render_valid_versioned_json() {
    let (_temp, home, xdg_data, audit_dir, manifest) = fixture();
    write_manifest(
        &audit_dir,
        &manifest,
        &serde_json::to_vec(&manifest).unwrap(),
    );

    let tail = Command::new(env!("CARGO_BIN_EXE_guard"))
        .args(["audit", "--tail", "--json"])
        .env("HOME", &home)
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .unwrap();
    assert!(
        tail.status.success(),
        "{}",
        String::from_utf8_lossy(&tail.stderr)
    );
    let tail_json: serde_json::Value = serde_json::from_slice(&tail.stdout).unwrap();
    assert_eq!(tail_json["schema"], 1);
    assert_eq!(
        tail_json["audits"][0]["run_id"],
        manifest.run_id.to_string()
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_guard"))
        .args(["inspect", &manifest.run_id.to_string(), "--json"])
        .env("HOME", &home)
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(inspect_json["schema"], 1);
    assert_eq!(inspect_json["audit"]["run_id"], manifest.run_id.to_string());

    let human = Command::new(env!("CARGO_BIN_EXE_guard"))
        .args(["inspect", &manifest.run_id.to_string()])
        .env("HOME", &home)
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .unwrap();
    assert!(human.status.success());
    let rendered = String::from_utf8(human.stdout).unwrap();
    assert!(!rendered.contains('\u{1b}'));
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains("\\u{1b}"));
    assert!(rendered.contains("\\u{202e}"));
    for expected in [
        "schema: 1",
        "synthetic-git: true",
        "interactive-egress-approval=true",
        "forwarded-environment-name: TOKEN_NAME",
        "allowed-egress: api.example",
        "egress: 1800000000",
        "approval: 1800000000",
        "clipboard-import: sandbox-guard-inputs/image.png",
        "resource-limits: memory-bytes=1",
        "included: src/main.rs bytes=7 executable=false sha256=1111",
        "excluded: .env reason={\\\"kind\\\":\\\"policy\\\"",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected:?} in {rendered}"
        );
    }
}

#[test]
fn corrupt_audit_fails_without_partial_stdout() {
    let (_temp, home, xdg_data, audit_dir, manifest) = fixture();
    write_manifest(&audit_dir, &manifest, b"{corrupt");

    for arguments in [
        vec!["audit".to_owned(), "--tail".to_owned(), "--json".to_owned()],
        vec![
            "inspect".to_owned(),
            manifest.run_id.to_string(),
            "--json".to_owned(),
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_guard"))
            .args(arguments)
            .env("HOME", &home)
            .env("XDG_DATA_HOME", &xdg_data)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "corrupt audit leaked partial stdout"
        );
    }
}
