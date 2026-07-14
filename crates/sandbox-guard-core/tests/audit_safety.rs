#![cfg(unix)]

use std::fs;

use sandbox_guard_core::{CompiledPolicy, ResourceLimitRecord, RunRecord, Stage, StageOptions};

#[test]
fn persisted_run_audit_never_contains_a_forwarded_secret_value() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("README.md"), "public\n").unwrap();

    let policy = CompiledPolicy::builtin().unwrap();
    let mut options = StageOptions::new(source.path(), policy);
    options.synthetic_git = false;
    let mut stage = Stage::build(options).unwrap();

    let secret_name = "VENDOR_TOKEN";
    let secret_value = "audit-must-not-contain-5c0de6a1";
    let forwarded_environment = [(secret_name.to_owned(), secret_value.to_owned())];
    stage.manifest_mut().run = Some(RunRecord {
        backend: "LinuxBwrap".to_owned(),
        network: "denied".to_owned(),
        tool: "vendor-cli".to_owned(),
        forwarded_environment_names: forwarded_environment
            .iter()
            .map(|(name, _)| name.clone())
            .collect(),
        allowed_egress_hosts: vec![],
        egress_audit: vec![],
        resource_limits: ResourceLimitRecord {
            memory_bytes: 1024,
            max_file_bytes: 1024,
            cpu_seconds: 60,
            open_files: 64,
            max_processes: 16,
            cpu_percent: 100,
        },
        cgroup_enforced: false,
        seccomp_enforced: true,
        exit_code: Some(0),
        success: true,
    });

    let audit_dir = tempfile::tempdir().unwrap();
    let destination = audit_dir.path().join("run.json");
    stage.persist_audit(&destination).unwrap();
    let bytes = fs::read(&destination).unwrap();

    assert!(
        bytes
            .windows(secret_name.len())
            .any(|part| part == secret_name.as_bytes()),
        "the audit should identify which environment variable was forwarded"
    );
    assert!(
        !bytes
            .windows(secret_value.len())
            .any(|part| part == secret_value.as_bytes()),
        "the audit leaked a forwarded environment value"
    );
}
