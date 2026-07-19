use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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

#[test]
fn corrupt_event_store_exits_nonzero_without_partial_stdout() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let xdg_data = temp.path().join("data");
    fs::create_dir(&home).unwrap();
    let events = guard_data_root(&home, &xdg_data).join("events");
    fs::create_dir_all(&events).unwrap();
    fs::set_permissions(&events, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(events.join("events.json"), b"{corrupt").unwrap();
    fs::set_permissions(
        events.join("events.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_guard"))
        .args(["events", "--json"])
        .env("HOME", &home)
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "corrupt JSON leaked partial stdout"
    );
}
