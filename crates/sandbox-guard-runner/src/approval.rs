use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::RunnerError;

const MAX_DECISION_FILE_BYTES: u64 = 1024 * 1024;

#[cfg(target_os = "macos")]
const MACOS_APPROVAL_SCRIPT: &str = r#"
on run argv
    set destination to item 1 of argv
    set messageText to "An isolated tool requested an HTTPS tunnel to " & destination & ".\n\nSandbox Guard can verify the exact hostname and port. The full URL, HTTP method, headers, and body remain encrypted and are not visible without intercepting TLS.\n\nAllowing access may disclose workspace data available to the tool. Only approve destinations you expect."
    try
        set dialogResult to display dialog messageText with title "Sandbox Guard Network Approval" buttons {"Deny", "Allow Once", "Allow for Session"} default button "Deny" with icon caution giving up after 45
        if gave up of dialogResult then return "Deny"
        set selectedDecision to button returned of dialogResult
        set rememberResult to display dialog "Remember this exact-host decision for future Sandbox Guard sessions?\n\nYou can review or remove remembered choices with guard approvals." with title "Remember Network Decision" buttons {"Not Now", "Remember"} default button "Not Now" with icon caution giving up after 15
        if gave up of rememberResult or button returned of rememberResult is "Not Now" then return selectedDecision
        if selectedDecision is "Deny" then return "Always Deny"
        return "Always Allow"
    on error number -128
        return "Deny"
    end try
end run
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalDecision {
    Deny,
    DenyAlways,
    AllowOnce,
    AllowSession,
    AllowAlways,
}

impl ApprovalDecision {
    fn protocol(self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::DenyAlways => "DENY_ALWAYS",
            Self::AllowOnce => "ALLOW_ONCE",
            Self::AllowSession => "ALLOW_SESSION",
            Self::AllowAlways => "ALLOW_ALWAYS",
        }
    }

    fn audit_name(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::DenyAlways => "deny-always",
            Self::AllowOnce => "allow-once",
            Self::AllowSession => "allow-session",
            Self::AllowAlways => "allow-always",
        }
    }

    fn from_dialog_output(value: &str) -> Self {
        match value {
            "Always Deny" => Self::DenyAlways,
            "Allow Once" => Self::AllowOnce,
            "Allow for Session" => Self::AllowSession,
            "Always Allow" => Self::AllowAlways,
            _ => Self::Deny,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RememberedDecision {
    Allow,
    Deny,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionDocument {
    version: u32,
    #[serde(default)]
    hosts: BTreeMap<String, RememberedDecision>,
}

impl Default for DecisionDocument {
    fn default() -> Self {
        Self {
            version: 1,
            hosts: BTreeMap::new(),
        }
    }
}

struct DecisionStore {
    path: PathBuf,
    document: DecisionDocument,
}

impl DecisionStore {
    fn open(path: PathBuf) -> Result<Self, String> {
        let parent = path
            .parent()
            .ok_or_else(|| "decision store has no parent directory".to_owned())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create decision directory: {error}"))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("secure decision directory: {error}"))?;
        validate_private_directory(parent)?;
        let lock = lock_decision_store(&path)?;
        let document = read_decisions(&path)?;
        drop(lock);
        Ok(Self { path, document })
    }

    fn lookup(&self, host: &str) -> Option<RememberedDecision> {
        self.document.hosts.get(host).copied()
    }

    fn remember(&mut self, host: &str, decision: RememberedDecision) -> Result<(), String> {
        let lock = lock_decision_store(&self.path)?;
        let mut document = read_decisions(&self.path)?;
        document.hosts.insert(host.to_owned(), decision);
        write_decisions(&self.path, &document)?;
        self.document = document;
        drop(lock);
        Ok(())
    }

    fn forget(&mut self, host: &str) -> Result<bool, String> {
        let lock = lock_decision_store(&self.path)?;
        let mut document = read_decisions(&self.path)?;
        let removed = document.hosts.remove(host).is_some();
        if removed {
            write_decisions(&self.path, &document)?;
        }
        self.document = document;
        drop(lock);
        Ok(removed)
    }

    fn clear(&mut self) -> Result<usize, String> {
        let lock = lock_decision_store(&self.path)?;
        let mut document = read_decisions(&self.path)?;
        let removed = document.hosts.len();
        document.hosts.clear();
        if removed > 0 {
            write_decisions(&self.path, &document)?;
        }
        self.document = document;
        drop(lock);
        Ok(removed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberedEgressDecision {
    pub host: String,
    pub allowed: bool,
}

pub fn list_remembered_egress_decisions(
    path: &Path,
) -> Result<Vec<RememberedEgressDecision>, RunnerError> {
    let store = DecisionStore::open(path.to_path_buf()).map_err(decision_store_error)?;
    Ok(store
        .document
        .hosts
        .into_iter()
        .map(|(host, decision)| RememberedEgressDecision {
            host,
            allowed: decision == RememberedDecision::Allow,
        })
        .collect())
}

pub fn forget_remembered_egress_decision(path: &Path, host: &str) -> Result<bool, RunnerError> {
    if !valid_exact_hostname(host) {
        return Err(RunnerError::SetupFailed(format!(
            "invalid exact egress hostname {host:?}"
        )));
    }
    let mut store = DecisionStore::open(path.to_path_buf()).map_err(decision_store_error)?;
    store.forget(host).map_err(decision_store_error)
}

pub fn clear_remembered_egress_decisions(path: &Path) -> Result<usize, RunnerError> {
    let mut store = DecisionStore::open(path.to_path_buf()).map_err(decision_store_error)?;
    store.clear().map_err(decision_store_error)
}

fn decision_store_error(error: String) -> RunnerError {
    RunnerError::SetupFailed(format!("manage remembered egress decisions: {error}"))
}

fn validate_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect decision directory: {error}"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("decision directory is not a private owner-owned directory".to_owned());
    }
    Ok(())
}

fn lock_decision_store(path: &Path) -> Result<File, String> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .map_err(|error| format!("open decision lock: {error}"))?;
    validate_private_file(&file, 0, "decision lock")?;
    // SAFETY: flock receives a valid open file descriptor and does not retain pointers.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "lock decision store: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

fn read_decisions(path: &Path) -> Result<DecisionDocument, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DecisionDocument::default());
        }
        Err(error) => return Err(format!("open decision store: {error}")),
    };
    let length = validate_private_file(&file, MAX_DECISION_FILE_BYTES, "decision store")?;
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read decision store: {error}"))?;
    let document: DecisionDocument =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse decision store: {error}"))?;
    if document.version != 1
        || document
            .hosts
            .keys()
            .any(|host| !valid_exact_hostname(host))
    {
        return Err("decision store contains an unsupported version or invalid host".to_owned());
    }
    Ok(document)
}

fn validate_private_file(file: &File, max_bytes: u64, label: &str) -> Result<u64, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect {label}: {error}"))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > max_bytes
    {
        return Err(format!(
            "{label} is not a private singly linked regular file"
        ));
    }
    Ok(metadata.len())
}

fn write_decisions(path: &Path, document: &DecisionDocument) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "decision store has no parent directory".to_owned())?;
    let temporary = parent.join(format!(".egress-decisions-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|error| format!("create temporary decision store: {error}"))?;
    let write_result = serde_json::to_writer_pretty(&mut file, document)
        .map_err(|error| format!("serialize decision store: {error}"))
        .and_then(|()| {
            file.write_all(b"\n")
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("sync decision store: {error}"))
        });
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("publish decision store: {error}"));
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync decision directory: {error}"))
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot invalidate Rust state.
    unsafe { libc::geteuid() }
}

#[derive(Debug, PartialEq, Eq)]
struct ApprovalRequest {
    id: u64,
    host: String,
    port: u16,
}

pub(crate) struct ApprovalController {
    thread: Option<JoinHandle<Vec<String>>>,
}

impl ApprovalController {
    pub(crate) fn start<R, W>(
        requests: R,
        responses: W,
        store: PathBuf,
    ) -> Result<Self, RunnerError>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let mut store = DecisionStore::open(store).map_err(|error| {
            RunnerError::SetupFailed(format!("open remembered egress decisions: {error}"))
        })?;
        Ok(Self {
            thread: Some(thread::spawn(move || {
                run_controller(requests, responses, |host, port| {
                    if let Some(decision) = store.lookup(host) {
                        return match decision {
                            RememberedDecision::Allow => ApprovalDecision::AllowAlways,
                            RememberedDecision::Deny => ApprovalDecision::DenyAlways,
                        };
                    }
                    let decision = native_approval(host, port);
                    match decision {
                        ApprovalDecision::AllowAlways => {
                            if let Err(error) = store.remember(host, RememberedDecision::Allow) {
                                eprintln!(
                                    "warning: could not remember approval for {host}:{port}; request denied: {error}"
                                );
                                ApprovalDecision::Deny
                            } else {
                                decision
                            }
                        }
                        ApprovalDecision::DenyAlways => {
                            if let Err(error) = store.remember(host, RememberedDecision::Deny) {
                                eprintln!(
                                    "warning: could not remember denial for {host}:{port}: {error}"
                                );
                                ApprovalDecision::Deny
                            } else {
                                decision
                            }
                        }
                        _ => decision,
                    }
                })
            })),
        })
    }

    pub(crate) fn finish(mut self) -> Vec<String> {
        self.thread
            .take()
            .and_then(|thread| thread.join().ok())
            .unwrap_or_default()
    }
}

fn run_controller<R, W, F>(requests: R, mut responses: W, mut prompt: F) -> Vec<String>
where
    R: Read,
    W: Write,
    F: FnMut(&str, u16) -> ApprovalDecision,
{
    let mut audit = Vec::new();
    for line in BufReader::new(requests).lines() {
        let Ok(line) = line else {
            break;
        };
        let Some(request) = parse_request(&line) else {
            continue;
        };
        let decision = prompt(&request.host, request.port);
        if writeln!(
            responses,
            "DECISION\t{}\t{}",
            request.id,
            decision.protocol()
        )
        .and_then(|()| responses.flush())
        .is_err()
        {
            break;
        }
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        audit.push(format!(
            "{timestamp}\t{}:{}\t{}",
            request.host,
            request.port,
            decision.audit_name()
        ));
    }
    audit
}

fn parse_request(line: &str) -> Option<ApprovalRequest> {
    let mut fields = line.trim_end_matches(['\r', '\n']).split('\t');
    if fields.next()? != "REQUEST" {
        return None;
    }
    let id = fields.next()?.parse().ok()?;
    let host = fields.next()?;
    if !valid_exact_hostname(host) {
        return None;
    }
    let port = fields.next()?.parse().ok()?;
    if port != 443 || fields.next().is_some() {
        return None;
    }
    Some(ApprovalRequest {
        id,
        host: host.to_owned(),
        port,
    })
}

fn valid_exact_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(target_os = "macos")]
fn native_approval(host: &str, port: u16) -> ApprovalDecision {
    let destination = format!("{host}:{port}");
    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(MACOS_APPROVAL_SCRIPT)
        .arg("--")
        .arg(destination)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    ApprovalDecision::from_dialog_output(
        output
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .as_deref()
            .unwrap_or_default(),
    )
}

#[cfg(target_os = "linux")]
fn native_approval(host: &str, port: u16) -> ApprovalDecision {
    let Ok(zenity) = which::which("zenity") else {
        eprintln!(
            "warning: denied interactive egress request for {host}:{port}; a trusted native prompt requires zenity"
        );
        return ApprovalDecision::Deny;
    };
    let message = format!(
        "An isolated tool requested an HTTPS tunnel to {host}:{port}.\n\nSandbox Guard can verify the exact hostname and port. The full URL, HTTP method, headers, and body remain encrypted and are not visible without intercepting TLS.\n\nAllowing access may disclose workspace data available to the tool."
    );
    let output = Command::new(zenity)
        .args([
            "--list",
            "--radiolist",
            "--title=Sandbox Guard Network Approval",
            "--column=Select",
            "--column=Decision",
            "TRUE",
            "Deny",
            "FALSE",
            "Always Deny",
            "FALSE",
            "Allow Once",
            "FALSE",
            "Allow for Session",
            "FALSE",
            "Always Allow",
            "--timeout=60",
        ])
        .arg("--text")
        .arg(message)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    ApprovalDecision::from_dialog_output(
        output
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .as_deref()
            .unwrap_or_default(),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn native_approval(_host: &str, _port: u16) -> ApprovalDecision {
    ApprovalDecision::Deny
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn protocol_accepts_only_exact_https_hostnames() {
        assert_eq!(
            parse_request("REQUEST\t7\tdocs.rs\t443"),
            Some(ApprovalRequest {
                id: 7,
                host: "docs.rs".to_owned(),
                port: 443,
            })
        );
        assert!(parse_request("REQUEST\t7\t*.docs.rs\t443").is_none());
        assert!(parse_request("REQUEST\t7\tdocs.rs\t80").is_none());
        assert!(parse_request("REQUEST\t7\tdocs.rs\t443\textra").is_none());
        assert!(parse_request("REQUEST\t7\tDOCS.rs\t443").is_none());
    }

    #[test]
    fn controller_returns_the_scoped_decision_and_records_it() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let audit = run_controller(
            Cursor::new(b"REQUEST\t42\tdocs.rs\t443\n"),
            SharedWriter(Arc::clone(&captured)),
            |host, port| {
                assert_eq!((host, port), ("docs.rs", 443));
                ApprovalDecision::AllowSession
            },
        );
        assert_eq!(
            String::from_utf8(captured.lock().unwrap().clone()).unwrap(),
            "DECISION\t42\tALLOW_SESSION\n"
        );
        assert_eq!(audit.len(), 1);
        assert!(audit[0].ends_with("\tdocs.rs:443\tallow-session"));
    }

    #[test]
    fn unknown_native_dialog_output_fails_closed() {
        assert_eq!(
            ApprovalDecision::from_dialog_output("unexpected"),
            ApprovalDecision::Deny
        );
    }

    #[test]
    fn remembered_exact_host_decisions_are_private_and_reloadable() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("guard-data");
        let path = parent.join("egress-decisions.json");
        let mut store = DecisionStore::open(path.clone()).unwrap();
        assert_eq!(store.lookup("docs.rs"), None);

        store
            .remember("docs.rs", RememberedDecision::Allow)
            .unwrap();
        let store = DecisionStore::open(path.clone()).unwrap();
        assert_eq!(store.lookup("docs.rs"), Some(RememberedDecision::Allow));
        assert_eq!(
            fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::symlink_metadata(parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn unsafe_or_malformed_remembered_decisions_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("egress-decisions.json");
        fs::write(&path, br#"{"version":1,"hosts":{"*.example.com":"allow"}}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(DecisionStore::open(path).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_approval_script_compiles_without_displaying_it() {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new("/usr/bin/osacompile")
            .arg("-o")
            .arg(directory.path().join("approval.scpt"))
            .arg("-e")
            .arg(MACOS_APPROVAL_SCRIPT)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
