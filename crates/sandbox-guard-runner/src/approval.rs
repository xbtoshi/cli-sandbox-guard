use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

#[cfg(target_os = "macos")]
const MACOS_APPROVAL_SCRIPT: &str = r#"
on run argv
    set destination to item 1 of argv
    set messageText to "An isolated tool requested HTTPS access to " & destination & ".\n\nAllowing access may disclose workspace data available to the tool. Only approve destinations you expected."
    try
        set dialogResult to display dialog messageText with title "Sandbox Guard Network Approval" buttons {"Deny", "Allow Once", "Allow for Session"} default button "Deny" cancel button "Deny" with icon caution giving up after 60
        if gave up of dialogResult then return "Deny"
        return button returned of dialogResult
    on error number -128
        return "Deny"
    end try
end run
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalDecision {
    Deny,
    AllowOnce,
    AllowSession,
}

impl ApprovalDecision {
    fn protocol(self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::AllowOnce => "ALLOW_ONCE",
            Self::AllowSession => "ALLOW_SESSION",
        }
    }

    fn audit_name(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::AllowOnce => "allow-once",
            Self::AllowSession => "allow-session",
        }
    }

    fn from_dialog_output(value: &str) -> Self {
        match value {
            "Allow Once" => Self::AllowOnce,
            "Allow for Session" => Self::AllowSession,
            _ => Self::Deny,
        }
    }
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
    pub(crate) fn start<R, W>(requests: R, responses: W) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        Self {
            thread: Some(thread::spawn(move || {
                run_controller(requests, responses, native_approval)
            })),
        }
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
            break;
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
        "An isolated tool requested HTTPS access to {host}:{port}.\n\nAllowing access may disclose workspace data available to the tool."
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
            "Allow Once",
            "FALSE",
            "Allow for Session",
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
