use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use thiserror::Error;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_TLS_RECORD_BYTES: usize = 64 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_APPROVAL_PROMPTS: u64 = 16;
// Native dialogs give up after 60 seconds. Leave transport headroom so the explicit denial can
// still reach the proxy instead of becoming a stale response for a later request.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(75);

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub socket: PathBuf,
    pub audit_log: PathBuf,
    pub allow_hosts: Vec<String>,
    pub allow_port: u16,
    pub connect_timeout: Duration,
    pub approval_stdio: bool,
}

pub fn run_proxy(config: ProxyConfig) -> Result<(), ProxyError> {
    #[cfg(target_os = "linux")]
    {
        // Terminate a guest/host proxy if its trusted launcher disappears unexpectedly.
        // SAFETY: prctl has no pointer arguments for PR_SET_PDEATHSIG.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) } != 0 {
            return Err(ProxyError::Connection(io::Error::last_os_error()));
        }
    }
    if config.allow_hosts.is_empty() {
        return Err(ProxyError::EmptyAllowlist);
    }
    let allowlist = config
        .allow_hosts
        .iter()
        .map(|host| AllowedHost::parse(host))
        .collect::<Result<Vec<_>, _>>()?;
    validate_private_parent(&config.socket)?;
    validate_private_parent(&config.audit_log)?;
    if fs::symlink_metadata(&config.socket).is_ok() {
        return Err(ProxyError::SocketExists(config.socket));
    }

    let audit = OpenOptions::new()
        .create_new(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&config.audit_log)
        .map_err(|source| ProxyError::Io {
            operation: "create proxy audit log",
            path: config.audit_log.clone(),
            source,
        })?;
    // Publish the socket only after every other startup step succeeds. Runners use its presence as
    // the readiness signal and must never mistake a half-initialized proxy for a live one.
    // SAFETY: the proxy is single-threaded during initialization and intentionally retains this
    // restrictive umask for all later audit-related work.
    unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(&config.socket).map_err(|source| ProxyError::Io {
        operation: "bind proxy socket",
        path: config.socket.clone(),
        source,
    })?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o600)).map_err(|source| {
        ProxyError::Io {
            operation: "secure proxy socket",
            path: config.socket.clone(),
            source,
        }
    })?;
    let shared = Arc::new(ProxyState {
        allowlist,
        allow_port: config.allow_port,
        connect_timeout: config.connect_timeout,
        approval: config.approval_stdio.then(ApprovalBroker::stdio),
        audit: Mutex::new(audit),
        active_connections: AtomicUsize::new(0),
    });

    for connection in listener.incoming() {
        let stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(ProxyError::Io {
                    operation: "accept proxy connection",
                    path: config.socket.clone(),
                    source: error,
                });
            }
        };
        let state = Arc::clone(&shared);
        if state.active_connections.fetch_add(1, Ordering::AcqRel) >= MAX_CONCURRENT_CONNECTIONS {
            state.active_connections.fetch_sub(1, Ordering::AcqRel);
            drop(stream);
            continue;
        }
        thread::spawn(move || {
            let _ = handle_connection(stream, &state);
            state.active_connections.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

struct ProxyState {
    allowlist: Vec<AllowedHost>,
    allow_port: u16,
    connect_timeout: Duration,
    approval: Option<ApprovalBroker>,
    audit: Mutex<File>,
    active_connections: AtomicUsize,
}

fn handle_connection(mut client: UnixStream, state: &ProxyState) -> Result<(), ProxyError> {
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(ProxyError::Connection)?;
    client
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(ProxyError::Connection)?;
    let header = read_http_header(&mut client)?;
    let first_line = header
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or(ProxyError::InvalidRequest)?;
    let first_line = std::str::from_utf8(first_line)
        .map_err(|_| ProxyError::InvalidRequest)?
        .trim_end_matches(['\r', '\n']);
    let mut fields = first_line.split_ascii_whitespace();
    let method = fields.next().ok_or(ProxyError::InvalidRequest)?;
    let authority = fields.next().ok_or(ProxyError::InvalidRequest)?;
    let version = fields.next().ok_or(ProxyError::InvalidRequest)?;
    if fields.next().is_some() || method != "CONNECT" || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        reject(&mut client, "CONNECT required")?;
        return Err(ProxyError::InvalidRequest);
    }
    let (host, port) = parse_authority(authority)?;
    if port != state.allow_port {
        reject(&mut client, "destination denied")?;
        return Err(ProxyError::DestinationDenied { host, port });
    }
    let allowlisted = state.allowlist.iter().any(|entry| entry.matches(&host));
    let approved = if allowlisted {
        true
    } else if let Some(approval) = &state.approval {
        approval.request(&host, port)?.is_allowed()
    } else {
        false
    };
    if !approved {
        reject(&mut client, "destination denied")?;
        return Err(ProxyError::DestinationDenied { host, port });
    }

    let addresses = resolve_public(&host, port)?;
    let mut upstream = connect_any(&addresses, state.connect_timeout)?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(ProxyError::Connection)?;

    let (client_hello, sni) = read_tls_client_hello(&mut client)?;
    if sni != host {
        return Err(ProxyError::SniMismatch {
            requested: host,
            observed: sni,
        });
    }
    upstream
        .write_all(&client_hello)
        .map_err(ProxyError::Connection)?;
    upstream
        .set_read_timeout(Some(TUNNEL_IDLE_TIMEOUT))
        .map_err(ProxyError::Connection)?;
    upstream
        .set_write_timeout(Some(TUNNEL_IDLE_TIMEOUT))
        .map_err(ProxyError::Connection)?;
    client
        .set_read_timeout(Some(TUNNEL_IDLE_TIMEOUT))
        .map_err(ProxyError::Connection)?;
    client
        .set_write_timeout(Some(TUNNEL_IDLE_TIMEOUT))
        .map_err(ProxyError::Connection)?;
    record_destination(&state.audit, &sni, port)?;
    tunnel(client, upstream)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalDecision {
    Deny,
    AllowOnce,
    AllowSession,
}

impl ApprovalDecision {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "DENY" => Some(Self::Deny),
            "ALLOW_ONCE" => Some(Self::AllowOnce),
            "ALLOW_SESSION" => Some(Self::AllowSession),
            _ => None,
        }
    }

    fn is_allowed(self) -> bool {
        matches!(self, Self::AllowOnce | Self::AllowSession)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApprovalResponse {
    id: u64,
    decision: ApprovalDecision,
}

fn parse_approval_response(line: &str) -> Option<ApprovalResponse> {
    let mut fields = line.trim_end_matches(['\r', '\n']).split('\t');
    if fields.next()? != "DECISION" {
        return None;
    }
    let id = fields.next()?.parse().ok()?;
    let decision = ApprovalDecision::parse(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    Some(ApprovalResponse { id, decision })
}

struct ApprovalBroker {
    prompt_lock: Mutex<()>,
    session_hosts: Mutex<BTreeSet<(String, u16)>>,
    responses: Mutex<mpsc::Receiver<ApprovalResponse>>,
    output: Mutex<Box<dyn Write + Send>>,
    next_id: AtomicU64,
}

impl ApprovalBroker {
    fn stdio() -> Self {
        Self::with_io(io::stdin(), io::stdout())
    }

    fn with_io<R, W>(input: R, output: W) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(64);
        thread::spawn(move || {
            for line in BufReader::new(input).lines() {
                let Ok(line) = line else {
                    break;
                };
                if let Some(response) = parse_approval_response(&line)
                    && sender.send(response).is_err()
                {
                    break;
                }
            }
        });
        Self {
            prompt_lock: Mutex::new(()),
            session_hosts: Mutex::new(BTreeSet::new()),
            responses: Mutex::new(receiver),
            output: Mutex::new(Box::new(output)),
            next_id: AtomicU64::new(1),
        }
    }

    fn request(&self, host: &str, port: u16) -> Result<ApprovalDecision, ProxyError> {
        if self.session_contains(host, port)? {
            return Ok(ApprovalDecision::AllowSession);
        }
        let _prompt = self
            .prompt_lock
            .lock()
            .map_err(|_| ProxyError::ApprovalUnavailable)?;
        if self.session_contains(host, port)? {
            return Ok(ApprovalDecision::AllowSession);
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if id > MAX_APPROVAL_PROMPTS {
            return Ok(ApprovalDecision::Deny);
        }
        {
            let mut output = self
                .output
                .lock()
                .map_err(|_| ProxyError::ApprovalUnavailable)?;
            writeln!(output, "REQUEST\t{id}\t{host}\t{port}").map_err(ProxyError::Connection)?;
            output.flush().map_err(ProxyError::Connection)?;
        }

        let deadline = Instant::now() + APPROVAL_TIMEOUT;
        let receiver = self
            .responses
            .lock()
            .map_err(|_| ProxyError::ApprovalUnavailable)?;
        let decision = loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break ApprovalDecision::Deny;
            };
            match receiver.recv_timeout(remaining) {
                Ok(response) if response.id == id => break response.decision,
                Ok(_) => continue,
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
                    break ApprovalDecision::Deny;
                }
            }
        };
        if decision == ApprovalDecision::AllowSession {
            self.session_hosts
                .lock()
                .map_err(|_| ProxyError::ApprovalUnavailable)?
                .insert((host.to_owned(), port));
        }
        Ok(decision)
    }

    fn session_contains(&self, host: &str, port: u16) -> Result<bool, ProxyError> {
        Ok(self
            .session_hosts
            .lock()
            .map_err(|_| ProxyError::ApprovalUnavailable)?
            .contains(&(host.to_owned(), port)))
    }
}

fn read_http_header(stream: &mut UnixStream) -> Result<Vec<u8>, ProxyError> {
    let mut result = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    while result.len() < MAX_HEADER_BYTES {
        read_exact_before(stream, &mut byte, deadline)?;
        result.push(byte[0]);
        if result.ends_with(b"\r\n\r\n") {
            return Ok(result);
        }
    }
    Err(ProxyError::HeaderTooLarge)
}

fn reject(stream: &mut UnixStream, reason: &str) -> Result<(), ProxyError> {
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        reason.len(),
        reason
    );
    stream
        .write_all(response.as_bytes())
        .map_err(ProxyError::Connection)
}

fn parse_authority(authority: &str) -> Result<(String, u16), ProxyError> {
    if authority.starts_with('[') {
        return Err(ProxyError::InvalidAuthority(authority.to_owned()));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| ProxyError::InvalidAuthority(authority.to_owned()))?;
    if host.contains(':') {
        return Err(ProxyError::InvalidAuthority(authority.to_owned()));
    }
    let host = normalize_hostname(host)?;
    let port = port
        .parse::<u16>()
        .map_err(|_| ProxyError::InvalidAuthority(authority.to_owned()))?;
    Ok((host, port))
}

fn normalize_hostname(host: &str) -> Result<String, ProxyError> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(ProxyError::InvalidHostname(host));
    }
    Ok(host)
}

#[derive(Debug)]
enum AllowedHost {
    Exact(String),
    Subdomains(String),
}

impl AllowedHost {
    fn parse(value: &str) -> Result<Self, ProxyError> {
        if let Some(suffix) = value.strip_prefix("*.") {
            Ok(Self::Subdomains(normalize_hostname(suffix)?))
        } else {
            Ok(Self::Exact(normalize_hostname(value)?))
        }
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => host == expected,
            Self::Subdomains(suffix) => {
                host.len() > suffix.len()
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
        }
    }
}

fn resolve_public(host: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|source| ProxyError::Resolve {
            host: host.to_owned(),
            source,
        })?;
    let mut public = Vec::new();
    for address in addresses {
        if is_public_ip(address.ip()) && !public.contains(&address) {
            public.push(address);
        }
    }
    if public.is_empty() {
        Err(ProxyError::NoPublicAddress(host.to_owned()))
    } else {
        Ok(public)
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    let in_prefix = |network: Ipv4Addr, prefix: u32| {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        value & mask == u32::from(network) & mask
    };
    ![
        (Ipv4Addr::new(0, 0, 0, 0), 8),
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 0, 0, 0), 24),
        (Ipv4Addr::new(192, 0, 2, 0), 24),
        (Ipv4Addr::new(192, 88, 99, 0), 24),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(198, 18, 0, 0), 15),
        (Ipv4Addr::new(198, 51, 100, 0), 24),
        (Ipv4Addr::new(203, 0, 113, 0), 24),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(240, 0, 0, 0), 4),
    ]
    .iter()
    .any(|(network, prefix)| in_prefix(*network, *prefix))
        && ip != Ipv4Addr::BROADCAST
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let octets = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // Deprecated IPv4-compatible addresses can otherwise encode private IPv4 destinations.
        || octets[..12] == [0; 12]
        // NAT64 prefixes can also encode private IPv4 destinations.
        || octets[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
        || octets[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]
        // Discard-only and transition prefixes are not ordinary public service addresses.
        || octets[..8] == [0x01, 0x00, 0, 0, 0, 0, 0, 0]
        || octets[..2] == [0x20, 0x02]
        || octets[..4] == [0x20, 0x01, 0x00, 0x00]
        || octets[0] & 0xfe == 0xfc
        || (octets[0] == 0xfe && octets[1] & 0xc0 == 0x80)
        || (octets[0] == 0xfe && octets[1] & 0xc0 == 0xc0)
        || (octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8)
        || (octets[0] == 0x3f && octets[1] & 0xf0 == 0xf0))
}

fn connect_any(addresses: &[SocketAddr], timeout: Duration) -> Result<TcpStream, ProxyError> {
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(ProxyError::Connection(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no upstream address")
    })))
}

fn read_tls_client_hello(stream: &mut UnixStream) -> Result<(Vec<u8>, String), ProxyError> {
    let mut header = [0_u8; 5];
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    read_exact_before(stream, &mut header, deadline)?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[0] != 22 || header[1] != 3 || length == 0 || length > MAX_TLS_RECORD_BYTES {
        return Err(ProxyError::TlsRequired);
    }
    let mut record = Vec::with_capacity(5 + length);
    record.extend_from_slice(&header);
    record.resize(5 + length, 0);
    read_exact_before(stream, &mut record[5..], deadline)?;
    let sni = parse_client_hello_sni(&record[5..])?;
    Ok((record, sni))
}

fn read_exact_before(
    stream: &mut UnixStream,
    mut destination: &mut [u8],
    deadline: Instant,
) -> Result<(), ProxyError> {
    while !destination.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ProxyError::HandshakeTimeout)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(ProxyError::Connection)?;
        match stream.read(destination) {
            Ok(0) => {
                return Err(ProxyError::Connection(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            Ok(read) => destination = &mut destination[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ProxyError::HandshakeTimeout);
            }
            Err(error) => return Err(ProxyError::Connection(error)),
        }
    }
    Ok(())
}

fn parse_client_hello_sni(payload: &[u8]) -> Result<String, ProxyError> {
    let mut cursor = Cursor::new(payload);
    if cursor.byte()? != 1 {
        return Err(ProxyError::TlsRequired);
    }
    let hello_length = cursor.u24()?;
    let hello = cursor.take(hello_length)?;
    let mut cursor = Cursor::new(hello);
    cursor.take(2 + 32)?;
    let session = cursor.byte()? as usize;
    cursor.take(session)?;
    let ciphers = cursor.u16()? as usize;
    cursor.take(ciphers)?;
    let compression = cursor.byte()? as usize;
    cursor.take(compression)?;
    let extensions_length = cursor.u16()? as usize;
    let extensions = cursor.take(extensions_length)?;
    let mut extensions = Cursor::new(extensions);
    while extensions.remaining() > 0 {
        let kind = extensions.u16()?;
        let length = extensions.u16()? as usize;
        let body = extensions.take(length)?;
        if kind != 0 {
            continue;
        }
        let mut names = Cursor::new(body);
        let list_length = names.u16()? as usize;
        let list = names.take(list_length)?;
        let mut list = Cursor::new(list);
        while list.remaining() > 0 {
            let name_type = list.byte()?;
            let name_length = list.u16()? as usize;
            let name = list.take(name_length)?;
            if name_type == 0 {
                let name = std::str::from_utf8(name).map_err(|_| ProxyError::InvalidTlsHello)?;
                return normalize_hostname(name);
            }
        }
    }
    Err(ProxyError::MissingSni)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn byte(&mut self) -> Result<u8, ProxyError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProxyError> {
        let value = self.take(2)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }

    fn u24(&mut self) -> Result<usize, ProxyError> {
        let value = self.take(3)?;
        Ok(((value[0] as usize) << 16) | ((value[1] as usize) << 8) | value[2] as usize)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProxyError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ProxyError::InvalidTlsHello)?;
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }
}

fn record_destination(audit: &Mutex<File>, host: &str, port: u16) -> Result<(), ProxyError> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let mut audit = audit.lock().map_err(|_| ProxyError::AuditPoisoned)?;
    writeln!(audit, "{timestamp}\t{host}:{port}").map_err(ProxyError::Connection)?;
    audit.flush().map_err(ProxyError::Connection)
}

fn tunnel(client: UnixStream, upstream: TcpStream) -> Result<(), ProxyError> {
    let mut client_read = client.try_clone().map_err(ProxyError::Connection)?;
    let mut upstream_write = upstream.try_clone().map_err(ProxyError::Connection)?;
    let forward = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let mut upstream_read = upstream;
    let mut client_write = client;
    let reverse = io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    reverse.map_err(ProxyError::Connection)?;
    forward
        .join()
        .map_err(|_| ProxyError::RelayPanicked)?
        .map_err(ProxyError::Connection)?;
    Ok(())
}

fn validate_private_parent(path: &Path) -> Result<(), ProxyError> {
    let parent = path
        .parent()
        .ok_or_else(|| ProxyError::UnsafeParent(path.to_path_buf()))?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| ProxyError::Io {
        operation: "inspect runtime directory",
        path: parent.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProxyError::UnsafeParent(parent.to_path_buf()));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("controlled egress requires at least one allowed host")]
    EmptyAllowlist,
    #[error("invalid allowed hostname {0:?}")]
    InvalidHostname(String),
    #[error("invalid CONNECT authority {0:?}")]
    InvalidAuthority(String),
    #[error("invalid HTTP proxy request")]
    InvalidRequest,
    #[error("proxy request header exceeded the limit")]
    HeaderTooLarge,
    #[error("proxy handshake exceeded the wall-clock deadline")]
    HandshakeTimeout,
    #[error("destination {host}:{port} is not allowlisted")]
    DestinationDenied { host: String, port: u16 },
    #[error("failed to resolve {host}: {source}")]
    Resolve {
        host: String,
        #[source]
        source: io::Error,
    },
    #[error("{0} did not resolve to a permitted public address")]
    NoPublicAddress(String),
    #[error("CONNECT tunnel must begin with a TLS ClientHello")]
    TlsRequired,
    #[error("invalid TLS ClientHello")]
    InvalidTlsHello,
    #[error("TLS ClientHello did not contain SNI")]
    MissingSni,
    #[error("TLS SNI {observed:?} did not match CONNECT host {requested:?}")]
    SniMismatch { requested: String, observed: String },
    #[error("proxy socket already exists: {0}")]
    SocketExists(PathBuf),
    #[error("runtime path has an unsafe parent: {0}")]
    UnsafeParent(PathBuf),
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("proxy connection failed: {0}")]
    Connection(io::Error),
    #[error("proxy audit lock was poisoned")]
    AuditPoisoned,
    #[error("interactive egress approval channel is unavailable")]
    ApprovalUnavailable,
    #[error("proxy relay thread panicked")]
    RelayPanicked,
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};

    use super::*;

    #[test]
    fn wildcard_matches_subdomains_but_not_the_apex_or_suffix_tricks() {
        let allowed = AllowedHost::parse("*.example.com").unwrap();
        assert!(allowed.matches("api.example.com"));
        assert!(allowed.matches("nested.api.example.com"));
        assert!(!allowed.matches("example.com"));
        assert!(!allowed.matches("attackerexample.com"));
    }

    #[test]
    fn rejects_private_link_local_metadata_and_documentation_addresses() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::192.168.1.1",
            "64:ff9b::a00:1",
            "64:ff9b:1::a00:1",
            "100::1",
            "2002:0a00:0001::1",
            "3fff::1",
            "2001::1",
            "240.0.0.1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn authority_parser_rejects_injection_and_missing_ports() {
        assert_eq!(
            parse_authority("api.example.com:443").unwrap(),
            ("api.example.com".to_owned(), 443)
        );
        assert!(parse_authority("api.example.com").is_err());
        assert!(parse_authority("api.example.com:443:80").is_err());
        assert!(parse_authority("api.example.com%0d:443").is_err());
    }

    #[test]
    fn approval_protocol_rejects_ambiguous_or_unknown_decisions() {
        assert_eq!(
            parse_approval_response("DECISION\t7\tALLOW_SESSION\n"),
            Some(ApprovalResponse {
                id: 7,
                decision: ApprovalDecision::AllowSession,
            })
        );
        assert!(parse_approval_response("DECISION\t7\tALLOW_ALWAYS").is_none());
        assert!(parse_approval_response("DECISION\t7\tDENY\textra").is_none());
        assert!(parse_approval_response("REQUEST\t7\tDENY").is_none());
    }

    #[test]
    fn session_approval_is_applied_once_then_cached_for_the_exact_host() {
        let (mut host, proxy) = UnixStream::pair().unwrap();
        let broker = Arc::new(ApprovalBroker::with_io(proxy.try_clone().unwrap(), proxy));
        let request_broker = Arc::clone(&broker);
        let request = thread::spawn(move || request_broker.request("docs.rs", 443).unwrap());

        let mut line = String::new();
        BufReader::new(host.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "REQUEST\t1\tdocs.rs\t443\n");
        host.write_all(b"DECISION\t1\tALLOW_SESSION\n").unwrap();
        assert_eq!(request.join().unwrap(), ApprovalDecision::AllowSession);

        assert_eq!(
            broker.request("docs.rs", 443).unwrap(),
            ApprovalDecision::AllowSession
        );
    }

    #[test]
    fn approval_prompt_budget_fails_closed_without_emitting_another_request() {
        let (mut host, proxy) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let broker = ApprovalBroker::with_io(proxy.try_clone().unwrap(), proxy);
        broker
            .next_id
            .store(MAX_APPROVAL_PROMPTS + 1, Ordering::Relaxed);

        assert_eq!(
            broker.request("docs.rs", 443).unwrap(),
            ApprovalDecision::Deny
        );
        let mut unexpected = [0_u8; 1];
        assert!(host.read(&mut unexpected).is_err());
    }

    #[test]
    fn extracts_sni_only_from_the_declared_client_hello() {
        let hostname = b"api.example.com";
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&(hostname.len() as u16 + 3).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        server_name.extend_from_slice(hostname);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name);

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303_u16.to_be_bytes());
        hello.extend_from_slice(&[0_u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2_u16.to_be_bytes());
        hello.extend_from_slice(&0x1301_u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let hello_len = hello.len();
        let mut payload = vec![
            1,
            ((hello_len >> 16) & 0xff) as u8,
            ((hello_len >> 8) & 0xff) as u8,
            (hello_len & 0xff) as u8,
        ];
        payload.extend_from_slice(&hello);
        assert_eq!(parse_client_hello_sni(&payload).unwrap(), "api.example.com");

        payload[3] = 4;
        assert!(parse_client_hello_sni(&payload).is_err());
    }
}
