use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{EnvironmentEntry, PROXY_ENVIRONMENT, ResourceLimits};

const MAX_CONCURRENT_RELAYS: usize = 64;
#[cfg(any(target_os = "linux", test))]
const SAFE_BASE_ENVIRONMENT: &[&str] = &["HOME", "PATH", "LANG", "TERM"];

#[derive(Debug, Clone)]
pub struct SupervisedCommand {
    pub command: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone)]
pub struct SuperviseConfig {
    pub environment_file: PathBuf,
    pub proxy_socket: Option<PathBuf>,
    pub limits: ResourceLimits,
    pub preflight: Option<SupervisedCommand>,
    pub command: OsString,
    pub args: Vec<OsString>,
}

pub fn supervise(config: SuperviseConfig) -> Result<ExitStatus, SupervisorError> {
    let environment = read_environment(&config.environment_file)?;
    #[cfg(target_os = "linux")]
    protect_supervisor()?;
    let relay = if let Some(socket) = &config.proxy_socket {
        Some(start_relay(socket.clone())?)
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    {
        if let Some(preflight) = &config.preflight {
            let status =
                run_supervised_command(preflight, &environment, relay.as_ref(), config.limits)?;
            if !status.success() {
                drop(relay);
                return Ok(status);
            }
        }
        let command = SupervisedCommand {
            command: config.command,
            args: config.args,
        };
        let status = run_supervised_command(&command, &environment, relay.as_ref(), config.limits)?;
        drop(relay);
        Ok(status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (environment, relay, config);
        Err(SupervisorError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
fn run_supervised_command(
    spec: &SupervisedCommand,
    environment: &[EnvironmentEntry],
    relay: Option<&Relay>,
    limits: ResourceLimits,
) -> Result<ExitStatus, SupervisorError> {
    let mut command = Command::new(&spec.command);
    command.args(&spec.args).env_clear();
    for name in SAFE_BASE_ENVIRONMENT {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(relay) = relay {
        let proxy = format!("http://127.0.0.1:{}", relay.port);
        for name in PROXY_ENVIRONMENT {
            command.env(name, &proxy);
        }
        command.env("NO_PROXY", "").env("no_proxy", "");
    }
    for entry in environment {
        command.env(&entry.name, &entry.value);
    }
    configure_linux_child(&mut command, limits);
    command.status().map_err(|source| SupervisorError::Execute {
        command: spec.command.clone(),
        source,
    })
}

fn read_environment(path: &PathBuf) -> Result<Vec<EnvironmentEntry>, SupervisorError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| SupervisorError::EnvironmentFile {
            path: path.clone(),
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| SupervisorError::EnvironmentFile {
            path: path.clone(),
            source,
        })?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(SupervisorError::UnsafeEnvironmentFile(path.clone()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|source| SupervisorError::EnvironmentFile {
            path: path.clone(),
            source,
        })?;
    let entries: Vec<EnvironmentEntry> =
        serde_json::from_slice(&bytes).map_err(SupervisorError::EnvironmentJson)?;
    for entry in &entries {
        if !safe_environment_name(&entry.name) || entry.value.as_bytes().contains(&0) {
            return Err(SupervisorError::UnsafeEnvironmentName(entry.name.clone()));
        }
    }
    Ok(entries)
}

fn safe_environment_name(name: &str) -> bool {
    let syntactically_valid = !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| match byte {
            b'A'..=b'Z' | b'_' => true,
            b'0'..=b'9' => index > 0,
            _ => false,
        });
    let exact = [
        "PATH", "HOME", "SHELL", "ENV", "BASH_ENV", "CDPATH", "NO_PROXY",
    ];
    let prefixes = [
        "GIT_",
        "LD_",
        "DYLD_",
        "NODE_",
        "PYTHON",
        "PERL5",
        "RUBY",
        "JAVA_",
        "JDK_JAVA_",
        "LUA_",
    ];
    syntactically_valid
        && !exact.contains(&name)
        && !PROXY_ENVIRONMENT.contains(&name)
        && !prefixes.iter().any(|prefix| name.starts_with(prefix))
}

struct Relay {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn start_relay(socket: PathBuf) -> Result<Relay, SupervisorError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(SupervisorError::Relay)?;
    listener
        .set_nonblocking(true)
        .map_err(SupervisorError::Relay)?;
    let port = listener
        .local_addr()
        .map_err(SupervisorError::Relay)?
        .port();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let active = Arc::new(AtomicUsize::new(0));
    let thread = thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((client, _)) => {
                    let socket = socket.clone();
                    let active = Arc::clone(&active);
                    if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONCURRENT_RELAYS {
                        active.fetch_sub(1, Ordering::AcqRel);
                        drop(client);
                        continue;
                    }
                    thread::spawn(move || {
                        if let Ok(upstream) = UnixStream::connect(socket) {
                            let _ = relay_connection(client, upstream);
                        }
                        active.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
    Ok(Relay {
        port,
        stop,
        thread: Some(thread),
    })
}

fn relay_connection(client: TcpStream, upstream: UnixStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let forward = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let mut upstream_read = upstream;
    let mut client_write = client;
    io::copy(&mut upstream_read, &mut client_write)?;
    let _ = client_write.shutdown(Shutdown::Write);
    forward
        .join()
        .map_err(|_| io::Error::other("relay thread panicked"))??;
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_linux_child(command: &mut Command, limits: ResourceLimits) {
    let filter = crate::seccomp::build_filter();
    // SAFETY: the closure performs only raw async-signal-safe syscalls in the post-fork child.
    unsafe {
        command.pre_exec(move || {
            set_limit(libc::RLIMIT_CORE, 0)?;
            set_limit(libc::RLIMIT_NOFILE, limits.open_files)?;
            set_limit(libc::RLIMIT_FSIZE, limits.max_file_bytes)?;
            set_limit(libc::RLIMIT_CPU, limits.cpu_seconds)?;
            set_limit(libc::RLIMIT_AS, limits.memory_bytes)?;
            set_limit(libc::RLIMIT_NPROC, limits.max_processes)?;
            // SAFETY: umask and prctl have no pointer arguments here.
            libc::umask(0o077);
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            crate::seccomp::install_filter(&filter)
        });
    }
}

#[cfg(target_os = "linux")]
fn protect_supervisor() -> Result<(), SupervisorError> {
    // The untrusted child shares the sandbox PID namespace with this trusted supervisor. Keep the
    // parent non-dumpable so /proc/<pid>/mem cannot become a route around the child's seccomp
    // filter on hosts without a restrictive ptrace policy.
    // SAFETY: prctl has no pointer arguments for these operations.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(SupervisorError::Protect(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_limit(resource: libc::__rlimit_resource_t, value: u64) -> io::Result<()> {
    let value: libc::rlim_t = value;
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: limit points to an initialized rlimit for the current child process.
    if unsafe { libc::setrlimit(resource, &limit) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub output: PathBuf,
    pub outside_path: PathBuf,
    pub host_pid: u32,
    pub loopback_port: u16,
    pub forbidden_environment: String,
}

#[derive(Debug, Clone)]
pub struct ControlledProxyProbeConfig {
    pub host_loopback_port: u16,
    pub denied_host: String,
}

pub fn run_controlled_proxy_probe(
    config: ControlledProxyProbeConfig,
) -> Result<(), SupervisorError> {
    let proxy = env::var("HTTPS_PROXY").map_err(|_| SupervisorError::ControlledProxyMissing)?;
    let port = proxy
        .strip_prefix("http://127.0.0.1:")
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| SupervisorError::ControlledProxyInvalid(proxy.clone()))?;
    let host_loopback_hidden = TcpStream::connect_timeout(
        &(Ipv4Addr::LOCALHOST, config.host_loopback_port).into(),
        Duration::from_millis(300),
    )
    .is_err();
    let direct_external_hidden = TcpStream::connect_timeout(
        &(Ipv4Addr::new(1, 1, 1, 1), 443).into(),
        Duration::from_millis(300),
    )
    .is_err();

    let mut stream =
        TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, port).into(), Duration::from_secs(2))
            .map_err(SupervisorError::ControlledProxy)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(SupervisorError::ControlledProxy)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(SupervisorError::ControlledProxy)?;
    write!(
        stream,
        "CONNECT {}:443 HTTP/1.1\r\nHost: {}:443\r\n\r\n",
        config.denied_host, config.denied_host
    )
    .map_err(SupervisorError::ControlledProxy)?;
    let mut response = [0_u8; 256];
    let read = stream
        .read(&mut response)
        .map_err(SupervisorError::ControlledProxy)?;
    let destination_rejected = response[..read].starts_with(b"HTTP/1.1 403 Forbidden\r\n");
    if host_loopback_hidden && direct_external_hidden && destination_rejected {
        Ok(())
    } else {
        Err(SupervisorError::ControlledProxyInvariant {
            host_loopback_hidden,
            direct_external_hidden,
            destination_rejected,
        })
    }
}

pub fn verify_current_cgroup(limits: ResourceLimits) -> Result<(), SupervisorError> {
    let membership =
        fs::read_to_string("/proc/self/cgroup").map_err(SupervisorError::CgroupMembership)?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(SupervisorError::CgroupV2Missing)?
        .trim_start_matches('/');
    let root = PathBuf::from("/sys/fs/cgroup").join(relative);
    let memory = read_cgroup_value(&root, "memory.max")?;
    let swap = read_cgroup_value(&root, "memory.swap.max")?;
    let tasks = read_cgroup_value(&root, "pids.max")?;
    let cpu = read_cgroup_value(&root, "cpu.max")?;
    let memory_matches = memory == limits.memory_bytes.to_string();
    let swap_matches = swap == "0";
    let tasks_matches = tasks == limits.max_processes.to_string();
    let mut cpu_fields = cpu.split_ascii_whitespace();
    let quota = cpu_fields
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    let period = cpu_fields
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    let cpu_matches = quota.zip(period).is_some_and(|(quota, period)| {
        cpu_fields.next().is_none()
            && (quota as u128) * 100 == (limits.cpu_percent as u128) * (period as u128)
    });
    if memory_matches && swap_matches && tasks_matches && cpu_matches {
        Ok(())
    } else {
        Err(SupervisorError::CgroupMismatch {
            expected_memory: limits.memory_bytes,
            observed_memory: memory,
            observed_swap: swap,
            expected_tasks: limits.max_processes,
            observed_tasks: tasks,
            expected_cpu_percent: limits.cpu_percent,
            observed_cpu: cpu,
        })
    }
}

fn read_cgroup_value(root: &Path, name: &'static str) -> Result<String, SupervisorError> {
    let path = root.join(name);
    fs::read_to_string(&path)
        .map(|value| value.trim().to_owned())
        .map_err(|source| SupervisorError::CgroupFile { path, source })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub success: bool,
    pub outside_path_hidden: bool,
    pub host_environment_hidden: bool,
    /// The bwrap launcher process (pid 1 in the sandbox pid namespace) exposes no inherited host
    /// session environment through `/proc/1/environ`.
    pub bwrap_launcher_environment_scrubbed: bool,
    /// Names observed on `/proc/1/environ` that are not part of the fixed clean-launcher allow
    /// list. Diagnostic only; recorded for a failing probe. Names, never values.
    pub bwrap_leaked_environment_names: Vec<String>,
    /// The explicit child environment delivered through bwrap `--setenv` (HOME/PATH/LANG) survives.
    pub child_environment_present: bool,
    pub host_pid_hidden: bool,
    pub host_loopback_hidden: bool,
    pub namespace_escape_blocked: bool,
    pub process_memory_syscall_blocked: bool,
    pub supervisor_memory_protected: bool,
    pub thread_creation_allowed: bool,
    pub core_dumps_disabled: bool,
    pub open_file_limit: u64,
    pub address_space_limit: u64,
    pub file_size_limit: u64,
    pub cpu_time_limit: u64,
    pub process_limit: u64,
}

pub fn run_probe(config: ProbeConfig) -> Result<ProbeReport, SupervisorError> {
    let outside_path_hidden = fs::symlink_metadata(&config.outside_path).is_err();
    let host_environment_hidden = env::var_os(&config.forbidden_environment).is_none();
    #[cfg(target_os = "linux")]
    let (bwrap_launcher_environment_scrubbed, bwrap_leaked_environment_names) =
        inspect_launcher_environment(&config.forbidden_environment);
    #[cfg(not(target_os = "linux"))]
    let (bwrap_launcher_environment_scrubbed, bwrap_leaked_environment_names): (bool, Vec<String>) =
        (false, Vec::new());
    // The clearenv/setenv boundary still delivers the explicit child environment. Proving these
    // remain present guards against an over-broad scrub that would also strip the child's own env.
    let child_environment_present = env::var("HOME").as_deref() == Ok("/home/guard")
        && env::var_os("PATH").is_some()
        && env::var_os("LANG").is_some();
    let host_pid_hidden = !PathBuf::from(format!("/proc/{}", config.host_pid)).exists();
    let host_loopback_hidden = TcpStream::connect_timeout(
        &(Ipv4Addr::LOCALHOST, config.loopback_port).into(),
        Duration::from_millis(300),
    )
    .is_err();
    #[cfg(target_os = "linux")]
    let namespace_escape_blocked = {
        // SAFETY: unshare has no pointer arguments and the seccomp profile must reject it.
        let result = unsafe { libc::unshare(libc::CLONE_NEWNS) };
        result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    };
    #[cfg(not(target_os = "linux"))]
    let namespace_escape_blocked = false;
    #[cfg(target_os = "linux")]
    let process_memory_syscall_blocked = process_memory_read_is_blocked();
    #[cfg(not(target_os = "linux"))]
    let process_memory_syscall_blocked = false;

    let core = get_limit(libc::RLIMIT_CORE)?;
    let nofile = get_limit(libc::RLIMIT_NOFILE)?;
    let address_space = get_limit(libc::RLIMIT_AS)?;
    let file_size = get_limit(libc::RLIMIT_FSIZE)?;
    let cpu_time = get_limit(libc::RLIMIT_CPU)?;
    let processes = get_limit(libc::RLIMIT_NPROC)?;
    // SAFETY: getppid has no preconditions; the probe is a direct child of the supervisor.
    let supervisor_pid = unsafe { libc::getppid() };
    let supervisor_memory_protected = OpenOptions::new()
        .read(true)
        .open(format!("/proc/{supervisor_pid}/mem"))
        .is_err();
    let thread_creation_allowed = thread::Builder::new()
        .name("guard-probe".to_owned())
        .spawn(|| true)
        .ok()
        .and_then(|handle| handle.join().ok())
        .unwrap_or(false);
    let report = ProbeReport {
        success: outside_path_hidden
            && host_environment_hidden
            && bwrap_launcher_environment_scrubbed
            && child_environment_present
            && host_pid_hidden
            && host_loopback_hidden
            && namespace_escape_blocked
            && process_memory_syscall_blocked
            && supervisor_memory_protected
            && thread_creation_allowed
            && core == 0,
        outside_path_hidden,
        host_environment_hidden,
        bwrap_launcher_environment_scrubbed,
        bwrap_leaked_environment_names,
        child_environment_present,
        host_pid_hidden,
        host_loopback_hidden,
        namespace_escape_blocked,
        process_memory_syscall_blocked,
        supervisor_memory_protected,
        thread_creation_allowed,
        core_dumps_disabled: core == 0,
        open_file_limit: nofile,
        address_space_limit: address_space,
        file_size_limit: file_size,
        cpu_time_limit: cpu_time,
        process_limit: processes,
    };
    let bytes = serde_json::to_vec_pretty(&report).map_err(SupervisorError::ProbeJson)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&config.output)
        .map_err(|source| SupervisorError::ProbeOutput {
            path: config.output,
            source,
        })?;
    output
        .write_all(&bytes)
        .map_err(SupervisorError::ProbeWrite)?;
    output.flush().map_err(SupervisorError::ProbeWrite)?;
    Ok(report)
}

/// Inspect the environment of pid 1 in the sandbox pid namespace — the bwrap launcher itself.
///
/// Bubblewrap's `--clearenv` scrubs only the executed child; the launcher survives as pid 1 and
/// its `/proc/1/environ` is readable by the confined tool. With the runner's `env -i` boundary in
/// place, that environ is empty on Linux hosts and carries only a fixed, non-secret `PATH` on the
/// Lima guest. Any other variable name is a leak of the launcher's inherited host environment.
///
/// Returns `(scrubbed, leaked_names)`. An unreadable environ cannot leak and counts as scrubbed.
#[cfg(target_os = "linux")]
fn inspect_launcher_environment(forbidden: &str) -> (bool, Vec<String>) {
    match fs::read("/proc/1/environ") {
        Ok(bytes) => classify_launcher_environment(&bytes, forbidden),
        Err(_) => (true, Vec::new()),
    }
}

/// Names permitted on the bwrap launcher's environment after the `env -i` boundary. The host
/// route leaves it empty; the Lima guest route re-establishes only a fixed, non-secret `PATH`.
#[cfg(any(target_os = "linux", test))]
const LAUNCHER_ALLOWED_ENVIRONMENT_NAMES: &[&str] = &["PATH"];

/// Pure classifier over the raw NUL-separated `environ` bytes. Any name outside the allow list,
/// or the harness-injected `forbidden` sentinel, is reported as an inherited-environment leak.
#[cfg(any(target_os = "linux", test))]
fn classify_launcher_environment(raw: &[u8], forbidden: &str) -> (bool, Vec<String>) {
    let mut leaked: Vec<String> = Vec::new();
    for entry in raw.split(|byte| *byte == 0).filter(|entry| !entry.is_empty()) {
        let name = entry.split(|byte| *byte == b'=').next().unwrap_or(entry);
        let name = String::from_utf8_lossy(name).into_owned();
        if !LAUNCHER_ALLOWED_ENVIRONMENT_NAMES.contains(&name.as_str()) || name == forbidden {
            leaked.push(name);
        }
    }
    leaked.sort();
    leaked.dedup();
    (leaked.is_empty(), leaked)
}

#[cfg(target_os = "linux")]
fn process_memory_read_is_blocked() -> bool {
    let source = [0x5a_u8];
    let mut destination = [0_u8];
    let local = libc::iovec {
        iov_base: destination.as_mut_ptr().cast(),
        iov_len: destination.len(),
    };
    let remote = libc::iovec {
        iov_base: source.as_ptr().cast_mut().cast(),
        iov_len: source.len(),
    };
    // Reading our own memory is permitted without capabilities, so EPERM here specifically proves
    // the installed seccomp rule rather than merely observing Bubblewrap's capability drop.
    // SAFETY: both iovec values refer to valid one-byte buffers for the duration of the syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            libc::getpid(),
            &local as *const libc::iovec,
            1_usize,
            &remote as *const libc::iovec,
            1_usize,
            0_usize,
        )
    };
    result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "linux")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type RlimitResource = libc::c_int;

fn get_limit(resource: RlimitResource) -> Result<u64, SupervisorError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit is a valid writable rlimit structure.
    if unsafe { libc::getrlimit(resource, &mut limit) } != 0 {
        return Err(SupervisorError::Limit(io::Error::last_os_error()));
    }
    Ok(limit.rlim_cur)
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("runtime supervision is supported only on Linux")]
    UnsupportedPlatform,
    #[error("failed to read environment file {path}: {source}")]
    EnvironmentFile { path: PathBuf, source: io::Error },
    #[error("unsafe environment file: {0}")]
    UnsafeEnvironmentFile(PathBuf),
    #[error("invalid environment JSON: {0}")]
    EnvironmentJson(serde_json::Error),
    #[error("unsafe forwarded environment variable {0:?}")]
    UnsafeEnvironmentName(String),
    #[error("failed to start proxy relay: {0}")]
    Relay(io::Error),
    #[error("controlled proxy environment was not installed")]
    ControlledProxyMissing,
    #[error("controlled proxy URL is invalid: {0:?}")]
    ControlledProxyInvalid(String),
    #[error("controlled proxy probe failed: {0}")]
    ControlledProxy(io::Error),
    #[error(
        "controlled proxy invariant failed (host_loopback_hidden={host_loopback_hidden}, direct_external_hidden={direct_external_hidden}, destination_rejected={destination_rejected})"
    )]
    ControlledProxyInvariant {
        host_loopback_hidden: bool,
        direct_external_hidden: bool,
        destination_rejected: bool,
    },
    #[error("failed to read cgroup membership: {0}")]
    CgroupMembership(io::Error),
    #[error("the probe process is not in a cgroup v2 hierarchy")]
    CgroupV2Missing,
    #[error("failed to read cgroup controller file {path}: {source}")]
    CgroupFile { path: PathBuf, source: io::Error },
    #[error(
        "cgroup properties do not match: memory expected {expected_memory}, observed {observed_memory}; swap observed {observed_swap}; tasks expected {expected_tasks}, observed {observed_tasks}; CPU expected {expected_cpu_percent}%, observed {observed_cpu}"
    )]
    CgroupMismatch {
        expected_memory: u64,
        observed_memory: String,
        observed_swap: String,
        expected_tasks: u64,
        observed_tasks: String,
        expected_cpu_percent: u64,
        observed_cpu: String,
    },
    #[error("failed to protect the trusted supervisor: {0}")]
    Protect(io::Error),
    #[error("failed to execute {command:?}: {source}")]
    Execute {
        command: OsString,
        source: io::Error,
    },
    #[error("failed to inspect a resource limit: {0}")]
    Limit(io::Error),
    #[error("failed to serialize the probe report: {0}")]
    ProbeJson(serde_json::Error),
    #[error("failed to create probe output {path}: {source}")]
    ProbeOutput { path: PathBuf, source: io::Error },
    #[error("failed to write probe output: {0}")]
    ProbeWrite(io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_rejects_execution_control_environment_names() {
        for name in [
            "PATH",
            "LD_PRELOAD",
            "GIT_CONFIG_COUNT",
            "PYTHONPATH",
            "HTTPS_PROXY",
        ] {
            assert!(!safe_environment_name(name));
        }
        assert!(safe_environment_name("OPENAI_API_KEY"));
        assert!(SAFE_BASE_ENVIRONMENT.contains(&"TERM"));
    }

    #[test]
    fn launcher_environment_classifier_flags_inherited_host_variables() {
        // Empty environ (host route): fully scrubbed.
        assert_eq!(classify_launcher_environment(b"", "CANARY"), (true, vec![]));

        // Guest route: only the fixed non-secret PATH remains.
        let (scrubbed, leaked) = classify_launcher_environment(
            b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0",
            "CANARY",
        );
        assert!(scrubbed);
        assert!(leaked.is_empty());

        // A regressed launcher leaking inherited host session variables (mirrors the live probe).
        let leaked_environ =
            b"HOME=/home/anton.guest\0USER=anton\0HTTPS_PROXY=http://10.0.0.2:17890\0CANARY=1\0PATH=/bin\0";
        let (scrubbed, leaked) = classify_launcher_environment(leaked_environ, "CANARY");
        assert!(!scrubbed);
        assert_eq!(leaked, vec!["CANARY", "HOME", "HTTPS_PROXY", "USER"]);

        // The sentinel is caught even if it collides with an otherwise-allowed name.
        let (scrubbed, leaked) = classify_launcher_environment(b"PATH=/bin\0", "PATH");
        assert!(!scrubbed);
        assert_eq!(leaked, vec!["PATH"]);
    }

    #[test]
    fn environment_file_values_are_not_command_arguments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("environment.json");
        fs::write(
            &path,
            serde_json::to_vec(&vec![EnvironmentEntry {
                name: "VENDOR_TOKEN".to_owned(),
                value: "not-in-argv".to_owned(),
            }])
            .unwrap(),
        )
        .unwrap();
        let entries = read_environment(&path).unwrap();
        assert_eq!(entries[0].value, "not-in-argv");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_preflight_prevents_the_main_command() {
        let directory = tempfile::tempdir().unwrap();
        let environment = directory.path().join("environment.json");
        fs::write(&environment, b"[]").unwrap();
        let marker = directory.path().join("main-ran");
        let status = supervise(SuperviseConfig {
            environment_file: environment,
            proxy_socket: None,
            limits: ResourceLimits::default(),
            preflight: Some(SupervisedCommand {
                command: OsString::from("/bin/false"),
                args: Vec::new(),
            }),
            command: OsString::from("/usr/bin/touch"),
            args: vec![marker.as_os_str().to_owned()],
        })
        .unwrap();
        assert!(!status.success());
        assert!(!marker.exists());
    }
}
