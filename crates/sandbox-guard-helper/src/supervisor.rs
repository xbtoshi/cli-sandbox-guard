use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{EnvironmentEntry, PROXY_ENVIRONMENT, ResourceLimits};

const MAX_CONCURRENT_RELAYS: usize = 64;

#[derive(Debug, Clone)]
pub struct SuperviseConfig {
    pub environment_file: PathBuf,
    pub proxy_socket: Option<PathBuf>,
    pub limits: ResourceLimits,
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

    let mut command = Command::new(&config.command);
    command.args(&config.args).env_clear();
    for name in ["HOME", "PATH", "LANG"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(relay) = &relay {
        let proxy = format!("http://127.0.0.1:{}", relay.port);
        for name in PROXY_ENVIRONMENT {
            command.env(name, &proxy);
        }
        command.env("NO_PROXY", "").env("no_proxy", "");
    }
    for entry in environment {
        command.env(entry.name, entry.value);
    }

    #[cfg(target_os = "linux")]
    {
        configure_linux_child(&mut command, config.limits);
        let status = command
            .status()
            .map_err(|source| SupervisorError::Execute {
                command: config.command,
                source,
            })?;
        drop(relay);
        Ok(status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, relay, config.limits);
        Err(SupervisorError::UnsupportedPlatform)
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub success: bool,
    pub outside_path_hidden: bool,
    pub host_environment_hidden: bool,
    pub host_pid_hidden: bool,
    pub host_loopback_hidden: bool,
    pub namespace_escape_blocked: bool,
    pub supervisor_memory_protected: bool,
    pub thread_creation_allowed: bool,
    pub core_dumps_disabled: bool,
    pub open_file_limit: u64,
    pub address_space_limit: u64,
    pub process_limit: u64,
}

pub fn run_probe(config: ProbeConfig) -> Result<ProbeReport, SupervisorError> {
    let outside_path_hidden = fs::symlink_metadata(&config.outside_path).is_err();
    let host_environment_hidden = env::var_os(&config.forbidden_environment).is_none();
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

    let core = get_limit(libc::RLIMIT_CORE)?;
    let nofile = get_limit(libc::RLIMIT_NOFILE)?;
    let address_space = get_limit(libc::RLIMIT_AS)?;
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
            && host_pid_hidden
            && host_loopback_hidden
            && namespace_escape_blocked
            && supervisor_memory_protected
            && thread_creation_allowed
            && core == 0,
        outside_path_hidden,
        host_environment_hidden,
        host_pid_hidden,
        host_loopback_hidden,
        namespace_escape_blocked,
        supervisor_memory_protected,
        thread_creation_allowed,
        core_dumps_disabled: core == 0,
        open_file_limit: nofile,
        address_space_limit: address_space,
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
}
