//! Trusted runtime helper used on the Linux side of both Sandbox Guard backends.

mod proxy;
mod supervisor;

#[cfg(target_os = "linux")]
mod seccomp;

use serde::{Deserialize, Serialize};

pub use proxy::{ProxyConfig, ProxyError, run_proxy};
pub use supervisor::{
    ControlledProxyProbeConfig, ProbeConfig, ProbeReport, SuperviseConfig, SupervisedCommand,
    SupervisorError, run_controlled_proxy_probe, run_probe, supervise, verify_current_cgroup,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentEntry {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub memory_bytes: u64,
    pub max_file_bytes: u64,
    pub cpu_seconds: u64,
    pub open_files: u64,
    pub max_processes: u64,
    pub cpu_percent: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 8 * 1024 * 1024 * 1024,
            max_file_bytes: 1024 * 1024 * 1024,
            cpu_seconds: 60 * 60,
            open_files: 1024,
            max_processes: 256,
            cpu_percent: 200,
        }
    }
}

pub const PROXY_ENVIRONMENT: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];
