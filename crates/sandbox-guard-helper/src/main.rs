use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use sandbox_guard_helper::{
    ControlledProxyProbeConfig, ProbeConfig, ProxyConfig, ResourceLimits, SuperviseConfig,
    SupervisedCommand, run_controlled_proxy_probe, run_probe, run_proxy, supervise,
    verify_current_cgroup,
};

#[derive(Debug, Parser)]
#[command(name = "guard-helper", version, hide = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Proxy(ProxyArgs),
    Supervise(SuperviseArgs),
    Probe(ProbeArgs),
    ControlledProbe(ControlledProbeArgs),
    CgroupProbe(CgroupProbeArgs),
}

#[derive(Debug, Args)]
struct ProxyArgs {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    audit_log: PathBuf,
    #[arg(long = "allow-host", required = true)]
    allow_hosts: Vec<String>,
    #[arg(long, default_value_t = 443)]
    allow_port: u16,
    #[arg(long, default_value_t = 30)]
    connect_timeout_seconds: u64,
}

#[derive(Debug, Args)]
struct SuperviseArgs {
    #[arg(long)]
    environment: PathBuf,
    #[arg(long)]
    proxy_socket: Option<PathBuf>,
    #[arg(long)]
    memory_bytes: u64,
    #[arg(long)]
    max_file_bytes: u64,
    #[arg(long, default_value_t = 3600)]
    cpu_seconds: u64,
    #[arg(long, default_value_t = 1024)]
    open_files: u64,
    #[arg(long, default_value_t = 256)]
    max_processes: u64,
    #[arg(long, default_value_t = 200)]
    cpu_percent: u64,
    #[arg(long)]
    preflight_command: Option<OsString>,
    #[arg(long = "preflight-arg", allow_hyphen_values = true)]
    preflight_args: Vec<OsString>,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    outside_path: PathBuf,
    #[arg(long)]
    host_pid: u32,
    #[arg(long)]
    loopback_port: u16,
    #[arg(long)]
    forbidden_environment: String,
}

#[derive(Debug, Args)]
struct ControlledProbeArgs {
    #[arg(long)]
    host_loopback_port: u16,
    #[arg(long, default_value = "denied.example.invalid")]
    denied_host: String,
}

#[derive(Debug, Args)]
struct CgroupProbeArgs {
    #[arg(long)]
    memory_bytes: u64,
    #[arg(long)]
    max_processes: u64,
    #[arg(long)]
    cpu_percent: u64,
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            eprintln!("guard-helper: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Proxy(args) => {
            run_proxy(ProxyConfig {
                socket: args.socket,
                audit_log: args.audit_log,
                allow_hosts: args.allow_hosts,
                allow_port: args.allow_port,
                connect_timeout: Duration::from_secs(args.connect_timeout_seconds),
            })?;
            Ok(0)
        }
        Command::Supervise(args) => {
            if args.preflight_command.is_none() && !args.preflight_args.is_empty() {
                bail!("--preflight-arg requires --preflight-command");
            }
            let (command, command_args) = args
                .command
                .split_first()
                .context("supervise command cannot be empty")?;
            let limits = ResourceLimits {
                memory_bytes: args.memory_bytes,
                max_file_bytes: args.max_file_bytes,
                cpu_seconds: args.cpu_seconds,
                open_files: args.open_files,
                max_processes: args.max_processes,
                cpu_percent: args.cpu_percent,
            };
            let status = supervise(SuperviseConfig {
                environment_file: args.environment,
                proxy_socket: args.proxy_socket,
                limits,
                preflight: args.preflight_command.map(|command| SupervisedCommand {
                    command,
                    args: args.preflight_args,
                }),
                command: command.clone(),
                args: command_args.to_vec(),
            })?;
            Ok(status.code().unwrap_or(128))
        }
        Command::Probe(args) => {
            let report = run_probe(ProbeConfig {
                output: args.output,
                outside_path: args.outside_path,
                host_pid: args.host_pid,
                loopback_port: args.loopback_port,
                forbidden_environment: args.forbidden_environment,
            })?;
            if !report.success {
                bail!("one or more sandbox invariants failed")
            }
            Ok(0)
        }
        Command::ControlledProbe(args) => {
            run_controlled_proxy_probe(ControlledProxyProbeConfig {
                host_loopback_port: args.host_loopback_port,
                denied_host: args.denied_host,
            })?;
            Ok(0)
        }
        Command::CgroupProbe(args) => {
            verify_current_cgroup(ResourceLimits {
                memory_bytes: args.memory_bytes,
                max_processes: args.max_processes,
                cpu_percent: args.cpu_percent,
                ..ResourceLimits::default()
            })?;
            Ok(0)
        }
    }
}
