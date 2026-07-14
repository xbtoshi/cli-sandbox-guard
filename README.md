# Sandbox Guard

Sandbox Guard is an experimental, vendor-neutral boundary for AI coding CLIs. It gives an
untrusted tool a sanitized disposable repository instead of the real host workspace.

> [!WARNING]
> This repository is an alpha security prototype, not a production sandbox. Controlled network
> egress, seccomp, cgroup enforcement, reviewed copy-back, and verified vendor updates remain open
> release blockers. Read the [security model](docs/SECURITY_MODEL.md) before using it.

## The boundary

    host repository
          |
          v
    trusted Rust policy + descriptor-safe stager
          |
          v
    sanitized tree + synthetic one-commit Git repository + audit manifest
          |
          +-- Linux: Bubblewrap
          |
          +-- macOS: mountless Lima VM, then Bubblewrap inside the guest
          |
          v
    untrusted AI CLI

The tool can modify its disposable copy, but version 0.1 never copies those changes to the host
repository.

## What works now

- Immutable built-in deny rules plus an additive user policy.
- NUL-delimited tracked and non-ignored-untracked Git enumeration.
- Descriptor-relative opening with no symlink traversal.
- Linux openat2 with RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS, RESOLVE_NO_MAGICLINKS, and
  RESOLVE_NO_XDEV.
- Hard-link rejection, special-file rejection, source-mutation detection, and byte/file limits.
- A synthetic baseline commit without original objects, refs, hooks, config, alternates, or history.
- Clean environment construction; dangerous loader/runtime variables cannot be forwarded.
- JSON audit manifests containing staged paths and hashes, exclusions, policy hash, and run result.
- Network denied by default.

## Build

Rust 1.85 or newer is required.

    cargo build --release
    cargo test --workspace

The binary is target/release/guard.

## Inspect a repository without running a tool

    guard stage /path/to/repository
    guard policy --check nested/.env.production
    guard policy --policy policy.example.toml
    guard gc --dry-run

The stage command keeps the sanitized workspace and prints its path. The run command normally
deletes the workspace after execution.

If a process is killed before its private stage can be deleted, guard gc removes old stages owned
by the current user. Per-stage advisory locks prevent collection of active runs.

## Linux

Install Bubblewrap and Git, then run:

    guard doctor
    guard run -- my-ai-cli

Static binaries outside /usr and /bin are mounted individually. Tools needing adjacent runtime
files must declare a narrow installation root:

    guard run --tool-root "$HOME/.local/lib/my-ai-cli" -- bin/my-ai-cli

Linux staging requires openat2 (kernel 5.6 or newer). The runner currently binds standard system
runtime directories read-only and does not yet install a seccomp profile or cgroup.

## macOS

The native macOS host does not provide Bubblewrap, Linux namespaces, seccomp, or cgroup v2.
Sandbox Guard therefore uses a dedicated Linux VM. Install Lima, create an instance without host
mounts, and install Bubblewrap, Git, CA certificates, and the selected CLI inside that guest:

    brew install lima
    limactl create --name=sandbox-guard --mount-none template:default
    limactl start --mount-none sandbox-guard
    limactl shell sandbox-guard sudo apt-get update
    limactl shell sandbox-guard sudo apt-get install -y bubblewrap git ca-certificates
    guard doctor
    guard run -- my-ai-cli

Before every run, the backend inspects guest mounts and refuses 9p, VirtioFS, or SSHFS host shares.
This runtime check covers Lima's known host-share filesystem families; the dedicated guest must not
be manually configured with another host-sharing mechanism.
It copies only the sanitized workspace into a unique guest directory and removes that directory
after execution.

## Network and credentials

The default mode creates a separate network namespace with no external connectivity:

    guard run --network denied -- my-ai-cli

An online CLI can currently be used only with the deliberately unsafe development mode:

    guard run --network unrestricted --allow-unrestricted-network \
      --forward-env OPENAI_API_KEY -- my-ai-cli

This shares the selected Linux-host or Lima-guest network namespace. It exposes that namespace's
loopback services, private and LAN networks, cloud metadata, and Linux abstract UNIX sockets.
Abstract sockets are outside filesystem isolation and may permit code execution in that network
namespace. This mode does **not** satisfy the controlled-egress requirement.

Forwarded values are passed intentionally to the tool and never written to audit logs; only their
names are recorded. In version 0.1, their values are also temporarily visible in the host-side
Bubblewrap or Lima process argument list.

## Policy

The built-in policy rejects .env files, .dev.vars files, id_rsa files, credentials.json, .ssh,
.aws/credentials, original .git, CCB session metadata, symlinks, special files, cross-filesystem
paths, and multiply linked files. See [policy.example.toml](policy.example.toml) for additive rules
and lower resource ceilings.

Without an explicit policy argument, Guard loads policy.toml from the platform configuration
directory printed by guard doctor when that file exists.

Filename rules cannot detect secret bytes copied under an innocent, independently stored filename.
Content scanning and keeping secrets outside repositories remain useful additional controls.

## Development status

The complete blocker register and target test matrix are in
[sandbox-guard-requirements.md](sandbox-guard-requirements.md). Contributions should preserve
fail-closed behavior: an unsupported security property is an error, never an implicit fallback.
