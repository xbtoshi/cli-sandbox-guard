# Security model

## Protected assets

Sandbox Guard is intended to prevent an AI CLI and its child processes from reading:

- host files that were not explicitly staged;
- original Git history, objects, hooks, configuration, and alternates;
- inherited environment variables and file descriptors;
- host processes and, in the default mode, host networking.

The AI CLI is treated as potentially malicious. Repository filenames, links, file types, Git ignore
rules, and file contents are also treated as untrusted.

## Trusted computing base

The current trusted computing base is:

- the host kernel and filesystem;
- this Rust staging, policy, audit, and runner code;
- Git during candidate enumeration and synthetic repository construction;
- Bubblewrap and the guest or host system runtime files mounted into the sandbox;
- Lima, its hypervisor, SSH transport, and the dedicated Linux guest on macOS.

On macOS, the dedicated Lima guest must never contain host filesystem mounts or durable secrets.
Vendor credentials should be short-lived and forwarded explicitly for a single run.

## Staging invariants

1. Built-in denies cannot be removed by user policy.
2. Candidate paths must be relative and contain only normal components.
3. Source files are opened relative to an already-open source-root descriptor.
4. Linux uses openat2 to reject symlinks, magic links, mount crossings, and path escapes.
5. Other Unix hosts open every parent with O_NOFOLLOW before opening the leaf with O_NOFOLLOW.
6. Non-regular files, symlinks, multiply linked files, and cross-device files are omitted and
   audited.
7. Device, inode, size, modification time, and change time must remain stable across a copy.
8. Any staging error aborts the run; the original workspace is never used as a fallback.
9. Synthetic Git metadata is built with system and global configuration disabled and contains one
   sanitized baseline commit.

## Isolation invariants

- The host repository is never mounted in the sandbox.
- The disposable workspace is the only writable project tree.
- The environment is cleared before audited values are added.
- Loader, runtime injection, Git configuration, PATH, and HOME variables cannot be forwarded;
  entire known-dangerous environment families such as GIT, LD, DYLD, NODE, PYTHON, PERL, RUBY,
  JAVA, and LUA are rejected.
- Capabilities are dropped and PID, IPC, UTS, user, and cgroup namespaces are separated.
- The network namespace is separated unless the user explicitly acknowledges unrestricted mode.

## Explicit limitations in version 0.1

- No maintained seccomp allowlist or denylist is installed.
- Memory, CPU, PID, aggregate disk, and bandwidth limits are not enforced.
- There is no controlled-egress proxy. Unrestricted mode shares the selected host or Lima-guest
  network namespace, exposing its loopback services, private and LAN networks, cloud metadata, and
  Linux abstract UNIX sockets. Abstract sockets are outside filesystem isolation and can provide a
  path to code execution in that network namespace.
- Forwarded credential values currently appear in the host-side Bubblewrap or Lima process
  argument list for the lifetime of a run.
- There is no safe copy-back; staged edits are discarded.
- There is no verified updater or tool-signature enforcement.
- The macOS backend requires a pre-created, correctly provisioned dedicated Lima guest.
- Lima host-share detection fails closed when mount inspection cannot run, but recognizes known
  Lima filesystem families by type; a new or manually configured sharing mechanism could require
  an updated check. The dedicated guest configuration remains part of the trusted computing base.
- A crash can leave a sanitized staging directory behind until guard gc removes it; active stages
  are protected by an advisory lock and garbage collection checks ownership and age.
- Filename policy cannot recognize copied secret content under an allowed filename.
- Kernel, hypervisor, Bubblewrap, Git, and Lima vulnerabilities are outside the threat model.
- A credential intentionally forwarded to a malicious tool can be stolen or misused by that tool.

These are release blockers, not hidden assumptions. See the requirements document for the complete
matrix.

## Reporting vulnerabilities

Do not include real secrets, credentials, private repositories, or exploit payloads containing
third-party data in a public issue. Use GitHub private vulnerability reporting for this repository
when enabled.
