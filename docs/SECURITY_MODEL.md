# Security model

## Protected assets

Sandbox Guard is intended to prevent an AI CLI and its child processes from reading:

- host files that were not explicitly staged;
- original Git history, objects, hooks, configuration, and alternates;
- inherited environment variables and file descriptors;
- host processes and host network services in denied and controlled network modes;
- forwarded credential values through host process argument lists or audit records.

The AI CLI and its child processes are treated as potentially malicious. Repository filenames,
links, file types, Git rules, file contents, and files returned from a Lima guest are also treated
as untrusted. A compromised vendor binary is inside the threat model up to the kernel/hypervisor
boundary.

## Trusted computing base

The current trusted computing base is:

- the host kernel and filesystem;
- the Rust policy, staging, audit, export, tool-store, runner, and `guard-helper` code;
- Git during candidate enumeration and synthetic repository construction;
- Bubblewrap and the system runtime files mounted into the sandbox;
- systemd and cgroup v2 when cgroup enforcement is selected;
- the trusted controlled-egress proxy running outside the tool's network namespace;
- on macOS, Lima, its hypervisor, SSH/rsync transport, and the dedicated Linux guest.

On macOS, the dedicated guest must contain no host filesystem mounts or durable credentials. It is
part of the trusted computing base. Vendor credentials should be short-lived and forwarded
explicitly for one run.

## Staging invariants

1. Built-in denies cannot be removed by user policy.
2. Candidate paths must be relative and contain only normal components.
3. Source files are opened relative to an already-open source-root descriptor.
4. Linux uses `openat2` to reject symlinks, magic links, mount crossings, and path escapes.
5. Other Unix hosts open every parent with `O_NOFOLLOW` before opening the leaf with
   `O_NOFOLLOW`.
6. Non-regular files, symlinks, multiply linked files, and cross-device files are omitted and
   audited.
7. Device, inode, size, modification time, and change time remain stable across a copy.
8. Any staging error aborts the run; the original workspace is never used as a fallback.
9. Synthetic Git metadata is built with system/global configuration disabled and contains one
   sanitized baseline commit.

## Execution invariants

- The host repository is never mounted in the sandbox.
- The disposable workspace is the only writable project tree.
- Bubblewrap clears the environment and closes inherited descriptors.
- Loader, runtime injection, Git configuration, proxy override, `PATH`, and `HOME` variables cannot
  be forwarded. Entire known-dangerous families such as GIT, LD, DYLD, NODE, PYTHON, PERL, RUBY,
  JAVA, and LUA are rejected.
- Forwarded credential values travel in a singly created mode-`0600` file inside a mode-`0700`
  runtime directory. They are not command arguments and are structurally absent from run audits.
- The trusted supervisor is non-dumpable, gives the child no new privileges, sets a restrictive
  umask and rlimits, then installs seccomp in the untrusted child before `exec`.
- Capabilities are dropped and PID, IPC, UTS, user, and cgroup namespaces are separated.
- Denied and controlled modes use a separate network namespace. Unrestricted mode requires an
  explicit acknowledgement and a high-visibility warning.

## Controlled-egress invariants

- The untrusted namespace has no normal external interface. It sees a loopback HTTP-proxy relay
  connected through a filesystem UNIX socket to the trusted proxy outside that network namespace.
- Only CONNECT to configured port 443 is accepted.
- Hostnames are normalized and must match an exact or explicit wildcard-suffix rule.
- DNS resolution occurs in the trusted namespace. Loopback, private, carrier-grade NAT,
  link-local, metadata, documentation, multicast, transition, and other selected non-public ranges
  are discarded. The proxy connects directly to the validated resolved address.
- The first TLS record must be a ClientHello whose SNI exactly equals the CONNECT hostname before
  any client bytes are sent upstream.
- The audit contains only a timestamp and successful destination hostname/port.

These controls constrain destinations, not information flow to an allowed destination. The proxy
does not inspect HTTP paths or encrypted payloads. A malicious tool can send all staged content and
every intentionally forwarded credential to an allowlisted service.

## Resource and syscall controls

The supervisor sets `RLIMIT_CORE=0` plus configured address-space, output-file-size, CPU-time,
open-file, and process-count limits. With delegated cgroup v2, Guard also applies memory, swap,
task-count, and CPU-quota controls to the entire Bubblewrap scope. `required` mode fails if this
cannot be established; `best-effort` records a warning and retains rlimits/seccomp.

The seccomp profile is an architecture-checked classic-BPF deny profile. It rejects namespace and
mount operations and namespace flags to `clone`; it makes `clone3` unavailable so libc falls back
to the filterable `clone` ABI. It also rejects BPF, perf, io_uring, file-handle APIs,
cross-process memory access, ptrace, `pidfd_getfd`, userfaultfd, module/reboot/swap/accounting, and
kernel-keyring operations. Seccomp filters syscall numbers and arguments, not pathnames. Filesystem
isolation remains the pathname boundary.

## Change-export invariants

- Export never writes to or applies changes to the source repository.
- The returned workspace is treated as hostile and walked without Git or ignore-file semantics.
- Synthetic `.git`, denied paths, links, special files, multiple links, and mount crossings are
  excluded or rejected.
- Accepted files are descriptor-opened relative to the returned workspace and revalidated across
  the copy.
- The new private destination must be outside source and stage, owned by the invoking user, and not
  group/world writable. It is published atomically only after its manifest is complete.
- Deletions are manifest records only. Added/modified content is placed under `files/` for manual
  review.

## Tool-install invariants

- The expected signer identity is the pinned SHA-256 fingerprint of a raw Ed25519 public key.
- A detached Ed25519 signature is verified before installation begins.
- Artifact, key, and signature inputs must be stable, singly linked regular files under fixed size
  limits.
- A new version is assembled privately and atomically renamed into an owner-private store. An
  existing version is never replaced.
- Re-verification checks signer identity, signature, artifact hash, and size.

This protects the offline install operation only. The current runner does not require tools to come
from this store and does not automatically re-verify them before every run.

## Explicit limitations in version 0.2 alpha

- The seccomp policy is a focused deny profile, not a maintained OCI allowlist. Compatibility and
  coverage still require testing against each real vendor CLI and its subprocesses.
- cgroup v2 defaults to best-effort because user delegation is not universal. Rlimits alone are
  weaker, especially for aggregate process trees. Aggregate writable-disk and network-bandwidth
  quotas are not implemented. `/dev/shm` memory is reliably bounded only when cgroup memory
  enforcement is active.
- Controlled egress supports proxy-aware HTTPS clients only. It requires a single-record initial
  ClientHello with SNI, does not perform TLS interception or certificate verification for the
  client, and cannot restrict URL paths or tenants behind an allowed shared endpoint.
- Unrestricted mode exposes the selected host or Lima-guest network namespace, including loopback,
  private/LAN networks, cloud metadata, and Linux abstract UNIX sockets. Abstract sockets are not
  covered by filesystem isolation and may provide a code-execution path in that namespace.
- Change export is a review bundle, not conflict-aware copy-back. The user must inspect and apply
  accepted files and deletions.
- The verified tool store has no network downloader, root-owned key policy, privileged installer,
  canonical wrapper enforcement, rollback policy, or automatic verification at execution time.
- The macOS backend requires a pre-created, correctly provisioned dedicated Lima guest and a Linux
  `guard-helper` installed inside it.
- Lima host-share detection fails closed when mount inspection cannot run but recognizes known
  share filesystem families by type. A new or manually configured sharing mechanism could require
  an updated check.
- CI exercises live Bubblewrap isolation on Ubuntu. Live Lima and real vendor login/API/subprocess
  workflows are not yet continuous-test gates.
- A crash can leave a sanitized stage, including its private credential runtime, behind until
  `guard gc` removes it. Active stages use an advisory lock; collection checks owner and age. A
  killed macOS run can also leave its mode-`0700` guest runtime in guest `/dev/shm` until reboot or
  manual removal.
- Filename policy cannot recognize copied secret content under an allowed filename.
- Kernel, hypervisor, Bubblewrap, Git, Lima, systemd, and trusted-helper vulnerabilities are outside
  the promised boundary.
- A credential intentionally forwarded to a malicious tool can be stolen or misused by that tool.

These limitations are release gates, not hidden assumptions. The
[requirements register](../sandbox-guard-requirements.md) tracks historical blockers and remaining
test work.

## Reporting vulnerabilities

Do not include real secrets, credentials, private repositories, or exploit payloads containing
third-party data in a public issue. Use GitHub private vulnerability reporting for this repository.
