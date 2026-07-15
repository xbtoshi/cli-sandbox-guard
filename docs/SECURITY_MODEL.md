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
- the host-side native approval controller and its private proxy protocol when interactive egress
  approval is enabled;
- on macOS, Lima, its hypervisor, SSH/rsync transport, and the dedicated Linux guest.

The `guard grok` adapter additionally trusts the host Grok authentication subcommand only while
it is confined by Grok's built-in `strict` profile to an empty private working directory and its
own configuration state. Guard does not run an agent in that host-side authentication process.
The vendor-neutral staging and execution path does not otherwise depend on Grok-specific state.

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
- An optional preflight command runs under the same cleared environment, namespaces, resource
  scope, seccomp setup, and controlled-egress policy as the main tool. A non-zero preflight status
  prevents the main tool from starting.
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
- Optional interactive grants cross a private stdio pipe owned by the trusted proxy transport, not
  the tool terminal. The host revalidates an exact normalized hostname and port 443 before showing
  a native dialog. Grants are one CONNECT or one Guard session and never add wildcard rules.
- Cancellation, timeout, malformed protocol, missing native UI, and noninteractive execution deny
  the request. Linux requires `zenity`; Guard does not accept approval input through the untrusted
  tool's shared terminal. Prompts are serialized and capped at 16 per run; excess requests deny
  without another prompt.
- DNS resolution occurs in the trusted namespace. Loopback, private, carrier-grade NAT,
  link-local, metadata, documentation, multicast, transition, and other selected non-public ranges
  are discarded. The proxy connects directly to the validated resolved address.
- The first TLS record must be a ClientHello whose SNI exactly equals the CONNECT hostname before
  any client bytes are sent upstream.
- The destination audit contains only a timestamp and successful hostname/port. A separate approval
  audit records hostname/port and deny, allow-once, or allow-session—not URLs or payloads.
- Handshakes have wall-clock deadlines, tunnels have idle timeouts, and concurrent proxy/relay
  connections are bounded.

These controls constrain destinations, not information flow to an allowed destination. The proxy
does not inspect HTTP paths or encrypted payloads. A malicious tool can send all staged content and
every intentionally forwarded credential to an allowlisted service.

## Grok adapter invariants

- `guard grok` accepts only an owner-owned, owner-private, singly linked regular
  `~/.grok/auth.json` no larger than 1 MiB and extracts only the newest unexpired OIDC access token.
- The host auth file, refresh token, Grok configuration, logs, and home directory are never staged
  or mounted into the sandbox.
- An expired credential is refreshed by a non-agent host Grok command using the built-in `strict`
  profile and an empty mode-`0700` working directory. Browser login is used only when silent
  refresh is unavailable.
- The guest receives only the short-lived access token through the existing private environment
  transport. A preflight hydrates the disposable synthetic home through Grok's documented external
  auth-provider interface before the main Grok process starts.
- Egress starts with controlled HTTPS access for `cli-chat-proxy.grok.com`. Interactive runs may
  grant an exact additional hostname once or for that Guard session through the trusted native
  approval controller; `--no-egress-prompts` restores the fixed allowlist. The adapter never offers
  unrestricted networking or permanent grants.

## Resource and syscall controls

The supervisor sets `RLIMIT_CORE=0` plus configured address-space, output-file-size, CPU-time,
open-file, and process-count limits. With delegated cgroup v2, Guard also applies memory, swap,
task-count, and CPU-quota controls to the entire Bubblewrap scope. `required` mode fails if this
cannot be established; `best-effort` records a warning and retains rlimits/seccomp. Capability is
probed with the same controller properties before the run, and a helper inside that scope reads
back `memory.max`, `memory.swap.max`, `pids.max`, and `cpu.max` before enforcement is reported.

The seccomp profile is an architecture-checked classic-BPF deny profile. It rejects namespace and
mount operations and namespace flags to `clone`; it makes `clone3` unavailable so libc falls back
to the filterable `clone` ABI. It also rejects BPF, perf, io_uring, file-handle APIs,
cross-process memory access, ptrace, `pidfd_getfd`, userfaultfd, module/reboot/swap/accounting, and
kernel-keyring operations. Seccomp filters syscall numbers and arguments, not pathnames. Filesystem
isolation remains the pathname boundary.

Audit enforcement booleans mean the corresponding setup completed: a failed seccomp `pre_exec`
aborts process creation, while cgroup `true` requires the real-property capability probe and the
controller-file readback plus the systemd-wrapped invocation. `guard test` separately executes a
capability-independent denied
process-memory syscall, compares every configured rlimit, and exercises controlled-proxy denial.

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

## Explicit limitations in version 0.3 alpha

- The seccomp policy is a focused deny profile, not a maintained OCI allowlist. Compatibility and
  coverage still require testing against each real vendor CLI and its subprocesses.
- cgroup v2 defaults to best-effort because user delegation is not universal. Rlimits alone are
  weaker, especially for aggregate process trees. Aggregate writable-disk and network-bandwidth
  quotas are not implemented. `/dev/shm` memory is reliably bounded only when cgroup memory
  enforcement is active.
- Controlled egress supports proxy-aware HTTPS clients only. It requires a single-record initial
  ClientHello with SNI, does not perform TLS interception or certificate verification for the
  client, and cannot restrict URL paths or tenants behind an allowed shared endpoint.
- Interactive approval identifies the requested hostname and port, not the executable or HTTP
  path responsible for the request. The tool can choose misleading hostnames and can send any data
  it can access after approval; users must approve only destinations they expected.
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
- `guard grok` does not yet provide live refresh brokerage. A session that outlives its short-lived
  access token must exit and relaunch so Guard can obtain a fresh token. The access token is
  intentionally visible to Grok and its child processes, though the refresh token is not.

These limitations are release gates, not hidden assumptions. The
[requirements register](../sandbox-guard-requirements.md) tracks historical blockers and remaining
test work.

## Reporting vulnerabilities

Do not include real secrets, credentials, private repositories, or exploit payloads containing
third-party data in a public issue. Use GitHub private vulnerability reporting for this repository.
