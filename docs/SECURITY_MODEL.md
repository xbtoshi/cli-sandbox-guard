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
- the Rust policy, staging, audit, export/apply, tool-store, runner, and `guard-helper` code;
- Git during candidate enumeration and synthetic repository construction;
- Bubblewrap and the system runtime files mounted into the sandbox;
- systemd and cgroup v2 when cgroup enforcement is selected;
- the trusted controlled-egress proxy running outside the tool's network namespace;
- the host-side native approval controller and its private proxy protocol when interactive egress
  approval is enabled;
- the host-side interactive PTY and one-shot clipboard-image controller when `Ctrl+V` import is
  used;
- on macOS, Lima, its hypervisor, SSH/rsync transport, and the dedicated Linux guest.

The `guard grok` adapter additionally trusts the host Grok authentication subcommand only while
it is confined by Grok's built-in `strict` profile to an empty private working directory and its
own configuration state. Guard does not run an agent in that host-side authentication process.
The vendor-neutral staging and execution path does not otherwise depend on Grok-specific state.

On macOS, the dedicated guest must contain no host filesystem mounts or durable credentials. It is
part of the trusted computing base. Vendor credentials should be short-lived and forwarded
explicitly for one run.

The explicit guest-package setup action runs a fixed APT package-name set through passwordless sudo
inside that dedicated guest only after repeated declared/live mount checks. It trusts the guest's
configured APT repositories, package-manager configuration, and root-run maintainer hooks/scripts;
package versions are not pinned. It does not use the runtime egress broker, invoke host sudo, or
automatically clean up a partial package-manager failure.

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
- The clean-environment guarantee includes the visible launcher process. Bubblewrap's `--clearenv`
  scrubs only the executed child, but bwrap itself stays alive as pid 1 inside the sandbox pid
  namespace and its `/proc/1/environ` is readable by the confined tool. The runner therefore
  interposes a fixed-argv `/usr/bin/env -i` boundary immediately before bwrap on every route (Linux
  host and Lima guest, interactive and noninteractive, cgroup-enforced and best-effort). Both
  executables at this boundary are fixed absolute paths (`/usr/bin/env`, and `/usr/bin/bwrap` in the
  guest / the runner's resolved absolute `bwrap` on the host), so no PATH-selected binary can run
  before the environment is cleared. The launcher inherits a fully empty environment on both
  backends; the bwrap child still receives its own `PATH`/`HOME`/`LANG` through `--setenv`. The
  boundary is placed *after* the `systemd-run` scope so cgroup delegation to the user manager still
  works. The hostile backend probe reads `/proc/1/environ` and fails closed unless it is empty.
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

## Interactive clipboard invariants

- Guard never polls or automatically forwards the host clipboard. Only a raw `Ctrl+V` received by
  the trusted host-side PTY during an interactive run triggers one read. Normal terminal `Cmd+V`
  text paste remains terminal-provided input.
- On macOS, the native clipboard service exports one PNG. Guard caps the encoded input at 32 MiB,
  limits dimensions to 16,384 per side and 40 million total pixels, decodes it under allocation
  limits, and re-encodes it as PNG before delivery. Original image metadata is not retained.
- The sanitized file is created mode `0600` inside a mode-`0700` per-run inbox. That inbox is
  read-only in the sandbox at `/workspace/sandbox-guard-inputs`; its name is a built-in denied
  source path, so repository content cannot pre-seed it. Lima delivery verifies the returned file
  type, mode, and size.
- The inbox is not part of the original repository, change exports, or persistent Grok session
  snapshots. It is removed from the staged workspace after execution and the backing runtime is
  deleted with the run.
- The PTY filters 7-bit OSC clipboard controls, iTerm host-control OSC, and opaque DCS/SOS/PM/APC
  terminal-multiplexer passthrough emitted by the untrusted tool so those channels cannot bypass
  the explicit clipboard broker. Raw C1 byte values are treated as UTF-8 continuation data, as in
  modern UTF-8 terminal modes. DEC mouse reporting is enabled by default for normal tool scrolling.
  Raw `Ctrl+S` switches the trusted broker into host selection/copy mode: Guard disables mouse
  reporting at the host terminal without telling the tool, suppresses later tool attempts to
  re-enable it, and restores only the exact requested modes when the user presses `Ctrl+S` again.
  The toggle is not delivered to the isolated TUI. Clipboard audit entries contain only the
  sandbox path, media type, dimensions, byte count, and SHA-256 digest.

After explicit import, the image is intentionally readable by the untrusted tool and can be sent
to any destination allowed by the network policy. The image itself may contain adversarial prompt
content; sanitization protects the file/decoder boundary, not model interpretation.

## Controlled-egress invariants

- The untrusted namespace has no normal external interface. It sees a loopback HTTP-proxy relay
  connected through a filesystem UNIX socket to the trusted proxy outside that network namespace.
- Only CONNECT to configured port 443 is accepted.
- Hostnames are normalized and must match an exact or explicit wildcard-suffix rule.
- Optional interactive grants cross a private stdio pipe owned by the trusted proxy transport, not
  the tool terminal. The host revalidates an exact normalized hostname and port 443 before showing
  a native dialog. Choices cover one CONNECT, one Guard session, or—only when the user explicitly
  remembers them—future sessions. macOS collects the decision and optional remember state in one
  `NSAlert`; Linux presents the persistent variants in the same `zenity` window. Remembered choices
  are exact-host port-443 entries and never add wildcard rules.
- Remembered allow and deny choices live in an owner-only, singly linked regular file under an
  owner-only Guard data directory. Writes are locked, merged, fsynced, and atomically renamed. The
  file path is outside the staged workspace and optional writable tool state. Persistence failure
  denies rather than widening access. `guard approvals` provides list, forget-one, and clear-all
  operations.
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
  audit records hostname/port and the scoped or remembered decision—not URLs or payloads.
- Handshakes have wall-clock deadlines, tunnels have idle timeouts, and concurrent proxy/relay
  connections are bounded.

These controls constrain destinations, not information flow to an allowed destination. The proxy
does not inspect HTTP paths or encrypted payloads. A malicious tool can send all staged content and
every intentionally forwarded credential to an allowlisted service.

## Observational event-index invariants

- The per-run audit is authoritative and is durably persisted before any event-index update is
  attempted. Event persistence is observational: failure emits one generic warning and cannot
  alter enforcement, audit persistence, or the tool's exit status.
- The current event schema contains only run IDs, event IDs/times, staging counts, run outcome,
  successful controlled-egress hostname/port pairs, and trusted native approval decisions. It
  cannot represent workspace paths, staging-exclusion paths/reasons, tool commands or arguments,
  environment names/values, URLs, headers, bodies, credentials, or clipboard details.
- Staging exclusions are not described as violations. The current runtime does not yet observe
  denied filesystem, environment, syscall, or resource attempts, so the index makes no claim that
  it does.
- Proxy and approval audit lines are accepted only through strict, bounded parsers: ASCII decimal
  Unix seconds, a normalized exact hostname, port 443, an exact field count, and (for approvals)
  one known decision name. Malformed lines produce no event.
- One audit contributes at most 512 records; excess source entries produce an explicit
  observation-truncated record with a count. The index is capped at 4096 records and 4 MiB. Oldest
  records are evicted under a nonblocking advisory lock; contention drops the observational update
  rather than delaying a completed tool. Publication uses a mode-`0600` temporary file, file sync,
  atomic rename, and directory sync.
- The event directory must be a real owner-owned mode-`0700` directory. The index and lock must be
  no-follow, singly linked, owner-owned regular files with exact mode `0600` and fixed size bounds.
  Unknown schema fields/variants or future schema versions fail closed. `guard events` performs no
  repair and emits no partial JSON when validation fails.

## Grok adapter invariants

- The adapter derives its runtime profile from the compiled built-in plus an optional owner-only
  `profile-overlays.toml` at Guard's fixed configuration directory. The file is opened without
  following links, bounded to 64 KiB, and required to be a singly linked owner-private regular
  file beneath an owner-validated configuration path. Repository files and CLI arguments cannot
  select or replace it.
- The overlay schema can only remove an existing egress rule, narrow a subdomain rule to its exact
  host, turn optional approval/clipboard/terminal capabilities off, or reduce positive session
  quotas. Commands, arguments, credentials, paths, mounts, session layout, seccomp expectations,
  and new hosts are not representable. The merged profile is revalidated before use.
- A missing overlay preserves the compiled profile exactly. Any present file that is unsafe,
  malformed, unknown-versioned, or attempts to widen the built-in boundary aborts `guard grok`
  before authentication, staging, or backend setup; Guard never warns and continues with the
  wider base profile. External documents accepted by `profile lint` remain inspection-only and
  cannot enter this runtime path.
- Signed vendor profiles installed with `guard profile install` are verified once against a pinned
  signer fingerprint and re-verified on every later read. The signature authenticates the exact
  profile bytes under the owner-pinned fingerprint; it does not attest a release binary. The store
  lives at an internally derived owner-private path with no store-path flag, downloader, or ambient
  signer trust, and a package whose profile name matches a built-in is refused. Installed profiles
  are content-only in this milestone: they are never runtime-effective and are unreachable from
  `guard grok`, `guard run`, the built-in resolver, and owner overlays. Every installed-profile
  inspection re-checks the stored bytes, signature, signer pin, package hash, manifest, and stored
  path identity and fails closed on any mismatch; a corrupt installed store never suppresses the
  built-in listing. `guard profile remove NAME VERSION` deletes only that exact name and version;
  it intentionally does not require a valid signature so corrupted state remains removable, but
  still enforces the owner-private, non-symlink store boundary. `guard uninstall` removes the
  profile store with the rest of Guard's private data directory.
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
  grant an exact additional hostname once, for that Guard session, or remember an exact-host allow
  or deny through the trusted native approval controller; `--no-egress-prompts` restores the fixed
  allowlist. The adapter never offers unrestricted networking.
- Only a Guard-owned staged copy of `/home/guard/.grok/sessions` is writable across runs. The host
  `~/.grok`, auth file, refresh token, configuration, and logs remain unavailable. Returned session
  files are staged again with link, special-file, hard-link, mount-crossing, mutation, size, and
  count checks before a per-source snapshot is atomically activated. `--resume` accepts a UUID
  present in that snapshot; `--continue` delegates latest-session selection to Grok.

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
controller-file readback plus the systemd-wrapped invocation. `guard test` separately issues every
unconditional deny-list syscall with non-destructive arguments and requires EPERM. Self-process
memory reads and writes are capability-independent, while capability-gated calls confirm the
complete sandbox boundary rather than attributing EPERM to seccomp alone. The probe also exercises
the namespace-flagged `clone` branch with a kernel-invalid flag combination, verifies the `clone3`
ENOSYS shim, compares every configured rlimit, and exercises controlled-proxy denial.

## Change-export and apply invariants

- The untrusted tool never receives a source-repository mount, source descriptor, Git metadata, or
  host Git credential during export or apply.
- The returned workspace is treated as hostile and walked without Git or ignore-file semantics.
- Synthetic `.git`, denied paths, links, special files, multiple links, and mount crossings are
  excluded or rejected.
- Accepted files are descriptor-opened relative to the returned workspace and revalidated across
  the copy.
- The new private destination must be outside source and stage, owned by the invoking user, and not
  group/world writable. It is published atomically only after its manifest is complete.
- Deletions are manifest records only. Added/modified content is placed under `files/` for trusted
  review.
- Any rejected path disables automatic apply for the whole run. Denied file contents—including a
  tool-created `.env`—are never copied into the bundle or source tree.
- Apply requires a matching run/policy baseline and canonical relative paths with no duplicates.
  Before the first mutation, every added path must still be absent and every modified/deleted file
  must securely reopen as an owner-owned, singly linked regular file on the source filesystem with
  its baseline size, hash, and executable class.
- Apply creates/opens parent directories descriptor-relative with `O_NOFOLLOW`, refuses writable
  multi-user parents and mount crossings, re-verifies exported bytes while copying, and publishes
  each file with a no-replace rename. Existing files first move to UUID-named rollback slots and
  are re-hashed there; normal errors roll the transaction back in reverse order.
- The core apply API rejects every deletion unless its trusted caller supplies explicit deletion
  authorization. The interactive handoff issues that authorization only after the user types a
  phrase bound to the exact deletion and baseline-file counts. Mass deletion—including removal of
  the complete staged baseline—also requires the trusted diff to render successfully before Apply
  is offered.
- Manual `--export-changes` remains export-only. `--review-changes` and the default interactive
  `guard grok` handoff require an explicit trusted-host apply choice.

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
  path responsible for the request. TLS remains end-to-end, so Guard cannot show the full URL,
  method, headers, or body. The tool can choose misleading hostnames and can send any data it can
  access after approval; users must approve only destinations they expected.
- Host clipboard image import currently supports macOS only. The injected `@` reference is native
  to Grok and several coding CLIs, but vendor-specific clients that do not accept file references
  may require a dedicated adapter.
- Unrestricted mode exposes the selected host or Lima-guest network namespace, including loopback,
  private/LAN networks, cloud metadata, and Linux abstract UNIX sockets. Abstract sockets are not
  covered by filesystem isolation and may provide a code-execution path in that namespace.
- Change apply is rollback-backed for normal errors but not crash-atomic across multiple files. A
  kill or host/filesystem failure during the short apply window can leave a denied
  `.sandbox-guard-apply-*` or `.sandbox-guard-rollback-*` artifact for manual recovery. Guard does
  not commit or push; those remain explicit host-side Git operations after review.
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
- Filename policy cannot recognize copied secret content under an allowed filename. The built-in
  deny list is a high-confidence privacy default, not exhaustive; ambiguous names that are often
  ordinary files (for example `*.tfvars`, generic `secrets.*`, `api_keys.json`, `application.yml`,
  `google-services.json`, and SQL dumps) are intentionally left to owner policy rather than blocked
  globally.
- The bwrap launcher's argument vector is visible to the confined tool through `/proc/1/cmdline`.
  This discloses the run's staging pathnames — a random-UUID stage directory that is a host tmp path
  on direct Linux and a disposable guest `/dev/shm` tmpfs path under Lima — plus the fixed guest
  mount targets. This is accepted low-severity metadata, not a filesystem escape: the paths are not
  openable from inside the sandbox and carry no credentials. Hiding them would require either
  bwrap's `--args` file-descriptor form, which cannot be carried unchanged through the current
  `systemd-run`/`limactl` transports, or moving bwrap out of pid 1, which would require redesign and
  re-validation of the `--die-with-parent` reaping and signal model. Neither trade is justified to
  conceal non-sensitive metadata.
- Kernel, hypervisor, Bubblewrap, Git, Lima, systemd, and trusted-helper vulnerabilities are outside
  the promised boundary.
- A credential intentionally forwarded to a malicious tool can be stolen or misused by that tool.
- `guard grok` does not yet provide live refresh brokerage. A session that outlives its short-lived
  access token must exit and relaunch so Guard can obtain a fresh token. The access token is
  intentionally visible to Grok and its child processes, though the refresh token is not.
- Guard-managed Grok sessions are private but not encrypted at rest. A crash or forced termination
  before post-run validation and atomic activation can lose the newest conversation updates while
  leaving the previous validated snapshot intact.

These limitations are release gates, not hidden assumptions. The
[requirements register](../sandbox-guard-requirements.md) tracks historical blockers and remaining
test work.

## Reporting vulnerabilities

Do not include real secrets, credentials, private repositories, or exploit payloads containing
third-party data in a public issue. Use GitHub private vulnerability reporting for this repository.
