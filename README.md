# Sandbox Guard

Sandbox Guard is an experimental, vendor-neutral boundary for AI coding CLIs. It gives an
untrusted tool a sanitized, disposable repository instead of the real host workspace.

> [!WARNING]
> Version 0.3 is an alpha security prototype, not a production sandbox. It now has controlled
> HTTPS egress, a focused seccomp deny profile, resource controls, reviewable change export, and
> offline signature-verified tool installation. Important release blockers remain. Read the
> [security model](docs/SECURITY_MODEL.md) before using it.

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
    trusted guard-helper: environment file + rlimits + seccomp + optional proxy relay
          |
          v
    untrusted AI CLI

The original repository is never mounted. The tool edits only its disposable copy. An optional
change export creates a separate review bundle; Guard never applies changes to the source tree.

## What works now

- Immutable built-in deny rules plus an additive user policy.
- NUL-delimited tracked and non-ignored-untracked Git enumeration.
- Descriptor-relative opening, Linux `openat2`, hard-link and special-file rejection, source
  mutation detection, and byte/file limits.
- A synthetic baseline commit without original objects, refs, hooks, config, alternates, or
  history.
- Bubblewrap namespaces on Linux and inside a mountless Lima guest on macOS.
- Environment clearing, explicit credential forwarding through a private file, and audit records
  that contain names but never credential values.
- Network denied by default, or controlled HTTPS CONNECT egress to explicit hostnames.
- A focused seccomp deny profile, rlimits, and optional cgroup v2 memory/task/CPU enforcement.
- Review-only export of added, modified, and deleted paths, with hostile output reopened and
  validated by the trusted staging layer.
- Offline Ed25519 verification against a pinned signer fingerprint before atomic tool install.
- Hostile denied-network and controlled-proxy probes through the real backend with `guard test`.

## One-command Grok workflow

After the backend and a Linux Grok binary are provisioned, the normal interactive workflow is:

    guard grok

Pass Grok arguments after `--`, for example:

    guard grok -- --model grok-build
    guard grok -- -p "review this repository"

`guard grok` is a thin application adapter over the vendor-neutral staging and runner core. It
always selects controlled egress to `cli-chat-proxy.grok.com`, disables Grok web search and memory,
uses inline terminal rendering, and runs `grok login` as an isolated preflight inside the
disposable synthetic home. The host refresh token and `~/.grok/auth.json` are never copied into
the workspace or Lima guest.

Guard reads only the current short-lived OAuth access token from an owner-only, singly linked
host auth file. When it is stale, Guard first asks the host Grok CLI to perform a silent refresh in
its built-in `strict` profile from an empty private working directory. If browser login is needed,
Guard prints the normal Grok login flow. The resulting access token travels through Guard's
private environment file; only the environment-variable names appear in the audit.

An access token is a credential intentionally given to the confined Grok process. Relaunch
`guard grok` after a long-running session reaches the token's expiry; live refresh brokerage is
not yet implemented.

## Build and self-test

Rust 1.85 or newer is required.

    cargo build --release
    cargo test --workspace

The workspace produces `target/release/guard` and `target/release/guard-helper`. Keep the two
binaries together on Linux. Run the real isolation probe after provisioning a backend:

    guard doctor
    guard test

Use `guard test --require-cgroup` when cgroup v2 delegation is a deployment requirement. CI runs
the hostile fixture probe through Bubblewrap on Ubuntu, in addition to the Rust test suite.

## Inspect and maintain staging

    guard stage /path/to/repository
    guard policy --check nested/.env.production
    guard policy --policy policy.example.toml
    guard gc --dry-run

`stage` keeps the sanitized workspace and prints its path. `run` normally deletes it after the
tool exits. If a process is killed before cleanup, `guard gc` removes old stages owned by the
current user; advisory locks protect active stages.

## Linux

Install Bubblewrap and Git, then run:

    guard doctor
    guard run -- my-ai-cli

Static tools outside `/usr` and `/bin` are mounted individually. Tools needing adjacent runtime
files must declare a narrow installation root:

    guard run --tool-root "$HOME/.local/lib/my-ai-cli" -- bin/my-ai-cli

Linux staging requires `openat2` (kernel 5.6 or newer). The default cgroup mode is `best-effort`:
rlimits and seccomp are always requested, while cgroup memory, process, and CPU quotas are used
when a delegated user systemd instance is available. Use `--cgroup required` to fail closed if it
is not. Before reporting cgroup enforcement, Guard launches a transient probe with the same
memory, swap, task, and CPU controller properties required by the real scope, then reads the probe
scope's cgroup v2 controller files back and requires exact effective values.

## macOS

The native macOS host does not provide Bubblewrap, Linux namespaces, seccomp, or cgroup v2.
Sandbox Guard therefore uses a dedicated Linux VM:

    brew install lima
    limactl create --name=sandbox-guard --mount-none template:default
    limactl start --mount-none sandbox-guard
    limactl shell sandbox-guard sudo apt-get update
    limactl shell sandbox-guard sudo apt-get install -y bubblewrap git ca-certificates rsync

Install a Linux build of `guard-helper` at `/usr/local/bin/guard-helper` inside the guest, together
with the selected AI CLI. The guest must be dedicated to Guard and contain no credentials or host
mounts. Then run:

    guard doctor --backend macos-lima
    guard test --backend macos-lima
    guard run --backend macos-lima -- my-ai-cli

For Grok installed as `/opt/sandbox-guard/tools/grok`, the final command becomes simply:

    guard grok

For `guard run`, Guard automatically requests a Lima PTY when both host standard input and output
are terminals, so interactive prompts, typing, and paste work without changing the isolation
policy. Interactive runs receive a fixed `TERM=xterm-256color` so line editing and bracketed paste
work without forwarding host terminal environment. Automation, pipelines, setup commands, and
`guard test` keep TTY allocation disabled. Bubblewrap still creates a new session to prevent
terminal injection into host processes.

Before every run, the backend starts Lima with `--mount-none`, inspects guest mounts, and refuses
known 9p, VirtioFS, and SSHFS host shares. It copies only the sanitized workspace and a private
environment file into a unique guest directory. After execution it retrieves the disposable
workspace with rsync's link-preserving transport into the private host stage, so hostile links are
not followed and the same hostile-output validator can reject them before producing a change
export. A per-run dangling-link canary makes retrieval fail closed if that transport ever
dereferences links. It then removes the guest directory.

## Network and credentials

The safe default creates a separate network namespace with no external connectivity:

    guard run --network denied -- my-ai-cli

Controlled mode keeps that namespace separation and exposes only a local relay to Guard's trusted
proxy:

    guard run --network controlled \
      --allow-host api.openai.com \
      --forward-env OPENAI_API_KEY \
      -- my-ai-cli

`--allow-host` accepts an exact hostname or a `*.subdomain.example` suffix. The proxy permits only
HTTP CONNECT to port 443, resolves outside the sandbox, rejects loopback/private/link-local/
metadata/documentation/transition addresses, connects to the validated IP, and requires the first
TLS ClientHello record to contain SNI exactly matching the CONNECT hostname. Successful
destinations—not URLs, headers, or credentials—are written to the run audit.

Proxy handshakes have wall-clock deadlines, established tunnels have idle timeouts, and both the
trusted proxy and sandbox relay cap concurrent connections.

The tool must honor the standard HTTP proxy environment variables. Direct networking still fails.
The proxy does not inspect HTTP paths or application payloads, and an allowed service can receive
anything intentionally present in the sanitized workspace plus any forwarded credential. Wildcard
allowlists and shared/CDN endpoints therefore deserve particular care.

Unrestricted mode remains available only as a noisy development escape hatch:

    guard run --network unrestricted --allow-unrestricted-network -- my-ai-cli

It shares the selected host or Lima-guest network namespace, exposing loopback, private/LAN
services, cloud metadata, and Linux abstract UNIX sockets. Filesystem isolation does not protect
abstract sockets.

Forwarded values are written to a mode-`0600` file inside a mode-`0700` runtime directory, then
loaded by the trusted helper after the sandbox starts. Values are absent from Bubblewrap,
`systemd-run`, and Lima argument lists and from audit JSON. The untrusted tool intentionally
receives—and can misuse—every credential named with `--forward-env`.

## Resource and syscall controls

Run flags set address-space, file-size, CPU-time, open-file, and process-count rlimits. When cgroup
v2 is available, Guard also sets `MemoryMax`, disables swap for the scope, sets `TasksMax`, and
applies `CPUQuota`:

    guard run --cgroup required --memory-mib 4096 --max-processes 128 \
      --cpu-percent 100 -- my-ai-cli

The seccomp filter rejects namespace creation/joining and namespace flags to `clone`; it reports
`clone3` unavailable so standard runtimes fall back to filterable `clone`. It also rejects mount
and new mount APIs, BPF, perf, io_uring, file handles, cross-process memory APIs, ptrace,
`pidfd_getfd`, userfaultfd, kernel-module/reboot/swap operations, and kernel keyring calls. This is
a focused deny profile, not a maintained OCI allowlist, and it makes no pathname-access claims.

## Reviewable change export

    guard run --export-changes "$HOME/guard-reviews/run-001" -- my-ai-cli

Guard treats the returned workspace as hostile. It ignores repository ignore rules, prunes
synthetic `.git`, reapplies policy, rejects links/special files/multiply linked files/mount
crossings, securely reopens each file relative to the workspace descriptor, and verifies stable
metadata while copying. The destination is new, private, outside both source and stage, and
published atomically. `manifest.json` records additions, modifications, deletions, hashes, modes,
and rejected output. The `files/` directory contains only accepted added/modified files.

This is deliberately not automatic copy-back. Review the manifest and content, resolve source
conflicts yourself, and apply only what you accept.

## Verified tool artifacts

`guard tool install` accepts a local artifact, detached Ed25519 signature, raw Ed25519 public key,
and the SHA-256 fingerprint of that raw public key. Signature and key files are hexadecimal:

    guard tool install \
      --name vendor-cli --version 1.2.3 \
      --artifact ./vendor-cli \
      --signature ./vendor-cli.sig.hex \
      --public-key ./vendor-ed25519.pub.hex \
      --signer-sha256 <64-hex-character-fingerprint>

Verification occurs before a new versioned directory is atomically published; an existing version
is never overwritten. Recheck an installation with:

    guard tool verify --root /path/to/vendor-cli/1.2.3 \
      --signer-sha256 <64-hex-character-fingerprint>

This is an offline verification foundation. Version 0.3 does not download updates, manage a
root-owned key policy, install a canonical root-owned wrapper, or automatically re-verify a tool
when `guard run` selects it.

## Policy and development status

The built-in policy rejects `.env` and credential environment files; private-key, keystore, and
wallet formats; SSH, AWS, GCloud, GitHub CLI, Docker, Kubernetes, Grok-auth, GnuPG, password-store,
Keychain, netrc, npm, PyPI, and Cargo credential paths; original `.git`; CCB session metadata;
links; special files; mount crossings; and multiply linked files. The rules are portable paths
relative to the selected source—Guard never imports host-specific absolute paths. See
[policy.example.toml](policy.example.toml) for additive rules and lower resource ceilings.
Filename rules cannot detect secret bytes copied into a distinct regular file under an innocent
name.

The complete blocker register, closed items, and remaining fixture gaps are in
[sandbox-guard-requirements.md](sandbox-guard-requirements.md). Unsupported security properties
must fail closed; they must never silently fall back to the original workspace.
