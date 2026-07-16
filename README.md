# Sandbox Guard

Sandbox Guard is an experimental, vendor-neutral boundary for AI coding CLIs. It gives an
untrusted tool a sanitized, disposable repository instead of the real host workspace.

> [!WARNING]
> Version 0.3 is an alpha security prototype, not a production sandbox. It now has controlled
> HTTPS egress, a focused seccomp deny profile, resource controls, a trusted review/apply handoff,
> and offline signature-verified tool installation. Important release blockers remain. Read the
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

The original repository is never mounted. The tool edits only its disposable copy. After the tool
exits, Guard can create a separate review bundle and apply accepted changes through trusted,
conflict-checked host code; the tool never receives access to the source tree or its Git state.

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
- Reviewable export and opt-in host apply of added, modified, and deleted paths, with hostile
  output reopened, policy-filtered, and validated by the trusted staging layer.
- Offline Ed25519 verification against a pinned signer fingerprint before atomic tool install.
- Hostile denied-network and controlled-proxy probes through the real backend with `guard test`.
- `guard setup` for idempotent owner-only state initialization plus actionable, machine-readable
  host and Lima readiness diagnostics without `sudo`, package installation, or VM mutation.

## One-command Grok workflow

After the backend and a Linux Grok binary are provisioned, the normal interactive workflow is:

    guard grok

Pass Grok arguments after `--`, for example:

    guard grok -- --model grok-build
    guard grok -- -p "review this repository"
    guard grok --scrollback
    guard grok --continue
    guard grok --resume 019f6389-2b2e-7b62-a650-2ff38c4b926e

`guard grok` is a thin application adapter over the vendor-neutral staging and runner core. It
always selects controlled egress to `cli-chat-proxy.grok.com`, disables Grok web search and memory,
keeps Grok's normal UI in inline terminal mode, and runs `grok login` as an isolated preflight
inside the disposable synthetic home. Unknown HTTPS destinations trigger a trusted host-native
approval dialog with deny, allow-once, and allow-for-session choices. On macOS the same alert has a
single optional “remember” checkbox, so persistence never requires a second confirmation. The
dialog can remember an exact-host allow or deny for later Guard sessions; `guard approvals` lists
those choices, while `guard approvals --forget HOST` and `guard approvals --clear` remove them.
`--no-egress-prompts` keeps the original fixed allowlist for automation or stricter sessions. Grok
mouse reporting is enabled by default so wheel scrolling works in the regular TUI. Press `Ctrl+S`
to enter trusted host selection/copy mode, which temporarily disables tool mouse reporting; press
it again to restore Grok scrolling. The toggle is consumed by Guard and is not delivered to Grok.
The optional `--scrollback` flag selects Grok's experimental native-scrollback renderer only when
the compiled profile permits that opt-in; the built-in profile currently does. It uses a visibly
different pinned-region layout. The host refresh token and `~/.grok/auth.json` are never
copied into the workspace or Lima guest.

On macOS, pressing `Ctrl+V` in an interactive Guard session explicitly imports one image from the
native clipboard. Guard decodes and re-encodes it as PNG under strict size and pixel limits, places
it in a per-run read-only `sandbox-guard-inputs` inbox, and pastes an `@` file reference into the
CLI. Guard never polls the clipboard. The inbox is removed before change export or Grok session
publication and disappears when the run ends. Normal terminal `Cmd+V` text paste is unchanged.

Guard reads only the current short-lived OAuth access token from an owner-only, singly linked
host auth file. When it is stale, Guard first asks the host Grok CLI to perform a silent refresh in
its built-in `strict` profile from an empty private working directory. If browser login is needed,
Guard prints the normal Grok login flow. The resulting access token travels through Guard's
private environment file; only the environment-variable names appear in the audit.

Grok conversation state is handled separately from credentials. Guard exposes only a private,
Guard-owned staged copy of `/home/guard/.grok/sessions`, validates the returned tree with the same
descriptor-safe policy layer, and atomically publishes a snapshot keyed to the canonical source
directory. It never mounts the host `~/.grok` directory. Use `--continue` for the latest stored
conversation or `--resume SESSION_ID` for a specific one. Sessions created before this feature, or
outside Guard, are not imported automatically.

When Grok exits, Guard validates the returned workspace and shows a trusted terminal prompt to
review, apply, keep, or discard its changes. Apply is performed by Guard only after every affected
host file still matches the pre-run baseline. The original `.git`, remotes, SSH agent, and Git
credentials are never exposed to Grok; after apply, use normal host `git diff`, commit, and push.
Use `--no-change-review` to discard changes without prompting, or `--export-changes DIRECTORY` to
keep the manual bundle workflow. If Grok creates `.env` or any other policy-denied/unsafe path,
that content is never opened for export or copied to the host, and automatic apply is disabled for
the entire run. Every deletion requires an exact typed host confirmation. Mass deletion requires
a successful trusted diff first, so a one-key Apply cannot propagate a sandbox-local `rm -rf` into
the real working tree.

An access token is a credential intentionally given to the confined Grok process. Relaunch
`guard grok` after a long-running session reaches the token's expiry; live refresh brokerage is
not yet implemented.

## Install

Alpha release archives for macOS ARM64 and Linux x86-64/ARM64, with
`SHA256SUMS` and a per-file manifest, are published from signed tags as
GitHub prereleases. Verify the tag signature and checksums first, then follow
[docs/INSTALL.md](docs/INSTALL.md) for install, upgrade, rollback, and removal
steps, including manual Lima guest provisioning on macOS. The artifacts are
alpha prototypes, not production-ready. Maintainers cut releases with
[docs/RELEASE.md](docs/RELEASE.md).

After installing the binary, run `guard setup`. Plain setup repairs only Guard-owned
private directories and prints manual commands for missing external
dependencies. `guard setup --check --json` performs no repairs and emits the
versioned readiness report.

On the macOS Lima backend, `guard setup --create-instance` is the only command
that creates the dedicated VM, and only when it is absent. It runs exactly
`limactl create --name <instance> --mount-none template:default`, then re-inspects
the result and refuses to report success unless the instance exists with no host
mounts. It never starts, reconfigures, or deletes a VM: an existing instance of
any status or configuration is left untouched, and a failed or unsafe creation is
reported for manual inspection rather than auto-deleted. Creation requires an
interactive typed confirmation (`CREATE LIMA INSTANCE <instance>`) or `--yes` for
non-interactive hosts; `--create-instance --json` requires `--yes` so machine
output is never mixed with a prompt. `--create-instance` conflicts with `--check`,
and the newly created instance remains stopped.

`guard setup --start-instance` is the separate, explicit startup action. It
accepts only an existing instance whose configuration declares no host mounts,
requires the typed phrase `START LIMA INSTANCE <instance>` (or `--yes`), and runs
exactly `limactl --tty=false start --mount-none <instance>`. Guard then requires
the instance to report `Running` and checks the live mount table for host-sharing
filesystems. It never stops, reconfigures, or deletes a VM; a failed post-check
leaves the running instance for manual inspection. An already-running mountless
instance is left unchanged and still passes through the normal readiness checks.
The start action conflicts with `--check` and `--create-instance`, and JSON mode
requires `--yes`. Guest packages, the helper, and the selected vendor tool all
remain separate manual provisioning steps.

`guard uninstall` is the matching non-mutating removal plan. Confirmed state
removal requires `--remove` and the exact terminal phrase (or explicit
`--remove --yes` automation); binaries, Lima, vendor state, and locked active
runs are never silently removed.

Inspect the compiled trusted vendor profiles with `guard profile list`,
`guard profile show grok`, and `guard profile explain grok`. `guard profile
lint FILE` can parse and validate an explicitly selected external TOML file,
but the lint-only result cannot be installed, trusted, or executed. v0.3 never
uses owner- or project-supplied profiles for a run. Scripts should use `--json`
rather than relying on the human-oriented output. `profile lint --json` emits
JSON for a valid document; invalid input exits 1 and reports a sanitized error
on standard error.

`guard profile install` verifies a signed profile package and stores it in an
owner-private location Guard derives internally; there is no store-path flag,
downloader, or ambient signer trust. The signature authenticates the exact
profile bytes under an owner-pinned signer fingerprint — it does not attest a
release binary. `guard profile list` then also shows installed profiles with
their provenance and exact distribution version, and `guard profile show NAME
--version VERSION` re-verifies and prints one installed profile; there is no
latest-version fallback. Every installed-profile read re-checks the stored
bytes, signature, signer pin, manifest, and path identity before any content is
shown. Installed profiles are content-only this milestone: they are never
runtime-effective, cannot be reached by `guard grok` or any run, and never
shadow a built-in name. `guard profile remove NAME VERSION` deletes only that
exact name and version. The signed-profile install and inspection commands are
documented in more detail under "Signed vendor profiles" below.

The Grok adapter currently consumes the compiled launch and Lima guest
executable, egress, credential, session, clipboard-import, and terminal sections, including the
runner-validated writable-home mount target;
`profile explain grok` reports the exact partial-migration status without treating
linted files as executable.
The remaining seccomp compatibility field is descriptive and CI-cross-pinned to the fixed helper
filter; neither built-in nor linted profiles can modify runtime syscall enforcement.

`guard profile effective grok` previews the built-in after validating the optional owner-only
`profile-overlays.toml` at Guard's fixed configuration directory; `profile explain` reports the
same overlay provenance. `guard grok` loads that same effective profile before authentication,
staging, or backend setup. A present invalid overlay aborts the run rather than silently falling
back to the wider built-in profile. The file cannot name commands, paths, credentials, mounts, or
new hosts, and there is deliberately no project-relative or `--overlay PATH` input. It can only
remove configured egress reach, disable optional approval/clipboard/terminal behavior, or lower
managed-session quotas.

For example, an owner can place this private file at the path shown by
`guard profile effective grok`:

```toml
schema_version = 1

[profiles.grok]
interactive_approval = false
clipboard_image_import = false
mouse_reporting_default = false
native_scrollback_opt_in = false
max_session_total_bytes = 104857600
max_session_files = 1000
```

## Build and self-test

Rust 1.85 or newer is required.

    cargo build --release
    cargo test --workspace

The workspace produces `target/release/guard` and `target/release/guard-helper`. Keep the two
binaries together on Linux. Run the real isolation probe after provisioning a backend:

    guard setup --check
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

    guard setup
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

    guard setup --backend macos-lima
    guard setup --check --backend macos-lima
    guard test --backend macos-lima
    guard run --backend macos-lima -- my-ai-cli

For Grok installed as `/opt/sandbox-guard/tools/grok`, the final command becomes simply:

    guard grok

On the Lima backend, the compiled Grok profile pins both the main process and matching login
preflight to that absolute guest path instead of falling back to another `grok` on guest `PATH`.
The run audit therefore records the absolute tool command on macOS; Linux retains the compiled
`grok` command while the runner resolves its host executable as before.

For `guard run`, Guard automatically requests a Lima PTY when both host standard input and output
are terminals, so interactive prompts, typing, and paste work without changing the isolation
policy. Guard owns a narrow host-side PTY broker for interactive runs: it synchronizes window size,
intercepts raw `Ctrl+V` for explicit clipboard-image import and raw `Ctrl+S` for the trusted
scroll/selection toggle, blocks host-sensitive OSC clipboard controls and opaque
terminal-multiplexer passthrough from the untrusted tool, and restores only the mouse-reporting
modes actually requested by the tool when scroll mode resumes. Interactive runs receive a fixed
`TERM=xterm-256color` so line editing and bracketed paste work without forwarding host terminal
environment. Automation, pipelines, setup commands, and `guard test` keep TTY allocation disabled.
Bubblewrap still creates a new session to prevent terminal injection into host processes.

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

Interactive sessions can ask Guard to approve an otherwise denied HTTPS hostname without stopping
the tool or editing policy:

    guard run --network controlled \
      --allow-host api.openai.com \
      --ask-egress \
      -- my-ai-cli

`--allow-host` accepts an exact hostname or a `*.subdomain.example` suffix. The proxy permits only
HTTP CONNECT to port 443, resolves outside the sandbox, rejects loopback/private/link-local/
metadata/documentation/transition addresses, connects to the validated IP, and requires the first
TLS ClientHello record to contain SNI exactly matching the CONNECT hostname. Successful
destinations—not URLs, headers, or credentials—are written to the run audit.

`--ask-egress` carries approval requests over a private protocol pipe from the trusted proxy to a
host-native dialog. The untrusted tool never receives approval input. A grant is always for the
exact requested hostname on port 443 and can cover one CONNECT, the current Guard session, or
future sessions when the user explicitly remembers the choice. The macOS alert collects the scope
and optional remember choice in one step; Linux presents persistent choices in the same `zenity`
window. Remembered allow and deny choices live in an owner-only Guard data file outside every
staged or sandbox-writable tree. Dialog
cancellation, timeout, malformed protocol, missing native UI, persistence failure, and
noninteractive execution all fail closed. Native prompts are serialized and capped at 16 per run
to bound prompt flooding. Approval decisions are recorded separately in the audit. On macOS Guard
uses the system dialog service. On Linux it uses `zenity` when available; otherwise the request is
denied so the tool cannot impersonate a trusted prompt in the shared terminal.

Because TLS remains end-to-end, the dialog can show and enforce the CONNECT hostname and port but
cannot show the full URL, HTTP method, headers, or body. Guard states that limitation in the prompt
instead of pretending to inspect encrypted request details.

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

## Trusted change review and apply

Interactive Grok runs enable the post-run review/apply prompt by default. The vendor-neutral
runner exposes the same flow explicitly:

    guard run --review-changes -- my-ai-cli

The default action is to keep the private pending bundle. `diff` uses trusted host Git with global
and system configuration, external diff drivers, text conversion, and paging disabled. `apply`
preflights every affected host path against the staging baseline before the first mutation, then
uses descriptor-relative, no-symlink operations, atomic per-file renames, and rollback records.
Added paths must still be absent; modified and deleted paths must retain their baseline hash,
owner, link count, filesystem, size, and executable class. Git metadata and credentials remain
host-only. A deletion can reach the core apply transaction only after Guard receives explicit
deletion authorization from the trusted prompt. Every deletion requires typing a count-bound
phrase such as `DELETE 3 FILES OF 37`. Removal of the entire baseline, at least 50 files, or at
least 5 files comprising 25% of the baseline is treated as mass deletion; Apply stays unavailable
until the trusted diff renders successfully.

For a manual bundle without an apply prompt:

    guard run --export-changes "$HOME/guard-reviews/run-001" -- my-ai-cli

Guard treats the returned workspace as hostile. It ignores repository ignore rules, prunes
synthetic `.git`, reapplies policy, rejects links/special files/multiply linked files/mount
crossings, securely reopens each file relative to the workspace descriptor, and verifies stable
metadata while copying. The destination is new, private, outside both source and stage, and
published atomically. `manifest.json` records additions, modifications, deletions, hashes, modes,
and rejected output. The `files/` directory contains only accepted added/modified files.

Any rejected path disables automatic apply. In particular, `.env`, private keys, credential files,
links, special files, hard-link aliases, and mount crossings are never included under `files/`.
Their path and rejection reason are recorded without copying their contents. The explicit export
form remains a review bundle and is never applied automatically.

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

## Signed vendor profiles

`guard profile install` verifies a detached Ed25519 signature over the exact profile package bytes
against a pinned signer fingerprint, then atomically publishes the package into an owner-private
store. The store path is derived internally from Guard's data directory; there is deliberately no
store-path flag, project-relative lookup, downloader, or ambient signer trust. Signature and key
files are hexadecimal:

    guard profile install \
      --package ./vendor-profile.toml \
      --signature ./vendor-profile.sig.hex \
      --public-key ./vendor-ed25519.pub.hex \
      --signer-sha256 <64-hex-character-fingerprint>

The signature authenticates the exact profile bytes under the owner-pinned signer fingerprint. It
does not attest a release binary, and installing a profile does not make it executable. An existing
name and version is never overwritten, and a package whose profile name matches a built-in is
refused so installed profiles can never shadow a compiled one.

List installed profiles alongside the built-ins, re-verify and print one installed profile by its
exact version, or remove exactly one name and version:

    guard profile list
    guard profile show vendor-profile --version 1.2.3
    guard profile remove vendor-profile 1.2.3

Every installed-profile inspection re-reads the stored bytes and re-checks the signature, signer
pin, package hash, manifest, and stored path identity before printing anything; a tampered
installation fails closed. `guard profile show NAME --version VERSION` has no latest-version
fallback, and a corrupt installed store never hides the built-in listing. Exact-version removal
does not require a valid signature, so a corrupted installation remains removable; it still
validates the owner-private store path and refuses symlink redirection. Installed profiles are
content-only in this milestone: they are not runtime-effective and cannot be reached by `guard
grok`, `guard run`, the built-in resolver, or owner overlays. `guard uninstall` removes the profile
store together with the rest of Guard's private data directory.

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
