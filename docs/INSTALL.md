# Installing Sandbox Guard (v0.3 alpha)

> [!WARNING]
> Every v0.3 artifact is an **alpha security prototype and is not
> production-ready**. Open release blockers are tracked in
> [sandbox-guard-requirements.md](../sandbox-guard-requirements.md). Read the
> [security model](SECURITY_MODEL.md) before running any untrusted tool
> through Guard.

Sandbox Guard ships two binaries:

- `guard` — the trusted CLI you run on the host.
- `guard-helper` — the trusted in-sandbox supervisor. On Linux it runs on the
  host next to `guard`; on macOS a **Linux ARM64** build of it runs inside the
  dedicated Lima guest.

## Release artifacts

Each release provides three archives plus `SHA256SUMS` and `manifest.json`:

| Archive | Contents |
| --- | --- |
| `sandbox-guard-<version>-linux-x86_64.tar.gz` | `guard`, `guard-helper` (both ELF x86-64), `LICENSE`, `ALPHA.txt` |
| `sandbox-guard-<version>-linux-aarch64.tar.gz` | `guard`, `guard-helper` (both ELF aarch64), `LICENSE`, `ALPHA.txt` |
| `sandbox-guard-<version>-macos-arm64.tar.gz` | `guard` (Mach-O arm64), `lima-guest/guard-helper` (ELF aarch64 for the Lima guest), `LICENSE`, `ALPHA.txt` |

`manifest.json` lists the SHA-256 of every archive and every file inside it.
The `lima-guest/guard-helper` in the macOS archive is byte-identical to the
`guard-helper` in the Linux ARM64 archive; the release workflow refuses to
publish otherwise.

## Verify before installing

Be clear about what each check proves in this alpha:

- `git verify-tag` proves the **source revision** was tagged by the holder of
  the maintainer key — a key you must have obtained and trusted through some
  independent channel. It does **not** cryptographically bind the binaries:
  the archives are built by GitHub-hosted runners, and v0.3 ships no signed
  provenance or build attestations. That remains an open production gate in
  ROADMAP.md.
- `SHA256SUMS` by itself detects download corruption only. It is published
  through the same release channel as the archives, so a coordinated
  replacement of an archive together with its checksum line would not be
  detected. It detects substitution only when you independently compare it
  against the `SHA256SUMS` printed in the release workflow's `verify` job log
  — and that log is still GitHub-hosted output, not signed provenance.
- So, as a compensating check: open the release's GitHub Actions run (linked
  from the tagged commit), confirm it ran the `Release` workflow for that
  tag, and compare the `SHA256SUMS` printed in the `verify` job log with your
  local file.

Steps, assuming you downloaded your platform's archive plus `SHA256SUMS`:

    # 1. Verify the tag signature against the maintainer's key.
    git -C cli-sandbox-guard verify-tag v<version>

    # 2. Verify the checksum of the one archive you downloaded.
    sha256sum --ignore-missing -c SHA256SUMS       # Linux
    shasum -a 256 --ignore-missing -c SHA256SUMS   # macOS

`--ignore-missing` skips the two archives you did not download; the command
must still report `OK` for yours (it fails if no file matches). Do not
install artifacts that fail any check.

Maintainers verifying a full draft asset set should use
`scripts/verify-release-artifacts.sh published <version> <dir>` instead; see
[RELEASE.md](RELEASE.md).

## Build from source (all platforms)

Rust 1.85 or newer is required.

    git clone https://github.com/xbtoshi/cli-sandbox-guard
    cd cli-sandbox-guard
    git verify-tag v<version> && git switch --detach v<version>
    cargo build --release --locked
    cargo test --workspace --locked

This produces `target/release/guard` and `target/release/guard-helper` for the
build host. A macOS host additionally needs a Linux ARM64 `guard-helper` for
the Lima guest; build one inside the guest itself or take it from the
`linux-aarch64` release archive.

## Binary install — Linux (x86-64 or ARM64)

Keep the two binaries together in the same directory, and make sure that
directory is on your `PATH` (`~/.local/bin` is on the default `PATH` of most
modern distributions; add `export PATH="$HOME/.local/bin:$PATH"` to your
shell profile if `guard` is not found):

    tar -xzf sandbox-guard-<version>-linux-<arch>.tar.gz
    install -d ~/.local/bin
    install -m 0755 sandbox-guard-<version>-linux-<arch>/guard ~/.local/bin/guard
    install -m 0755 sandbox-guard-<version>-linux-<arch>/guard-helper ~/.local/bin/guard-helper

Requirements: Bubblewrap, Git, a kernel with `openat2` (5.6+), and glibc 2.39
or newer (the binaries are built on Ubuntu 24.04). Initialize Guard's private
state and inspect every prerequisite before validating the live boundary:

    guard setup
    guard setup --check
    guard test

On a native Ubuntu 24.04 x86-64 or ARM64 host whose common WSL/container markers
are absent, Guard can
install only the missing fixed runtime package subset after explicit consent:

    guard setup --install-linux-packages

Review the exact action, then type `INSTALL LINUX PACKAGES ubuntu-24.04`, or add
`--yes` for an already-reviewed noninteractive invocation. The command uses
fixed absolute `/usr/bin/sudo --non-interactive -- /usr/bin/env -i ...
/usr/bin/apt-get` argv and only the package names `bubblewrap`, `git`, and
`ca-certificates`; APT is passed `--no-remove`. The missing subset shown before
confirmation is an upper bound: if later revalidation adds a package, Guard aborts
and requires a fresh confirmation. Versions, repository metadata, package-manager configuration,
and root-run package hooks come from and therefore trust the host's configured
Ubuntu APT sources. Guard refuses root, detected common WSL/container environments, other distro
versions, and unsupported architectures. It does not change sysctls, AppArmor,
setuid bits, systemd/cgroup policy, Guard binaries, or `guard-helper`, and it
does not clean up partial APT state automatically.

When cgroup enforcement is required for deployment, explicitly launch the
disposable namespace and exact transient-cgroup probes as part of setup readiness,
then run the complete hostile probe:

    guard setup --check --require-cgroup
    guard test --require-cgroup

Without `--require-cgroup`, `guard setup --check` runs presence/static diagnostics
only. The explicit probe flag invokes no sudo or repair and makes no persistent
host-policy change.

Plain `guard setup` is intentionally unprivileged: it creates or tightens only
Guard-owned directories below the current user's data/configuration roots and
prints commands for missing host dependencies. The explicit Linux package action
above and the macOS-only creation, startup, and guest-package actions are separate
confirmed exceptions. Creation and startup never invoke `sudo`; guest-package
installation invokes passwordless sudo only inside an already-running,
verified-mountless guest; only `--install-linux-packages` invokes host sudo.
`guard setup --check` is the read-only/reporting form; add `--json` for the
versioned machine-readable schema. Exit status is 0 when ready, 1 when known
repairs remain, and 3 when a required probe failed and readiness is unknown.

## Binary install — macOS (Apple Silicon)

> [!WARNING]
> The macOS `guard` binary in this alpha is **not Developer ID signed and not
> notarized** (it carries only an ad-hoc linker signature with no
> TeamIdentifier, and `spctl --assess` rejects it). If the archive was
> downloaded by a browser, Gatekeeper will block the quarantined binary.
> **Building from source is the preferred install path on macOS.** If you use
> the binary anyway: complete every verification step above first (tag,
> checksum, workflow-log comparison), and only then remove the quarantine
> attribute from the one extracted binary —
> `xattr -d com.apple.quarantine sandbox-guard-<version>-macos-arm64/guard`.
> Never disable Gatekeeper globally and never clear quarantine attributes
> recursively or on paths you have not verified. Removing the attribute does
> not make the binary authentic; it only records your own decision to trust
> the verification you performed.

Install the host binary into a directory on your `PATH` (create it first and
add `export PATH="$HOME/.local/bin:$PATH"` to your shell profile if needed):

    tar -xzf sandbox-guard-<version>-macos-arm64.tar.gz
    install -d ~/.local/bin
    install -m 0755 sandbox-guard-<version>-macos-arm64/guard ~/.local/bin/guard

Run `guard setup --check --backend macos-lima` first for a readiness report.
The command detects a missing or stopped instance, declared or live host
mounts, guest packages, and a missing or version-mismatched helper. `guard setup
--check` never starts, creates, deletes, or modifies a Lima instance.

Create the dedicated mountless instance. Guard can do this one step for you:

    brew install lima
    guard setup --create-instance --backend macos-lima

`guard setup --create-instance` creates the instance only when it is absent,
running exactly `limactl create --name sandbox-guard --mount-none template:default`
and then verifying it exists with no host mounts. It prompts for the typed phrase
`CREATE LIMA INSTANCE sandbox-guard` (or accepts `--yes`), and it never starts,
reconfigures, or deletes a VM. An existing instance is left untouched. The
equivalent manual command is:

    limactl create --name=sandbox-guard --mount-none template:default

Start the stopped instance through Guard's second explicit lifecycle action:

    guard setup --start-instance --backend macos-lima

The command accepts only a present, declared-mountless instance with status
`Stopped`, requires the typed phrase `START LIMA INSTANCE sandbox-guard` (or
`--yes`), and invokes exactly
`limactl --tty=false start --mount-none sandbox-guard`. It then requires the
instance to report `Running` and rejects any live 9p, virtiofs, sshfs, or
reverse-sshfs host-sharing mount. It never stops, reconfigures, or deletes a VM;
if a post-start check fails, inspect the running instance manually. The
equivalent manual command is:

    limactl --tty=false start --mount-none sandbox-guard

Install the fixed guest package-name set through the third explicit action:

    guard setup --install-guest-packages --backend macos-lima

The action requires a running instance with safe declared and live mounts. It
is an idempotent no-op when `/usr/bin/bwrap`, `/usr/bin/git`, `/usr/bin/rsync`,
`/usr/bin/findmnt`, and the CA bundle are already present. Otherwise it requires
the typed phrase `INSTALL GUEST PACKAGES sandbox-guard` (or `--yes`), revalidates
the instance around both package-manager mutations, and runs the equivalent of:

    limactl --tty=false shell sandbox-guard -- /usr/bin/sudo --non-interactive -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none /usr/bin/apt-get update
    limactl --tty=false shell sandbox-guard -- /usr/bin/sudo --non-interactive -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none /usr/bin/apt-get install --yes --no-install-recommends --reinstall bubblewrap git ca-certificates rsync util-linux

The package names are fixed, but versions come from—and therefore trust—the
guest's configured APT repositories, package-manager configuration, and root-run
hooks/scripts. This action does not use Guard's runtime egress broker. A partial
failure is reported and left for inspection or an idempotent retry—Guard never
runs package cleanup or stops/deletes the VM. Machine-readable `--json` mode
requires `--yes`.

Install the packaged Linux ARM64 helper with its exact digest from the verified
release manifest (the guest distribution needs glibc 2.39 or newer, e.g. Ubuntu
24.04+):

    guard setup --install-guest-helper sandbox-guard-<version>-macos-arm64/lima-guest/guard-helper \
      --guest-helper-sha256 <64-hex-digest-from-the-verified-manifest> \
      --backend macos-lima

The action requires the exact typed phrase `INSTALL GUEST HELPER sandbox-guard`
(or `--yes`; JSON mode requires it). It does not download the artifact or decide
which release to trust. It opens the caller-selected file with `O_NOFOLLOW`,
requires current-user ownership, a regular file with one link and a stable bounded
size, checks the exact digest and Linux AArch64 ELF header, then copies only a
read-only snapshot from an owner-private temporary directory. The running Lima
instance is revalidated as uniquely present, declared mountless, and live
mountless around mutation.

The snapshot directory is created atomically as mode 0700 beneath a real,
current-user-owned HOME directory opened without following symlinks; ambient
`TMPDIR` is not used. `limactl copy` is path-based, so another process with the
same host UID remains able to race or replace that pathname before Lima opens it.
Do not run setup concurrently with untrusted processes under the same host user.

The guest copy is hashed before installation. Guard installs a unique root-owned
mode-0755 sibling in `/usr/local/bin`, verifies its hash, regular/single-link
metadata, and exact version, then atomically renames it to
`/usr/local/bin/guard-helper` and repeats those checks. An already exact helper is
an idempotent no-op. Fixed absolute guest executables and discrete argv are used
throughout—never a shell or host sudo. If a copy, install, rename, cleanup, or
postcondition fails, the diagnostic states whether guest temporary artifacts may
remain. Guard does not restore an earlier helper and never starts, stops,
reconfigures, or deletes the VM as part of this action.

Provision a selected vendor tool only from an exact installation already in
Guard's local verified-tool store. For the currently compiled `grok` profile:

    guard setup --install-guest-tool grok \
      --guest-tool-root '/exact/root/reported/by/guard/tool/install' \
      --guest-tool-signer-sha256 '<64-hex-owner-pinned-fingerprint>' \
      --backend macos-lima

This accepts only a compiled built-in profile and derives the destination solely
from that profile (`/opt/sandbox-guard/tools/grok`); there is no guest destination
option. Guard re-verifies the stored detached Ed25519 signature and owner-supplied
signer fingerprint, snapshots the authenticated bytes without reopening the
installed artifact, and requires a unique running declared/live mountless guest.
It never downloads or executes the vendor binary. After the typed phrase
`INSTALL GUEST TOOL grok sandbox-guard` (or `--yes`), Guard verifies copied and
root-owned staged hash/size, then atomically renames the files. A root-owned
`0644` public-identity receipt beside the `0755` artifact binds the compiled profile, local
manifest version, artifact hash/size, and signer fingerprint. Setup diagnostics
re-check the receipt, metadata, and artifact hash without running the tool. An
exact match is an unprompted no-op; a safe partial or different installation
requires confirmed replacement, with partial state reported on failure.

The signer fingerprint is a trust decision made by the machine owner, not a
value Guard discovers or downloads. As of July 19, 2026, xAI's public Grok CLI
release materials do not publish a detached artifact-signing identity suitable
for this flow. Do not substitute a checksum, repository commit signer, TLS
certificate, or key invented by Guard. Until xAI supplies a qualified detached
signature and stable public-key identity (or the owner independently establishes
equivalent trusted distribution), this Phase 1 item remains incomplete.

Then validate:

    guard setup --backend macos-lima
    guard setup --check --backend macos-lima
    guard test --backend macos-lima

If setup reports the instance as `unsafe` because it contains a host-sharing
mount, it deliberately offers no automatic repair: inspect the instance and
decide whether to remove it yourself. Setup never deletes or recreates a VM.

## Upgrade

1. Download and verify the new release exactly as above.
2. Replace `guard` and `guard-helper` **together**. They are released and
   tested as one version; do not mix versions across the pair.
3. On macOS, reinstall `lima-guest/guard-helper` into the guest in the same
   step, using the `limactl copy` commands above.
4. Re-run `guard setup --check` and `guard test` (with `--backend macos-lima` on
   macOS) before the next real session.

Remembered egress decisions, audit records, and policy files are kept in
Guard's private data directory and survive upgrades. Guard fails closed on
state files whose versions it does not understand.

## Rollback

Keep the previous release archive and its `SHA256SUMS` until you have
validated an upgrade. To roll back, reinstall the older binaries (both of
them, and the guest helper on macOS) using the same steps, then re-run
`guard setup --check` and `guard test`. Never reuse a version number for
different bytes; if a release is bad, the fix ships as a new prerelease
version.

## Removal

Run `guard uninstall` first to inspect the exact Guard-owned data and
configuration roots plus the manual binary/VM steps. The default is always a
non-mutating dry run; add `--json` for its versioned machine-readable report.
To remove only the validated Guard-owned data/configuration roots, run
`guard uninstall --remove` and type the exact confirmation phrase on a TTY.
For explicit non-interactive automation use
`guard uninstall --remove --yes`; `--remove` without `--yes` never deletes in
a non-interactive or JSON invocation. Unsafe ownership, symlink, mode, active
stage, or active egress-decision-lock checks abort before any root is renamed.
Stop Guard sessions before removal. Guard detects active stages under its
default staging base, but it cannot discover sessions launched with a custom
`--staging-base`; those sessions must be stopped explicitly.
Installed binaries, Lima, vendor state, and stale stages remain separate
manual/Guard-GC steps and are never swept into state-root deletion.

1. Optionally clean leftover stages first: `guard gc`.
2. Delete the binaries: `guard` and `guard-helper` from your install
   directory.
3. Delete Guard-owned state (contains remembered egress decisions, audit
   records, pending change bundles, and the verified tool store):
   - Linux: `~/.local/share/sandbox-guard` and `~/.config/sandbox-guard`
   - macOS: `~/Library/Application Support/com.xbtoshi.sandbox-guard`
4. On macOS, delete the dedicated guest if you no longer need it:
   `limactl delete sandbox-guard` (stop it first if Lima requires that).

`guard setup` creates or tightens only Guard-owned private state directories;
it does not write outside those directories, modify shell profiles, invoke
`sudo`, or create privileged files. Everything else on this page — the
binaries in `~/.local/bin`, the Lima instance, and the guest's
`/usr/local/bin/guard-helper` — is created by you through the manual steps
above, which is why removal is also a manual checklist.
