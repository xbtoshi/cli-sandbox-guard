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

`guard setup` is intentionally unprivileged: it creates or tightens only
Guard-owned directories below the current user's data/configuration roots.
It prints commands for missing host dependencies but never invokes `sudo`, a
package manager, or a network downloader. `guard setup --check` is the
read-only/reporting form; add `--json` for the versioned machine-readable
schema. Exit status is 0 when ready, 1 when known repairs remain, and 3 when a
required probe failed and readiness is unknown.

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
mounts, guest packages, and a missing or version-mismatched helper. It never
starts, creates, deletes, or modifies a Lima instance.

Provision the dedicated Lima guest. **Guest provisioning remains a manual,
trusted operation in v0.3**: everything you place inside the guest becomes
part of the trusted computing base. The guest must be dedicated to Guard,
created with `--mount-none`, and must never contain credentials or host
mounts:

    brew install lima
    limactl create --name=sandbox-guard --mount-none template:default
    limactl start --mount-none sandbox-guard
    limactl shell sandbox-guard sudo apt-get update
    limactl shell sandbox-guard sudo apt-get install -y bubblewrap git ca-certificates rsync util-linux

Install the packaged Linux ARM64 helper inside the guest (the guest
distribution needs glibc 2.39 or newer, e.g. Ubuntu 24.04+):

    limactl copy sandbox-guard-<version>-macos-arm64/lima-guest/guard-helper sandbox-guard:/tmp/guard-helper
    limactl shell sandbox-guard sudo install -m 0755 /tmp/guard-helper /usr/local/bin/guard-helper
    limactl shell sandbox-guard rm /tmp/guard-helper

Install the AI CLI you intend to confine inside the guest as well (for Grok:
`/opt/sandbox-guard/tools/grok`). Then validate:

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
