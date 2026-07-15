# Release process (v0.3 alpha)

This is the maintainer checklist for cutting an alpha release. The mechanics
live in `.github/workflows/release.yml`, `scripts/package-release.sh`, and
`scripts/verify-release-artifacts.sh`; the scripts are covered by
`scripts/test-release-scripts.sh`.

## Guarantees the pipeline enforces

- The tag name must equal `v` + the Cargo workspace version, the tag must be
  an **annotated** tag object, the tagged commit must already be on `main`,
  and `Cargo.lock` must be consistent with `Cargo.toml`; otherwise the
  workflow fails before building anything.
- Every target job runs `cargo fmt --check`, `cargo clippy -D warnings`, and
  `cargo test --workspace --release --locked` against the same tree that
  produces the packaged binaries; both Linux jobs additionally run the live
  Bubblewrap hostile-fixture probe (`guard test --backend linux-bwrap
  --require-cgroup`) against the exact release binaries being packaged.
- The macOS archive embeds the `guard-helper` built and tested by the Linux
  ARM64 job; verification fails if the embedded helper is not byte-identical
  to the one in the `linux-aarch64` archive.
- A read-only `verify` job runs `scripts/verify-release-artifacts.sh
  prepublish`, which validates each archive's member-name list before
  extraction (no duplicates, traversal, absolute paths, or extras), forbids
  every member type except regular files and directories, requires the exact
  expected file set with correct executable modes and binary formats, and
  only then emits `SHA256SUMS` and `manifest.json`. The resulting
  `SHA256SUMS` is printed into the workflow log for later comparison.
- Publication is a separate job that runs only on the validated tag path. It
  is the only job with `contents: write`; it checks out no code, executes no
  repository scripts, requires the exact expected asset set, re-checks
  `SHA256SUMS`, and uploads the verified bundle unchanged as a **draft**
  prerelease. Nothing becomes public without a human review step. Dry runs
  (`workflow_dispatch`) never instantiate the write-scoped job, even when
  dispatched against a tag ref: publication is double-gated on
  `event_name == push` in both the preflight output and the publish job's
  own condition, and a policy test pins that invariant.
- All third-party actions are pinned to immutable full commit SHAs, checkouts
  use `persist-credentials: false` (except preflight, which needs the
  read-only token for `git fetch`), and no secrets beyond the default
  `GITHUB_TOKEN` are used. `GH_TOKEN` is explicitly placed in the environment
  only for the single `gh` step; note that GitHub allows any action to read
  the job's `github.token`, so the pinned `download-artifact` action running
  inside the write-scoped publish job is part of the release trusted
  computing base — pin reviews for that action matter as much as for the
  build steps.

## What is manual, and must stay manual in this phase

**Tag signing.** CI has no key infrastructure, so it can enforce only that the
tag is annotated and on `main`; it cannot verify a signature. Therefore:

1. Release tags MUST be created with `git tag -s` (GPG or SSH signing key of
   a maintainer). Never release from a lightweight or unsigned tag.
2. Before publishing the draft release, a maintainer — ideally not the tagger
   — MUST run `git verify-tag <tag>` locally against the known maintainer key
   and confirm the tag points at the reviewed commit.

Inventing workflow-side signing with repository secrets would put the signing
key inside the CI trust domain; that is deliberately out of scope until the
signed, provenance-bearing release gate (see ROADMAP.md production gates).
Until that gate closes, the archives themselves carry **no cryptographic
provenance**: the signed tag authenticates the source revision, not the
binaries GitHub built from it.

## Checklist

1. Confirm `main` is green in CI and that any change to a trusted boundary
   component in this release has had an independent adversarial review.
2. Confirm the workspace version in `Cargo.toml` is the version to release
   (bump it and run `cargo check` to refresh `Cargo.lock` if not; commit via
   normal review).
3. On the reviewed `main` commit, create and push a signed annotated tag:

       git tag -s v<version> -m "Sandbox Guard v<version> (alpha)"
       git push origin v<version>

4. The release workflow builds, tests, packages, verifies, and uploads a
   draft prerelease. A `workflow_dispatch` run of the same workflow is a full
   dry run that never publishes; use it to validate changes to the pipeline.
5. Before pressing publish on the draft:
   - `git verify-tag v<version>` against the maintainer key;
   - download **all** draft assets (the three `.tar.gz` archives,
     `SHA256SUMS`, and `manifest.json`) into an otherwise empty directory
     and run:

         scripts/verify-release-artifacts.sh published <version> <dir>

     This recomputes every archive and inner-file hash independently and
     verifies the supplied `SHA256SUMS` and `manifest.json` against them;
   - compare the `SHA256SUMS` output with the copy printed in the `verify`
     job's workflow log;
   - confirm the release is marked as a prerelease and the notes carry the
     alpha warning;
   - record the live Bubblewrap/Lima validation status for the release notes.
6. If anything is wrong: delete the draft, fix, bump the alpha number
   (`-alpha.N+1`), and start over. Never reuse a version for different bytes
   and never edit assets of a published release.

## Rollback of a published release

Mark the release as yanked in its notes and publish a fixed higher alpha
version. Users roll back by installing the previous verified archive; see
[INSTALL.md](INSTALL.md#rollback).
