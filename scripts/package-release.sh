#!/usr/bin/env bash
# Package one Sandbox Guard release archive with an exact, fixed file set.
#
# Usage: package-release.sh TARGET VERSION OUTPUT_DIR
#   TARGET: linux-x86_64 | linux-aarch64 | macos-arm64
#
# Inputs:
#   CARGO_RELEASE_DIR  directory holding the built release binaries
#                      (default: <repo>/target/release)
#   LIMA_GUEST_HELPER  macos-arm64 only: path to the Linux ARM64 guard-helper
#                      binary that is shipped for installation inside the
#                      dedicated Lima guest.
#
# The archive layout is deliberately small and closed:
#   linux-*:     NAME/guard, NAME/guard-helper, NAME/LICENSE, NAME/ALPHA.txt
#   macos-arm64: NAME/guard, NAME/lima-guest/guard-helper, NAME/LICENSE,
#                NAME/ALPHA.txt
# scripts/verify-release-artifacts.sh rejects any deviation before publish.

set -euo pipefail

die() {
    echo "package-release: $*" >&2
    exit 1
}

[ "$#" -eq 3 ] || die "usage: package-release.sh TARGET VERSION OUTPUT_DIR"
target="$1"
version="$2"
output_dir="$3"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
release_dir="${CARGO_RELEASE_DIR:-$repo_root/target/release}"
name="sandbox-guard-${version}-${target}"

case "$target" in
linux-x86_64 | linux-aarch64 | macos-arm64) ;;
*) die "unsupported target ${target}" ;;
esac

# VERSION becomes part of directory and archive names; allow only safe
# SemVer-shaped strings.
case "$version" in
'' | -* | *..* | *[!A-Za-z0-9.+-]*) die "unsafe version string $(printf '%q' "$version")" ;;
esac

[ -f "$release_dir/guard" ] || die "missing $release_dir/guard; build the workspace in release mode first"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name"

install -m 0755 "$release_dir/guard" "$stage/$name/guard"
case "$target" in
linux-*)
    [ -f "$release_dir/guard-helper" ] || die "missing $release_dir/guard-helper"
    install -m 0755 "$release_dir/guard-helper" "$stage/$name/guard-helper"
    ;;
macos-arm64)
    [ -n "${LIMA_GUEST_HELPER:-}" ] || die "macos-arm64 requires LIMA_GUEST_HELPER"
    [ -f "$LIMA_GUEST_HELPER" ] || die "LIMA_GUEST_HELPER ${LIMA_GUEST_HELPER} is not a file"
    # The guest helper must be a Linux ELF binary, never a macOS Mach-O one;
    # shipping the wrong format would only fail later inside the guest.
    case "$(file -b "$LIMA_GUEST_HELPER")" in
    *ELF*aarch64* | *ELF*ARM\ aarch64*) ;;
    *) die "LIMA_GUEST_HELPER is not a Linux ARM64 ELF binary: $(file -b "$LIMA_GUEST_HELPER")" ;;
    esac
    mkdir -p "$stage/$name/lima-guest"
    install -m 0755 "$LIMA_GUEST_HELPER" "$stage/$name/lima-guest/guard-helper"
    ;;
esac
install -m 0644 "$repo_root/LICENSE" "$stage/$name/LICENSE"
cat >"$stage/$name/ALPHA.txt" <<NOTICE
Sandbox Guard ${version} (${target})

This is an alpha security prototype. It is NOT production-ready and open
release blockers remain. Read docs/SECURITY_MODEL.md and docs/INSTALL.md in
the source repository before use:

    https://github.com/xbtoshi/cli-sandbox-guard

Verify the archive checksum against the release SHA256SUMS file and the
signed release tag before installing.
NOTICE
chmod 0644 "$stage/$name/ALPHA.txt"

# Strip macOS extended attributes so bsdtar never embeds host metadata and
# the verifier sees the same clean member list on every platform.
if command -v xattr >/dev/null 2>&1; then
    xattr -rc "$stage/$name"
fi

mkdir -p "$output_dir"
archive="$output_dir/$name.tar.gz"
tar -czf "$archive" -C "$stage" "$name"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$output_dir" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
else
    (cd "$output_dir" && shasum -a 256 "$name.tar.gz" >"$name.tar.gz.sha256")
fi

echo "packaged $archive"
cat "$archive.sha256"
