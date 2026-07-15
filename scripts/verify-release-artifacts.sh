#!/usr/bin/env bash
# Verify the complete Sandbox Guard release artifact set. This script is a
# release boundary: every check fails closed and there is no bypass switch.
#
# Usage: verify-release-artifacts.sh MODE VERSION DIST_DIR
#
#   MODE=prepublish  CI mode, before any publish step. DIST_DIR must contain
#                    exactly the three archives plus their per-archive
#                    .sha256 sidecars. On success the script writes
#                    SHA256SUMS and manifest.json into DIST_DIR.
#
#   MODE=published   Maintainer mode for downloaded draft-release assets.
#                    DIST_DIR must contain exactly the three archives plus
#                    SHA256SUMS and manifest.json. Both files are verified
#                    against independently recomputed data, never trusted or
#                    rewritten.
#
# Checks common to both modes, per archive:
#   - the tar member-name list is validated BEFORE extraction and must equal
#     the expected list exactly: no duplicates, no absolute paths, no "..",
#     no unexpected entries;
#   - after extraction, expected files must be regular non-symlink files with
#     link count 1, expected directories real directories, and nothing else
#     may exist (no symlinks, hard links, or special files anywhere);
#   - executable modes only where expected (binaries yes, documents no);
#   - binary formats must match the target (ELF x86-64 / ELF aarch64 /
#     Mach-O arm64);
#   - the Linux ARM64 guard-helper inside the macOS archive must be
#     byte-identical to the guard-helper in the linux-aarch64 archive, so the
#     Lima guest runs the exact binary that was tested on Linux ARM64.

set -euo pipefail

die() {
    echo "verify-release-artifacts: $*" >&2
    exit 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

nlink_of() {
    stat -c '%h' "$1" 2>/dev/null || stat -f '%l' "$1"
}

[ "$#" -eq 3 ] || die "usage: verify-release-artifacts.sh {prepublish|published} VERSION DIST_DIR"
mode="$1"
version="$2"
dist="$(cd "$3" && pwd)"
case "$mode" in
prepublish | published) ;;
*) die "unknown mode ${mode}; expected prepublish or published" ;;
esac

# VERSION is a maintainer-supplied CLI argument used in path and archive
# names; allow only safe SemVer-shaped strings.
case "$version" in
'' | -* | *..* | *[!A-Za-z0-9.+-]*) die "unsafe version string $(printf '%q' "$version")" ;;
esac

targets=(linux-x86_64 linux-aarch64 macos-arm64)

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v file >/dev/null 2>&1 || die "file is required"

archive_names() {
    local target
    for target in "${targets[@]}"; do
        echo "sandbox-guard-${version}-${target}.tar.gz"
    done
}

# --- exact artifact-directory content per mode --------------------------------

expected_dist="$(archive_names)"
if [ "$mode" = "prepublish" ]; then
    expected_dist+=$'\n'"$(archive_names | sed 's/$/.sha256/')"
else
    expected_dist+=$'\n'"SHA256SUMS"$'\n'"manifest.json"
fi
expected_dist="$(printf '%s\n' "$expected_dist" | sort)"
actual_dist="$(find "$dist" -mindepth 1 -maxdepth 1 -print0 | xargs -0 -n1 basename | sort)"
[ "$actual_dist" = "$expected_dist" ] ||
    die "unexpected artifact set in ${dist} for mode ${mode}:"$'\n'"got:"$'\n'"${actual_dist}"$'\n'"expected:"$'\n'"${expected_dist}"

# --- expected archive structure ------------------------------------------------

expected_members_for() {
    local name="$2"
    case "$1" in
    linux-x86_64 | linux-aarch64)
        printf '%s\n' "$name/" "$name/ALPHA.txt" "$name/LICENSE" "$name/guard" "$name/guard-helper"
        ;;
    macos-arm64)
        printf '%s\n' "$name/" "$name/ALPHA.txt" "$name/LICENSE" "$name/guard" \
            "$name/lima-guest/" "$name/lima-guest/guard-helper"
        ;;
    esac
}

expected_files_for() {
    case "$1" in
    linux-x86_64 | linux-aarch64)
        printf '%s\n' "ALPHA.txt" "LICENSE" "guard" "guard-helper"
        ;;
    macos-arm64)
        printf '%s\n' "ALPHA.txt" "LICENSE" "guard" "lima-guest" "lima-guest/guard-helper"
        ;;
    esac
}

is_executable_member() {
    case "$1" in
    guard | guard-helper | lima-guest/guard-helper) return 0 ;;
    *) return 1 ;;
    esac
}

check_format() {
    local target="$1" relative="$2" path="$3" kind
    kind="$(file -b "$path")"
    case "$target:$relative" in
    linux-x86_64:*)
        case "$kind" in *ELF*x86-64*) ;; *) die "$target/$relative is not ELF x86-64: $kind" ;; esac
        ;;
    linux-aarch64:*)
        case "$kind" in *ELF*aarch64* | *ELF*ARM\ aarch64*) ;; *) die "$target/$relative is not ELF aarch64: $kind" ;; esac
        ;;
    macos-arm64:guard)
        case "$kind" in *Mach-O*arm64*) ;; *) die "$target/$relative is not Mach-O arm64: $kind" ;; esac
        ;;
    macos-arm64:lima-guest/guard-helper)
        case "$kind" in *ELF*aarch64* | *ELF*ARM\ aarch64*) ;; *) die "$target/$relative is not ELF aarch64: $kind" ;; esac
        ;;
    esac
}

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# verify_archive TARGET sets ARCHIVE_SHA and FILES_JSON for the caller.
verify_archive() {
    local target="$1"
    local name="sandbox-guard-${version}-${target}"
    local archive="$dist/$name.tar.gz"

    ARCHIVE_SHA="$(sha256_of "$archive")"

    # Validate the member-name list exactly, before extracting anything.
    local members
    members="$(tar -tzf "$archive")"
    local duplicates
    duplicates="$(printf '%s\n' "$members" | sort | uniq -d)"
    [ -z "$duplicates" ] || die "$name.tar.gz contains duplicate members:"$'\n'"$duplicates"
    local member
    while IFS= read -r member; do
        case "$member" in
        /*) die "$name.tar.gz contains an absolute member path: $member" ;;
        *..*) die "$name.tar.gz contains a traversal member path: $member" ;;
        esac
    done <<<"$members"
    local expected_members
    expected_members="$(expected_members_for "$target" "$name" | sort)"
    [ "$(printf '%s\n' "$members" | sort)" = "$expected_members" ] ||
        die "$name.tar.gz member list mismatch:"$'\n'"got:"$'\n'"$(printf '%s\n' "$members" | sort)"$'\n'"expected:"$'\n'"$expected_members"

    # Only regular files and directories may be extracted. This must run
    # before extraction: a fifo member can block tar itself on some
    # platforms, and symlink/hardlink/device members must never touch the
    # filesystem in the first place.
    local member_types
    member_types="$(tar -tvzf "$archive" | awk '{print substr($0, 1, 1)}' | sort -u)"
    local member_type
    while IFS= read -r member_type; do
        case "$member_type" in
        d | -) ;;
        *) die "$name.tar.gz contains a forbidden member type '$member_type'" ;;
        esac
    done <<<"$member_types"

    local extract="$scratch/$target"
    mkdir "$extract"
    tar -xzf "$archive" -C "$extract"

    # Nothing may exist besides the expected entries, and nothing anywhere may
    # be a symlink, hard link, or special file. find does not follow links.
    local listed
    listed="$(cd "$extract/$name" && find . -mindepth 1 | sed 's|^\./||' | sort)"
    local expected_files
    expected_files="$(expected_files_for "$target" | sort)"
    [ "$listed" = "$expected_files" ] ||
        die "$name.tar.gz extracted file set mismatch:"$'\n'"got:"$'\n'"$listed"$'\n'"expected:"$'\n'"$expected_files"
    local irregular
    irregular="$(find "$extract" -mindepth 1 ! -type f ! -type d)"
    [ -z "$irregular" ] || die "$name.tar.gz contains symlinks or special files:"$'\n'"$irregular"

    FILES_JSON="[]"
    local relative path file_sha size
    while IFS= read -r relative; do
        path="$extract/$name/$relative"
        [ ! -L "$path" ] || die "$name/$relative is a symlink"
        if [ "$relative" = "lima-guest" ]; then
            [ -d "$path" ] || die "$name/$relative is not a directory"
            continue
        fi
        [ -f "$path" ] || die "$name/$relative is not a regular file"
        [ "$(nlink_of "$path")" = "1" ] || die "$name/$relative is multiply hard-linked"
        if is_executable_member "$relative"; then
            [ -x "$path" ] || die "$name/$relative is not executable"
            check_format "$target" "$relative" "$path"
        else
            [ ! -x "$path" ] || die "$name/$relative must not be executable"
        fi
        file_sha="$(sha256_of "$path")"
        size="$(wc -c <"$path" | tr -d ' ')"
        FILES_JSON="$(jq --arg p "$relative" --arg s "$file_sha" --argjson z "$size" \
            '. + [{path: $p, sha256: $s, size: $z}]' <<<"$FILES_JSON")"
        if [ "$target" = "linux-aarch64" ] && [ "$relative" = "guard-helper" ]; then
            linux_aarch64_helper_sha="$file_sha"
        fi
        if [ "$target" = "macos-arm64" ] && [ "$relative" = "lima-guest/guard-helper" ]; then
            macos_guest_helper_sha="$file_sha"
        fi
    done <<<"$expected_files"
}

# --- recompute everything independently ----------------------------------------

linux_aarch64_helper_sha=""
macos_guest_helper_sha=""
manifest_entries="[]"
computed_sums=""

for target in "${targets[@]}"; do
    name="sandbox-guard-${version}-${target}"
    verify_archive "$target"
    computed_sums+="${ARCHIVE_SHA}  ${name}.tar.gz"$'\n'
    manifest_entries="$(jq --arg n "$name.tar.gz" --arg t "$target" --arg s "$ARCHIVE_SHA" \
        --argjson f "$FILES_JSON" \
        '. + [{archive: $n, target: $t, sha256: $s, files: $f}]' <<<"$manifest_entries")"
done

[ -n "$linux_aarch64_helper_sha" ] || die "did not record the linux-aarch64 guard-helper hash"
[ -n "$macos_guest_helper_sha" ] || die "did not record the macOS lima-guest guard-helper hash"
[ "$linux_aarch64_helper_sha" = "$macos_guest_helper_sha" ] ||
    die "the macOS package ships a guard-helper that differs from the tested linux-aarch64 build"

computed_manifest="$(jq -n --arg version "$version" --argjson artifacts "$manifest_entries" \
    '{schema: 1, project: "sandbox-guard", version: $version, status: "alpha; not production-ready", artifacts: $artifacts}')"

# --- mode-specific handling of SHA256SUMS and manifest.json ---------------------

if [ "$mode" = "prepublish" ]; then
    for target in "${targets[@]}"; do
        name="sandbox-guard-${version}-${target}"
        recorded="$(cut -d' ' -f1 "$dist/$name.tar.gz.sha256")"
        actual="$(printf '%s' "$computed_sums" | awk -v f="${name}.tar.gz" '$2 == f {print $1}')"
        [ "$recorded" = "$actual" ] ||
            die "$name.tar.gz checksum mismatch: build recorded $recorded, verifier computed $actual"
    done
    printf '%s' "$computed_sums" | sort -k2 >"$dist/SHA256SUMS"
    printf '%s\n' "$computed_manifest" >"$dist/manifest.json"
    echo "verified ${#targets[@]} archives for version ${version} (prepublish)"
    echo "wrote $dist/SHA256SUMS and $dist/manifest.json"
else
    supplied_sums="$(sort "$dist/SHA256SUMS")"
    expected_sums="$(printf '%s' "$computed_sums" | sort)"
    [ "$supplied_sums" = "$expected_sums" ] ||
        die "SHA256SUMS does not match the recomputed archive checksums:"$'\n'"supplied:"$'\n'"$supplied_sums"$'\n'"recomputed:"$'\n'"$expected_sums"
    supplied_manifest="$(jq -S . "$dist/manifest.json")" || die "manifest.json is not valid JSON"
    [ "$supplied_manifest" = "$(jq -S . <<<"$computed_manifest")" ] ||
        die "manifest.json does not match the recomputed artifact manifest"
    echo "verified ${#targets[@]} archives for version ${version} (published assets)"
    echo "SHA256SUMS and manifest.json match the recomputed data"
fi

echo "--- SHA256SUMS ---"
printf '%s' "$computed_sums" | sort -k2
