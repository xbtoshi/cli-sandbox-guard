#!/usr/bin/env bash
# Automated tests for scripts/package-release.sh and
# scripts/verify-release-artifacts.sh, covering the happy path in both
# verification modes plus hostile negative cases. Runs on Linux and macOS
# with only bash, tar, python3, jq, and file.
#
# Fixture binaries are minimal but real ELF and Mach-O executables, so the
# production binary-format checks run unmodified — there is no test bypass in
# the production scripts.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
package="$here/package-release.sh"
verify="$here/verify-release-artifacts.sh"
version="0.0.0-test.1"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

failures=0
pass() { echo "ok: $1"; }
fail() {
    echo "FAIL: $1" >&2
    failures=$((failures + 1))
}

expect_ok() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}

expect_reject() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then fail "$description (accepted)"; else pass "$description"; fi
}

# --- fixture binaries: minimal real ELF / Mach-O executables --------------------

python3 - "$work" <<'EOF'
import struct, sys, os
base = sys.argv[1]
def elf64(machine):
    header = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
    header += struct.pack('<HHIQQQIHHHHHH', 2, machine, 1, 0x1000, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    return header
macho = struct.pack('<IiiIIII', 0xfeedfacf, 0x0100000C, 0, 2, 0, 0, 0) + b'\x00' * 4
for name, blob in (
    ('elf-x86_64', elf64(0x3E)),
    ('elf-aarch64', elf64(0xB7)),
    ('elf-aarch64-other', elf64(0xB7) + b'different'),
    ('macho-arm64', macho),
):
    path = os.path.join(base, name)
    with open(path, 'wb') as handle:
        handle.write(blob)
    os.chmod(path, 0o755)
EOF

package_all() {
    local dest="$1" helper="${2:-$work/elf-aarch64}"
    mkdir -p "$dest" bin-x86 bin-arm bin-mac
    cp "$work/elf-x86_64" bin-x86/guard && cp "$work/elf-x86_64" bin-x86/guard-helper
    cp "$work/elf-aarch64" bin-arm/guard && cp "$work/elf-aarch64" bin-arm/guard-helper
    cp "$work/macho-arm64" bin-mac/guard
    chmod 0755 bin-x86/* bin-arm/* bin-mac/*
    CARGO_RELEASE_DIR="$work/bin-x86" "$package" linux-x86_64 "$version" "$dest" >/dev/null
    CARGO_RELEASE_DIR="$work/bin-arm" "$package" linux-aarch64 "$version" "$dest" >/dev/null
    CARGO_RELEASE_DIR="$work/bin-mac" LIMA_GUEST_HELPER="$helper" \
        "$package" macos-arm64 "$version" "$dest" >/dev/null
}

published_from() {
    # Build a published-assets directory (tarballs + SHA256SUMS + manifest.json)
    # from a verified prepublish directory.
    local source="$1" dest="$2"
    mkdir -p "$dest"
    cp "$source"/*.tar.gz "$source/SHA256SUMS" "$source/manifest.json" "$dest/"
}

# Repack one archive inside DIST after mutating its tree with a python
# snippet, keeping the outer .sha256 sidecar consistent so only the
# structural checks can reject it.
repack_with() {
    local dist="$1" target="$2" python_body="$3"
    local name="sandbox-guard-${version}-${target}"
    python3 - "$dist" "$name" <<EOF
import io, os, sys, tarfile
dist, name = sys.argv[1], sys.argv[2]
archive = os.path.join(dist, name + '.tar.gz')
members = []
with tarfile.open(archive) as reader:
    for member in reader.getmembers():
        data = reader.extractfile(member).read() if member.isreg() else None
        members.append((member, data))
def emit(writer, member, data):
    writer.addfile(member, io.BytesIO(data) if data is not None else None)
with tarfile.open(archive, 'w:gz') as writer:
${python_body}
EOF
    (cd "$dist" && if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$name.tar.gz" >"$name.tar.gz.sha256"
    else
        shasum -a 256 "$name.tar.gz" >"$name.tar.gz.sha256"
    fi)
}

# --- positive: prepublish then published --------------------------------------

package_all dist
expect_ok "prepublish verification passes" "$verify" prepublish "$version" dist
[ -f dist/SHA256SUMS ] && [ -f dist/manifest.json ] || fail "prepublish outputs missing"

published_from dist assets
expect_ok "published-assets verification passes" "$verify" published "$version" assets

# --- packaging rejects a non-ELF guest helper ----------------------------------

printf 'not a binary\n' >"$work/plain.txt" && chmod 0755 "$work/plain.txt"
expect_reject "packaging rejects a non-ELF lima guest helper" \
    env CARGO_RELEASE_DIR="$work/bin-mac" LIMA_GUEST_HELPER="$work/plain.txt" \
    "$package" macos-arm64 "$version" reject-dist

# --- unsafe version strings ------------------------------------------------------

for bad_version in "" "../evil" "0.1.0/x" "0.1.0 x" "-0.1.0" "0.1.*" '0.1.0$(id)'; do
    expect_reject "packaging rejects unsafe version '${bad_version}'" \
        env CARGO_RELEASE_DIR="$work/bin-x86" "$package" linux-x86_64 "$bad_version" bad-dist
    expect_reject "verifier rejects unsafe version '${bad_version}'" \
        "$verify" prepublish "$bad_version" dist
done

# --- mode/dist content confusion -----------------------------------------------

expect_reject "published mode rejects a prepublish directory" "$verify" published "$version" dist
expect_reject "prepublish mode rejects a published directory" "$verify" prepublish "$version" assets

# --- tampering ------------------------------------------------------------------

cp -R dist tamper-pre && printf x >>tamper-pre/sandbox-guard-${version}-linux-x86_64.tar.gz
rm tamper-pre/SHA256SUMS tamper-pre/manifest.json
expect_reject "prepublish rejects a tampered archive" "$verify" prepublish "$version" tamper-pre

cp -R assets tamper-pub && printf x >>tamper-pub/sandbox-guard-${version}-linux-x86_64.tar.gz
expect_reject "published rejects a tampered archive" "$verify" published "$version" tamper-pub

cp -R assets tamper-sums
python3 - tamper-sums/SHA256SUMS <<'EOF'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines()
first = lines[0]
digest, rest = first.split(' ', 1)
flipped = ('0' if digest[0] != '0' else '1') + digest[1:]
lines[0] = flipped + ' ' + rest
open(path, 'w').write('\n'.join(lines) + '\n')
EOF
expect_reject "published rejects a tampered SHA256SUMS" "$verify" published "$version" tamper-sums

cp -R assets tamper-manifest
jq '.artifacts[0].files[0].sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' \
    tamper-manifest/manifest.json >tamper-manifest/manifest.json.new
mv tamper-manifest/manifest.json.new tamper-manifest/manifest.json
expect_reject "published rejects a tampered manifest.json" "$verify" published "$version" tamper-manifest

# --- helper mismatch between linux-aarch64 and the macOS package ----------------

package_all mismatch "$work/elf-aarch64-other"
expect_reject "prepublish rejects a mismatched lima guest helper" "$verify" prepublish "$version" mismatch

# --- unexpected directory content ------------------------------------------------

cp -R dist extra-dist && rm extra-dist/SHA256SUMS extra-dist/manifest.json && touch extra-dist/surprise
expect_reject "prepublish rejects extra files in the artifact directory" "$verify" prepublish "$version" extra-dist

cp -R assets extra-assets && touch extra-assets/surprise
expect_reject "published rejects extra files in the asset directory" "$verify" published "$version" extra-assets

# --- hostile archive members ------------------------------------------------------

hostile() {
    # hostile NAME PYTHON_BODY — copy the verified prepublish dist, repack the
    # linux-x86_64 archive with a hostile member, expect prepublish rejection.
    local test_name="$1" body="$2"
    local dir="hostile-$test_name"
    cp -R dist "$dir" && rm "$dir/SHA256SUMS" "$dir/manifest.json"
    repack_with "$dir" linux-x86_64 "$body"
    expect_reject "prepublish rejects $test_name" "$verify" prepublish "$version" "$dir"
}

hostile "an extra archive member" "
    for member, data in members:
        emit(writer, member, data)
    import tarfile as t
    extra = t.TarInfo(name + '/evil.sh')
    extra.size = 0
    writer.addfile(extra, io.BytesIO(b''))
"

hostile "a traversal member path" "
    for member, data in members:
        if member.name.endswith('/ALPHA.txt'):
            member.name = name + '/../ALPHA.txt'
        emit(writer, member, data)
"

hostile "an absolute member path" "
    for member, data in members:
        if member.name.endswith('/ALPHA.txt'):
            member.name = '/tmp/ALPHA.txt'
        emit(writer, member, data)
"

hostile "duplicate member names" "
    for member, data in members:
        emit(writer, member, data)
    for member, data in members:
        if member.isreg() and member.name.endswith('/guard'):
            emit(writer, member, data)
"

hostile "a symlink in place of a binary" "
    for member, data in members:
        if member.name.endswith('/guard-helper'):
            link = tarfile.TarInfo(member.name)
            link.type = tarfile.SYMTYPE
            link.linkname = 'guard'
            emit(writer, link, None)
        else:
            emit(writer, member, data)
"

hostile "a hard link in place of a binary" "
    for member, data in members:
        if member.name.endswith('/guard-helper'):
            link = tarfile.TarInfo(member.name)
            link.type = tarfile.LNKTYPE
            link.linkname = name + '/guard'
            emit(writer, link, None)
        else:
            emit(writer, member, data)
"

hostile "a fifo special file in place of a binary" "
    for member, data in members:
        if member.name.endswith('/guard-helper'):
            fifo = tarfile.TarInfo(member.name)
            fifo.type = tarfile.FIFOTYPE
            emit(writer, fifo, None)
        else:
            emit(writer, member, data)
"

hostile "a wrong-format binary" "
    for member, data in members:
        if member.name.endswith('/guard-helper'):
            data = b'#!/bin/sh\necho fake\n'
            member.size = len(data)
        emit(writer, member, data)
"

hostile "a non-executable binary" "
    for member, data in members:
        if member.name.endswith('/guard-helper'):
            member.mode = 0o644
        emit(writer, member, data)
"

hostile "an executable document" "
    for member, data in members:
        if member.name.endswith('/ALPHA.txt'):
            member.mode = 0o755
        emit(writer, member, data)
"

# --------------------------------------------------------------------------------

if [ "$failures" -gt 0 ]; then
    echo "test-release-scripts: ${failures} failure(s)" >&2
    exit 1
fi
echo "test-release-scripts: all tests passed"
