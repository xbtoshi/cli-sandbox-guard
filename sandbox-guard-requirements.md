# AI-CLI Sandbox Guard — Requirements & Blockers

**Status**: active prototype as of 2026-07-14. The Rust implementation currently targets
fail-closed staging and read-only/discarded execution. It is not yet a production security
boundary; the remaining blockers in this document are release gates.

**Context**: Grok Build CLI auto-uploads git bundles to xAI GCS on session start. `/privacy opt-out` is our current mitigation, plus grok is removed from all CCB session configs and `grok-api.luc.wtf` uses headless `grok -p` (which does not trigger the upload). This document captures what we'd have to build if we ever need a real sandbox.

## Goal

Prevent AI coding CLIs (grok, codex, opencode) from reading sensitive files (`.env*`, `.dev.vars*`, `id_rsa*`, `~/.ssh/`, `~/.aws/credentials`, `credentials.json`, user-editable denylist) — even when those tools auto-upload the workspace to their vendor cloud.

## Current implementation scope

- Shared Rust policy, staging, synthetic-Git, and audit layer.
- Linux execution through Bubblewrap.
- macOS execution inside a mountless Lima Linux VM, with Bubblewrap inside the guest.
- Network denied by default. An explicitly acknowledged unrestricted mode exists for development,
  but does not satisfy blocker 7.
- Tool writes affect only the disposable staged tree and are discarded. Reviewed copy-back is not
  implemented.
- Automated vendor updates, controlled egress, seccomp, and cgroup enforcement are not implemented.
- The repository must remain clearly labeled as an alpha until every applicable release blocker
  and fixture-backed test passes.

## Non-goals (explicit)

- Not a defense against network exfiltration to vendor endpoints — Grok Build **does** upload the workspace; we sanitize the workspace, we don't block the network.
- Not a defense against kernel or bwrap escape (documented in threat model).
- Not a defense against xAI/OpenAI subpoena of already-uploaded content.
- **Constraining potentially hostile or overreaching tool code IS the sandbox's central purpose** — this is a goal, not a non-goal.

## Review scores that got us here

| review | model | overall | security | verdict |
|---|---|--:|--:|---|
| v1 @ codex terra medium | gpt-5.6-terra medium | 4.2 | 3.0 | reject |
| v2 @ codex terra medium | gpt-5.6-terra medium | 7.1 | 7.4 | shippable pilot (over-generous) |
| v2 @ codex sol high | **gpt-5.6-sol high** | **5.3** | **6.0** | **not shippable** |

The sol/high review is authoritative. The 12 blockers below come from that pass.

## Critical blockers (must fix before shipping)

### 1. bwrap inherits env by default
- **Bug in v2**: `--setenv PATH ... --setenv HOME ...` doesn't remove other env vars. `GITHUB_TOKEN`, `AWS_*`, `ANTHROPIC_*`, all shell vars pass through untouched.
- **Fix**: `--clearenv --close-fds --dir /tmp/jail-home`, then only audited variables. Treat the forwarded vendor auth token as intentionally exposed to that specific tool.

### 2. Updater runs vendor code before verification
- **Bug in v2**: pinned-hash check happens *after* the vendor updater runs. By then, malicious update code has already had normal-home access — post-verification can't undo credential theft or host modification.
- **Fix**: download the artifact into a dedicated sandbox or unprivileged helper account, verify signatures + pinned signer identity, then atomically install through a minimal privileged installer. Hashes are secondary to signer identity.

### 3. No copy-back mechanism = tool edits vanish
- **Bug in v2**: shadow tree is deleted on exit → coding tool's edits are lost.
- **Fix**: pick one:
  - **A**: explicit read-only mode; document that edits are discarded (fine for review, useless for editing).
  - **B**: reviewed copy-back phase — accept only regular non-denylisted files, check source-snapshot for conflicts, reject links + special files, atomic writes.

### 4. `.git` absent breaks git-native workflows
- **Bug in v2**: `git bundle --all` fails inside jail, so the sanitized-bundle test passes vacuously. Also `git status/diff/log` broken → agents can't work normally.
- **Fix**: construct a synthetic repo containing a sanitized baseline commit + the sanitized working tree. Do not expose original objects, alternates, hooks, config, or history. Tests must assert commands succeed *before* inspecting output.

### 5. `git ls-files | xargs tar` is unsafe
- **Bug in v2**: xargs may spawn multiple tars → concatenated archives. Also validation-then-copy is a TOCTOU race (attacker replaces file between checks).
- **Fix**: descriptor-based staging helper (Rust or Go) using `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, and no-symlink resolution. Use `git ls-files --others --exclude-standard -z` for untracked inclusion.

### 6. Hard-link aliases bypass denylist
- **Bug in v2**: if `.env` is hard-linked to `README.md`, tar reads the bytes. `--hard-dereference` doesn't help; `rsync --safe-links` only covers symbolic links.
- **Fix**: reject multiply-linked regular files, OR compare source inodes against all discovered denylisted files' inodes. Document that filename policy cannot detect copied secret content under an innocent filename.

### 7. `--share-net` exposes host loopback + link-local
- **Bug in v2**: sharing the host netns exposes 127.0.0.1 services, RFC1918 private network, cloud-metadata endpoints (169.254.169.254), and Linux abstract Unix sockets.
- **Fix**: separate network namespace with controlled egress through a proxy or firewall that denies loopback, RFC1918, link-local, metadata endpoints, unintended abstract sockets. If shared networking must remain, add "host-service access" to explicit non-goals.

### 8. Missing bindings — CLIs likely can't run
- **Bug in v2**: no vendor binary, no runtime resources, no CA certs, no DNS config, no `/etc/hosts`, no `/etc/resolv.conf`. `/tmp/jail-home` not created.
- **Fix**: bind the exact verified tool + required libs, provide synthetic `passwd/group/hosts` files, read-only `resolv.conf` and CA bundle. Test the real CLI's login, API connection, subprocess, and update workflows end-to-end.

### 9. Seccomp blacklist is incomplete + overclaims
- **Bug in v2**: blocking `unshare` misses namespace creation via `clone` flags and `clone3`. Seccomp cannot filter pathname access (`/dev/kmem` guard is illusory). Missing: `bpf`, `perf_event_open`, `io_uring`, `open_by_handle_at`, new mount APIs, `process_vm_*`, `pidfd_getfd`.
- **Fix**: start from a maintained OCI/systemd seccomp profile and narrow using observed workloads. Filter `clone` namespace flags, decide explicitly how to handle `clone3`. Don't claim seccomp blocks pathnames.

### 10. `/etc/profile.d` is policy, not enforcement
- **Bug in v2**: existing shells, later startup files, aliases, command hashing, absolute paths, and user-controlled PATH edits all select an unwrapped binary.
- **Fix**: make the guarded executable itself root-owned at the canonical command path, keep real vendor binaries outside normal PATH. Test command resolution in login, non-login, tmux, GUI, already-running shells.

### 11. No resource limits
- **Bug in v2**: buggy/malicious CLI can exhaust memory, CPU, PIDs, `/dev/shm`, network bandwidth.
- **Fix**: run under cgroup v2 + rlimit controls (memory, PIDs, CPU quota, file size, open files, `/dev/shm` size).

### 12. Threat model wrongly excludes malicious vendor binary
- **Bug in v2**: non-goals list excluded "vendor-binary compromise" — but that's exactly what the sandbox exists to constrain.
- **Fix**: correct non-goal is *kernel-level* escape, not ordinary malicious behavior inside the namespace. Rewrite threat model accordingly.

## Test matrix (must-cover)

Every rule needs a fixture-backed test:

- Malicious repository content (denylist files under innocent names via hard-link)
- Local-network services (loopback egress from inside jail — must fail)
- Staging races (concurrent write to a source file during copy)
- Hard-link aliases (denylisted file linked to allowed name)
- Crash cleanup (SIGKILL during staging → `/dev/shm/guard-*` GC)
- Disk exhaustion (`fallocate` inside jail → cgroup limit trips)
- Copy-back attacks (jail writes a symlink that resolves outside on the host)
- Ignored, untracked, nested, symlinked denylist paths
- `.git` leaks (assert absent in bundles + archives)
- Language-runtime configs (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `GOPATH`, `NODE_PATH`) must be scrubbed
- Malicious updater arguments (assert `guard update <tool>` rejects unknown subcommand shape)
- Replaced `~/.local/bin` symlink (assert `guard doctor` detects + repairs)
- `/proc` visibility (only jail PIDs)
- Namespace-escape attempts (`unshare`, `setns`, `clone3` with namespace flags → EPERM)

## Reference implementation shape

- **Language**: Rust or Go (need `openat2`, precise fd handling, no shell)
- **Staging helper**: unprivileged, executes as invoking user, produces `/dev/shm/guard-<uid>-<hash>/`
- **Wrapper binary**: root-owned in `/usr/local/libexec/sensitive-guard/bin/`, verifies own SHA256 against `/etc/sensitive-guard/wrapper.sha256` on startup
- **Privileged installer**: separate root-only binary that handles updates; verifies signer identity + pinned key fingerprints from `/etc/sensitive-guard/keys/`
- **Egress proxy**: minimal HTTP(S) forward proxy running in host netns, allow-listed by destination hostname
- **CLI surface**: `guard run <tool> [args]`, `guard update <tool>`, `guard doctor`, `guard test`, `guard policy`

## Rollout

- Wrap `grok` first (proven leak history) — pilot only.
- Ship codex + opencode wrappers only after the grok test suite has been green for at least 7 days with real usage.
- Any code changes to the wrapper require a passing `guard test` full-matrix run + a review pass at codex-sol-high tier.

## Estimated effort

- Staging helper (Rust, openat2): 2-3 days
- bwrap harness + seccomp profile: 1-2 days
- Egress proxy: 1 day
- Privileged installer: 2 days
- Test matrix: 2-3 days
- Threat model docs + non-goals + audit trail: 1 day
- **Total**: ~2 weeks of focused work

## Alternative: give up and wait

If xAI ships **granular controls** (per-file exclusions, opt-out that survives across sessions, opt-out for individual repos), we no longer need this. Their tweet on 2026-07-13 said "granular controls and local options are in active development". The weekly watcher at `/home/ccb/services/grok-privacy-watcher/check.sh` will flag any release notes about this.

## Sources

- Codex plan review v2 @ gpt-5.6-sol high, task `20260714-224631-852-3721552`, 2026-07-14
- @SpaceXAI tweet 2026-07-13 (ZDR / `/privacy` command / promised granular controls)
- Live audit of `~/.grok/logs/unified.jsonl` — 3 repos leaked (xmrclub-directory, claude_code_bridge, kyc-rip), all reportedly purged post `/privacy opt-out`
