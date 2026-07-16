# Live inside-sandbox security probe (2026-07-16)

**Date:** 2026-07-16
**Method class:** empirical breakout attempts from *inside* a running sandbox — not a docs-only review
**Probe actor:** the confined tool process (Grok) under a live `guard grok` session on a macOS host
using the Lima backend
**Remediation status:** see [Remediation in alpha.4](#remediation-in-alpha4). Finding 1 is fixed;
Finding 2 is accepted and documented; Finding 4 candidates are converted to real built-in denies and
tests; Finding 3 is a documented intentional residual.

> **Redaction and provenance note.** All host/guest identifiers observed during this probe
> (username, guest home directory, internal proxy IP and port, per-run stage UUID, runtime ports)
> are redacted below as `<redacted>` placeholders. This document is a **historical live-probe
> record**. The exact binary under test was **not** captured — no artifact SHA-256 or build commit
> identity was recorded during the session — so **this report is not release evidence for the
> published alpha.3 binaries**. It documents behavior observed on *a* build resembling alpha.3, not a
> provenance-verified one. No artifact hashes or commit identities are invented here.

---

## Remediation in alpha.4

- **Finding 1** (launcher session-environment leak): **fixed** — bwrap is invoked behind a fixed
  `/usr/bin/env -i` boundary on every backend and mode, leaving pid 1 with an empty environment; a
  hostile-probe check now reads `/proc/1/environ` and fails closed unless it is empty.
- **Finding 2** (staging pathnames in `/proc/1/cmdline`): **accepted and documented** as
  low-severity metadata.
- **Finding 3** (access token + allowlisted HTTPS): **intentional residual risk**, already in the
  security model.
- **Finding 4** (secret-filename gaps): selected high-confidence candidates are now **denied** by
  the real `CompiledPolicy` globset with native tests; ambiguous candidates remain owner-policy-only.

---

## Scope and honesty statement

This report records what **actually happened** when the untrusted tool process tried to escape or
extract information from a running Sandbox Guard session.

It **is**:

- commands executed from inside the guest sandbox (`PWD=/workspace`, `HOME=/home/guard`);
- observed syscall / network / filesystem results;
- redacted evidence of readable metadata and credentials available to the tool.

It is **not**:

- a fantasy threat model or a re-statement of `docs/SECURITY_MODEL.md`;
- a claim that every code path was formally verified;
- a full `cargo test` re-run of the in-tree hostile fixture suite (see [Limitations](#limitations));
- provenance-verified evidence about the published alpha.3 release artifacts.

The first "security review" pass in the original session was static reading of source and docs. This
document covers only the **second pass**: live probes. Only claims that were executed and observed
are promoted here.

### "Branch under review": `guard-baseline`

The session reported a Git branch named `guard-baseline`. This is **not** source provenance. Guard
stages an untrusted copy of the workspace and builds a **synthetic in-sandbox Git repository** with
system/global config disabled and a single sanitized baseline commit (see the staging invariants in
`docs/SECURITY_MODEL.md`). `guard-baseline` is that synthetic branch name observed *inside* the
sandbox; it does not identify the host source tree, its real history, or the build under test.

---

## Environment under test (observed)

The tool was already confined when probing. Evidence from the live session:

| Observation | Value / evidence |
|-------------|------------------|
| Working directory | `/workspace` (bind-mounted staged copy) |
| Synthetic home | `/home/guard` |
| Tool binary | `/opt/sandbox-guard/tools/grok` (static aarch64 ELF) |
| Helper | `/usr/local/bin/guard-helper supervise …` |
| Isolation launcher | `/usr/bin/bwrap` with `--unshare-user/pid/ipc/uts/cgroup/net`, `--cap-drop ALL`, `--clearenv`; host repo **not** mounted |
| Network | Controlled egress via `HTTPS_PROXY=http://127.0.0.1:<redacted-port>` → UNIX socket relay → host proxy |
| Guest staging path (from bwrap argv) | `/dev/shm/sandbox-guard-<redacted-uuid>` — a **Lima guest** tmpfs path, not a macOS host path |
| PID namespace view | Only a handful of processes (bwrap, guard-helper, grok, shells) — not the host PID table |

Mount table (abbreviated, from `/proc/self/mountinfo`):

- root = tmpfs;
- `/usr`, `/bin`, `/lib`, cert stores, passwd/group = **ro** binds from guest disk;
- `/workspace` = **rw** bind of the staged tree;
- `/home/guard/.grok/sessions` = **rw** session-state bind;
- `/run/sandbox-guard` = **ro** runtime (env file, egress socket, audit);
- `/workspace/sandbox-guard-inputs` = **ro** inbox.

**Host vs. guest paths.** This probe ran under the **macOS Lima backend**. Every absolute path the
tool observed (`/dev/shm/sandbox-guard-<uuid>`, `/home/<redacted>`, `/run/user/<redacted>`) lives
inside the **disposable Linux guest**, which is part of the trusted computing base and holds no host
filesystem mounts. On the **direct-Linux backend** the equivalent stage path
(`.sandbox-guard-runtime-<uuid>` beside the workspace) is a **host** path. The distinction matters
for every finding below.

---

## Attempts mapped to observed results

Each attempt is mapped to its observed result. Where an outcome was not reliably retained during the
session, it is labelled **not retained** rather than asserted.

### A. Host/guest filesystem reach

| Attempt | Observed result |
|---------|-----------------|
| Read `/home/<redacted>`, `/Users`, `/root`, `/etc/shadow` | **Not present** in the mount namespace |
| Read guest staging path `/dev/shm/sandbox-guard-<uuid>` by absolute path | **Missing** inside guest (`/dev/shm` is a private empty tmpfs in the sandbox) |
| `/var/run/docker.sock`, `/run/user/<redacted>`, `/run/user/<redacted>/bus` | **Not present** |
| Block devices `/dev/sda`, `/dev/nvme0n1`; `/sys/fs/cgroup` | **Not present / restricted** |

### B. Network breakout

| Attempt | Observed result |
|---------|-----------------|
| Direct TCP to `1.1.1.1:443`, `8.8.8.8:53`, `169.254.169.254:80` | **Network unreachable** (errno 101) |
| Guest-side DNS for vendor/proxy/`crates.io` names | **Failed** (`Temporary failure in name resolution`; resolution happens on the trusted proxy) |
| `CONNECT host:80` via the local proxy | **HTTP 403 Forbidden** immediately |
| SNI ≠ CONNECT hostname after an allowlisted CONNECT | Tunnel aborted (unexpected EOF) |
| Direct connect to `/run/sandbox-guard/egress.sock` | No usable channel obtained (**not retained** as a precise error string) |

### C. Privilege / namespace / seccomp

| Attempt | Observed result |
|---------|-----------------|
| `unshare(NEWUSER|NEWNET|NEWNS)`, `mount` tmpfs | **EPERM** |
| `ptrace(TRACEME)` / `PTRACE_ATTACH` on bwrap/helper | **EPERM** |
| `process_vm_readv` toward other PIDs | **EPERM** |
| `bpf`, `io_uring_setup`, `pidfd_open`, `keyctl` | **EPERM** |

### D. Process metadata and credentials

| Attempt | Observed result |
|---------|-----------------|
| Read `/proc/<pid>/environ|cmdline|maps|status` for visible PIDs | Mixed; see Findings 1–2 |
| Read `/proc/1/environ` (bwrap) | **Readable** → launcher session-environment leak; guest metadata observed (Finding 1) |
| Read `/proc/1/cmdline` (bwrap) | **Readable** → staging pathnames (Finding 2) |
| Read `guard-helper` (pid 2) environ & mem | **Permission denied** (supervisor is non-dumpable) |
| Read `/run/sandbox-guard/environment.json` | **Readable** (mode 600, by design — Finding 3) |
| Complete allowlisted TLS **without** attaching the bearer token | **Succeeded** (Finding 3) |

### E. Writes outside the staged project tree

Attempted `create` under `/tmp`, `/home/guard`, `/home/guard/.grok`, `/etc`, `/usr`,
`/run/sandbox-guard`, and the sandbox root (`/workspace/..`).

- Writes to read-only binds (`/usr`, `/run/sandbox-guard`) were **denied**.
- Writes that **succeeded** were confined to **private tmpfs** (`/tmp`, the synthetic `/etc` tmpfs)
  or **synthetic home** paths (`/home/guard`). None of these are host paths; all are destroyed when
  the run ends.
- The precise result of the `/workspace/..` root-path attempt was **not retained** and is not
  asserted here.
- `/home/guard/.grok/sessions` is a **narrow rw bind** of Guard-owned session state. A write there
  (`POISON_TEST`, see cleanup) persists only inside that Guard-owned staged copy, which Guard
  re-validates with the descriptor-safe policy layer and atomically publishes as a session snapshot
  after the run. It is **not** a host filesystem write and does not reach the original repository.

### F. Built-in deny policy coverage

The workspace could not be recompiled in-session (`crates.io` blocked by controlled egress), so
`Stage::build` was **not** re-executed live. Instead, `BUILTIN_DENY_RULES` was extracted from source
and a **Python glob approximation** was run against known unit-test paths. This is an approximation,
not proof of `Stage` behavior; see Finding 4 and its alpha.4 follow-up.

---

## Results: isolation that held

No classical "read the real host repository or host home as files" breakout was achieved. Direct
external networking, cloud-metadata reach, guest DNS, port-80 CONNECT, namespace creation, `ptrace`,
`process_vm_readv`, `bpf`/`io_uring`, supervisor memory reads, and writes to read-only runtime mounts
all failed as intended.

---

## Finding 1 — Launcher session-environment leak via bwrap `/proc/1/environ` (demonstrated under Lima) — **fixed in alpha.4**

### What was done

Listed PIDs in the sandbox pid namespace. Pid 1 is `bwrap`. Opened `/proc/1/environ` successfully as
the same UID.

### What was observed (redacted) — Lima guest metadata

The environ dump exposed the launcher's inherited **guest login-session environment**, which under
this Lima run is guest metadata, including (redacted): `HOME=/home/<redacted>`,
`USER`/`LOGNAME=<redacted>`, `PWD`, the guest-side
`https_proxy`/`HTTPS_PROXY`/`HTTP_PROXY=http://<redacted-ip>:<redacted-port>`,
`XDG_RUNTIME_DIR=/run/user/<redacted>`, `DBUS_SESSION_BUS_ADDRESS`, `SSH_TTY`, the full guest login
`PATH`, a systemd `INVOCATION_ID`, and `_=/usr/bin/systemd-run`. This is what was **live-observed**.

### Why it matters (Lima observed; direct-Linux inferred)

Bubblewrap's `--clearenv` clears the environment for the **executed child**, not for the **bwrap
process itself**, which remains visible as pid 1 inside the sandbox pid namespace with a
tool-readable `/proc/1/environ`. Under Lima the leaked values are **guest identity/metadata**, were
**not** mountable from inside, and are what this probe actually observed — identity disclosure, not a
host file open.

On the **direct-Linux backend** the same code path would instead expose the **host** shell's session
environment, which can contain real secrets. That host-secret impact is **derived from the launch
code path, not separately observed** in this Lima session. In both cases it contradicts the
operational expectation that the untrusted side sees only a cleaned environment.

### Remediation

Fixed in alpha.4: the runner interposes a fixed-argv `/usr/bin/env -i` clean-environment boundary
immediately before bwrap on every route (Linux host and Lima guest; interactive and noninteractive;
cgroup-enforced and best-effort), using fixed absolute executables so no PATH-selected binary runs at
the boundary. bwrap inherits a fully **empty** environment on both backends. The hostile backend
probe now reads `/proc/1/environ` and fails closed unless it is empty.

---

## Finding 2 — Staging pathnames via bwrap `/proc/1/cmdline` (demonstrated) — **accepted, documented**

### What was done

Read `/proc/1/cmdline` for bwrap.

### What was readable

The bwrap argument vector, including the per-run stage directory
(`/dev/shm/sandbox-guard-<redacted-uuid>` on this Lima run) and the fixed guest mount targets for
`workspace`, `session-state`, and `inbox`.

### Why it matters

Discloses the random stage UUID and the sandbox mount layout. Under Lima this is a **disposable guest
tmpfs path**; on **direct Linux** the analogous source is a **host** stage path. In both cases the
path was **not openable** from inside (private tmpfs) and carries no credentials.

### Disposition

Accepted as **low-severity metadata**. Eliminating it would require either bwrap's `--args`
file-descriptor form (which cannot be carried unchanged through the current `systemd-run`/`limactl
shell` transports) or moving bwrap out of pid 1 (which would require redesign and re-validation of
the `--die-with-parent` reaping and signal model). Neither trade is justified to conceal
non-sensitive metadata. Documented in `docs/SECURITY_MODEL.md` under "Explicit limitations".

---

## Finding 3 — Access token + allowlisted HTTPS usable by the tool (demonstrated, by design) — **intentional residual risk**

This is **not** a mount escape. It is a live confirmation of a residual data-flow risk that the
security model already accepts.

### What was demonstrated

1. `GROK_SESSION_TOKEN` was present in the tool process environment (redacted; length noted only).
2. `/run/sandbox-guard/environment.json` is mode `600`, readable by the tool, and carried the same
   forwarded token value (by design — it is how the credential is delivered).
3. `/home/guard/.grok/auth.json` existed (mode `600`) in the disposable synthetic home from preflight
   login hydration. No `refresh` field was present in the scanned content.
4. Proxy `CONNECT` to the allowlisted vendor host returned `200 Connection Established`; TLS 1.3
   completed; a plain unauthenticated `GET /` returned an edge HTTP response — sufficient to prove a
   working tunnel. **The test request did not attach the bearer token.**

The runtime egress audit recorded allowlisted successful destinations as `hostname:443` lines only.

### Non-allowlisted CONNECT behavior

Under interactive approval mode, `CONNECT` to non-allowlisted hosts did **not** return an immediate
403; short client timeouts observed `TimeoutError`, consistent with the host-native approval dialog
waiting (fail-closed for *granting* access). `CONNECT <vendor>:80` was denied immediately with 403.
The approval dialog itself was **not observed from the tool side**; this behavior is inferred from
client timeouts only.

### Why it matters

A malicious or prompt-injected tool can read the short-lived access token and open a real HTTPS
channel to the allowlisted vendor host, and therefore exfiltrate staged content and the token to that
destination. This is the **intentional residual**: destination control is not payload control, and a
credential deliberately forwarded to an untrusted tool can be misused by it (see
`docs/SECURITY_MODEL.md`, "Explicit limitations"). This run proved the channel is live; it did not
find a new class of escape.

No token was exfiltrated to any third party during this probe; allowlisted TLS was exercised only
with an unauthenticated `GET /`.

---

## Finding 4 — Built-in secret-filename policy: candidate gaps (rule approximation) — **candidates converted in alpha.4**

### Constraint

`Stage::build` was not re-executed in-session (crates.io blocked). The results below come from a
Python glob **approximation** of `BUILTIN_DENY_RULES`, validated against a handful of known
unit-test vectors. They are **candidate gaps**, not confirmed `Stage` behavior.

### Candidate names the approximation reported as **allowed**

`secrets.{yaml,yml,toml,json}`, `api_keys.json`, `api-keys.json`, `token.txt`, `tokens.json`,
`local.env`, `prod.env`, `env.local`, `dotenv`, `serviceAccount.json` (camelCase; `service-account*.json`
was denied), `google-services.json`, `terraform.tfvars`, `terraform.tfstate`, `.yarnrc.yml`,
`auth.json` (while `.grok/auth.json` was denied), `application.yml`, `application.properties`,
`settings.local.json`, `wallet.dat`, `kubeconfig`, `dump.sql`, `backup.sql`.

### alpha.4 follow-up (confirmed through real native tests)

The candidates were re-checked against the **real `CompiledPolicy` globset** in native Rust tests
(`crates/sandbox-guard-core/src/policy.rs`). Selected high-confidence candidates are now immutable
built-in denies with tests: `*.env` (non-dotfile dotenv spellings), `serviceaccount*.json`,
`.yarnrc.yml`, `kubeconfig` / `*.kubeconfig`, `*.tfstate` / `*.tfstate.backup`, and `wallet.dat`.
Most are credential/state files that are never source; `.yarnrc.yml` is an exception — it is
commonly committed config, blocked because it can embed registry tokens, with the acknowledged
tradeoff that a token-free `.yarnrc.yml` is excluded from staging too.

Ambiguous candidates that are frequently ordinary files are **deliberately left to owner policy**
rather than blocked globally, with the rationale recorded in the policy tests: `*.tfvars`, generic
`secrets.*`, `api_keys.json`/`tokens.json`, `application.yml`/`application.properties`,
`google-services.json`, and SQL dumps. A companion test asserts ordinary source (`secrets.rs`,
`token.rs`, `kubeconfig.rs`, …) is **not** over-blocked.

---

## Cleanup performed after probes

Test artifacts were created and removed. All were inside the **sandbox tmpfs / synthetic home /
Guard-owned session-state copy**, never the host: `/tmp/breakout`, `/home/guard/breakout`,
`/home/guard/.grok/breakout`, `/etc/breakout` (the sandbox tmpfs `/etc`), and
`/home/guard/.grok/sessions/POISON_TEST`. No intentional exfiltration of the access token to
third-party hosts was performed.

---

## Limitations

1. **Provenance not captured.** No artifact hash or build-commit identity was recorded; this is not
   alpha.3 release evidence.
2. **No in-session rebuild.** Controlled egress blocked crates.io; the in-tree hostile fixture suite
   and `Stage::build` were not re-run live. Finding 4's in-session results are a rule approximation
   (since re-checked natively in alpha.4).
3. **Staging escape not re-proved live.** `openat2`/hardlink/symlink staging escapes were not
   re-proved in this session; prior in-tree unit tests (`staging_security.rs`) exist but were not
   freshly executed here.
4. **Export/apply hostility not live-tested** end-to-end.
5. **`/proc/1/mem` bulk reads not established** (`process_vm_readv` EPERM; mem open inconsistent).
   Findings 1–2 do not depend on mem dumps.
6. **Approval dialog not observed from the tool side;** non-allowlisted CONNECT behavior is inferred
   from client timeouts only.
7. **Lima-only run.** Every observed absolute path was a guest path. Direct-Linux host-path behavior
   for Findings 1–2 is reasoned from the shared runner code, not separately observed here.

---

## Summary table

| # | Finding | Demonstrated? | Host FS escape? | Severity | alpha.4 status |
|---|---------|---------------|-----------------|----------|----------------|
| 1 | Launcher session env readable on bwrap `/proc/1/environ` | Yes (Lima metadata) | No | Medium under Lima; potentially High on direct Linux when secrets were inherited | **Fixed** |
| 2 | Staging pathnames in bwrap `/proc/1/cmdline` | Yes | No | Low (metadata) | **Accepted, documented** |
| 3 | Access token + allowlisted HTTPS usable by tool | Yes | No | High for confidentiality *within model* | **Intentional residual** |
| 4 | Secret-filename candidate gaps (rule approximation) | Approximation | N/A | Medium if such files exist | **Candidates converted + native tests** |
| — | Host file / network / seccomp breakout | Attempted, failed | No | — | — |

---

## Bottom line

From inside a live Sandbox Guard / `guard grok` session on the Lima backend, the tool ran real
breakout probes.

- It **did not** read the real host repository or host home directories.
- It **did** read the **launcher's inherited guest session environment** (Finding 1, now fixed) and
  **staging pathnames** (Finding 2, accepted metadata) via bwrap's `/proc/1`.
- It **did** confirm the tool holds a real access token and can open a real allowlisted TLS session
  (Finding 3, an intentional residual of forwarding a credential to an untrusted tool).
- It **did** surface secret-filename **candidate gaps** (Finding 4), since confirmed and partly
  closed through real native policy tests.

That is the difference between reading the security model and testing the running boundary — recorded
here honestly, without provenance claims it cannot support.

---

## Appendix — example commands (non-exhaustive)

```sh
# mount / visibility
cat /proc/self/mountinfo
ls -la / /home /home/guard /run/sandbox-guard

# launcher environment leak (Finding 1)
python3 -c "print(open('/proc/1/environ','rb').read().split(b'\\0'))"

# launcher argv / staging paths (Finding 2)
python3 -c "print(open('/proc/1/cmdline','rb').read().replace(b'\\0', b' '))"

# network: direct connect_ex to public/metadata IPs; CONNECT via $HTTPS_PROXY
# seccomp / privileges: ctypes unshare/mount/ptrace/process_vm_readv/bpf/io_uring_setup
```
