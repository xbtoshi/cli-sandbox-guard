# macOS Native Seatbelt Evaluation (Prior Art: Gemini CLI)

Status: reviewed prior-art evaluation only. This document does **not** approve a
`macos-native` backend and does not authorize implementation. It records prior
art for the Phase 4 line item "Evaluate an experimental `macos-native` Seatbelt
backend for low-friction local use" and defines an explicit go/no-go gate for
any later architecture decision.

## Scope and method

The evaluation reads two things and keeps them separate:

- **Documented claims** — the public Gemini CLI sandbox documentation.
- **Source-confirmed behavior** — the actual open-source implementation and
  Seatbelt (SBPL) profiles at a pinned commit, read line by line.

Where the two disagree or the docs are silent, source wins and the gap is
called out. Nothing here was executed; no Seatbelt profile was run and no Lima
mutation was attempted. Claims about `sandbox-exec` platform status are OS-level
facts (Apple man page / macOS behavior), labelled as such, not source-confirmed.

### Inspected sources

- Inspected Gemini CLI commit: `3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb`
  (`main`, committed 2026-07-15).
- [Upstream repository](https://github.com/google-gemini/gemini-cli)
- [Documentation page (documented claims)](https://geminicli.com/docs/cli/sandbox/#1-macos-seatbelt-macos-only)
- [In-repo docs mirror at the inspected commit](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/docs/cli/sandbox.md)

Stable source URLs (all pinned to the commit above):

- [Legacy static profiles (layer 1)](https://github.com/google-gemini/gemini-cli/tree/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/cli/src/utils), including
  `permissive-open`, `permissive-proxied`, `restrictive-open`,
  `restrictive-proxied`, `strict-open`, and `strict-proxied`.
- [Legacy launcher](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/cli/src/utils/sandbox.ts)
- [Command/profile selection](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/cli/src/config/sandboxConfig.ts)
- [Per-command manager (layer 2)](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/core/src/sandbox/macos/MacOsSandboxManager.ts)
- [Dynamic profile builder](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/core/src/sandbox/macos/seatbeltArgsBuilder.ts)
- [Base SBPL profile](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/core/src/sandbox/macos/baseProfile.ts)
- [Environment sanitization](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/core/src/services/environmentSanitization.ts)
- [Path resolution and secret/governance metadata](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/core/src/services/sandboxManager.ts)
- [Denial parsing](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/core/src/sandbox/utils/sandboxDenialUtils.ts)
  and [expansion UX](https://github.com/google-gemini/gemini-cli/blob/3ff5ba20fc1ad7d867218bbdb34756eb54d6eccb/packages/core/src/tools/shell.ts)

## Executive summary

Gemini CLI ships **two distinct macOS Seatbelt implementations** in the same
tree, and this is the single most important finding — the public documentation
describes only the older one:

1. **Layer 1 — static whole-process relaunch (documented).** At startup the CLI
   re-executes itself under `sandbox-exec -f <profile>.sb` using one of six
   fixed `.sb` files selected by `SEATBELT_PROFILE` (default `permissive-open`).
   The default profile is `(allow default)` — everything is allowed except
   writes outside an allowlist. This is what `geminicli.com/docs/cli/sandbox`
   documents. It is low-assurance by construction.

2. **Layer 2 — dynamic per-command profile (source-only, undocumented on the
   sandbox page).** A newer `MacOsSandboxManager` builds a `(deny default)`
   profile per shell command, importing Apple's `system.sb`, embedding resolved
   workspace paths, conditional governance/secret rules, and a configurable
   environment sanitizer. This is a more defensible starting point, but its
   exceptions and configuration still leave important gaps described below.

For Guard, the conclusion is: **Lima must remain the recommended, high-assurance
backend.** A `macos-native` Seatbelt backend, if ever built, is a distinctly
lower-assurance, explicit, experimental, opt-in tier that must never be an
automatic fallback. Layer 1's permissive defaults are a direct example of what
Guard must *not* copy. Layer 2 supplies several tactics Guard can adapt, but
only *behind* Guard's existing staging/copy-back, egress broker, credential
broker, terminal filter, audit, and denylist — never as a replacement for them,
and never by writable-mounting the real workspace.

Recommendation: **conditional no-go for implementation now; proceed to a
gated design spike only.** See the go/no-go gate at the end.

## 1. Seatbelt invocation and profile construction

### Layer 1 (documented, static)

Source-confirmed in `packages/cli/src/utils/sandbox.ts`:

- Command is chosen in `sandboxConfig.ts` `getSandboxCommand`: on `darwin`,
  when no explicit command is set and `sandbox-exec` exists, it auto-selects
  `'sandbox-exec'` (source-confirmed: `os.platform() === 'darwin' &&
  commandExists.sync('sandbox-exec')`). Seatbelt is therefore the *default*
  macOS sandbox when sandboxing is enabled at all.
- Profile name: `process.env['SEATBELT_PROFILE'] ??= 'permissive-open'`.
- Profile file resolves to `sandbox-macos-<profile>.sb`. Unrecognized names fall
  back to `~/.gemini` then project `.gemini`, with `path.basename()` stripping
  separators (source-confirmed path-traversal guard on `SEATBELT_PROFILE`). This
  still creates a policy-injection seam: when the user selects a non-built-in
  profile name and no same-named owner profile exists, repository-controlled
  `.gemini/sandbox-macos-<name>.sb` becomes the enforcement policy.
- Invocation shape (source-confirmed):
  `sandbox-exec -D TARGET_DIR=… -D TMP_DIR=… -D HOME_DIR=… -D CACHE_DIR=… -D INCLUDE_DIR_0..4=… -f <profile> sh -c 'SANDBOX=sandbox-exec NODE_OPTIONS=… <argv…>'`.
- `-D` parameters are `realpathSync`-resolved host paths. `INCLUDE_DIR_0..4`
  always emit five slots, unused ones defaulting to `/dev/null`.
- The whole Node CLI is relaunched inside the sandbox (`spawn(config.command,
  args, { stdio: 'inherit' })`); the child sets `SANDBOX=sandbox-exec` so the
  re-entrant process knows it is already sandboxed and does not recurse.

### Layer 2 (source-only, dynamic)

Source-confirmed in `MacOsSandboxManager.prepareCommand` and
`seatbeltArgsBuilder.buildSeatbeltProfile`:

- Per shell command, a profile string is generated from `BASE_SEATBELT_PROFILE`
  (`(version 1) (deny default) (import "system.sb")` plus a curated allowlist of
  `sysctl-read`, `mach-lookup`, PTY, and read-only system framework subpaths).
- Workspace read is always granted; workspace write only when `workspaceWrite`
  is true (not readonly mode, or strictly approved, or yolo).
- The profile is written to a temp file `gemini-cli-seatbelt-<ts>-<rand>.sb`
  with mode `0o600`, then run as `/usr/bin/sandbox-exec -f <tempfile> -- <cmd>`;
  a best-effort cleanup callback calls `unlinkSync` and ignores cleanup errors.
- Path strings are embedded into SBPL via `escapeSchemeString`
  (`\` and `"` escaped) and `escapeRegex` for secret-file regex denies.

Guard note: two co-existing sandbox layers with divergent assurance in one
product is itself a cautionary tale — it produces exactly the documentation gap
seen here (users read the permissive story; a second, stricter engine exists but
is not described on the sandbox page). Guard should never present two macOS
sandbox behaviors under one name.

## 2. What each profile actually allows/denies (source-confirmed)

Layer 1 static `.sb` files. The material `open` vs `proxied` difference is
network policy (source-confirmed via diff): `open` allows outbound networking;
`proxied` confines outbound TCP to `localhost:8877`. Restrictive/strict variants
allow inbound only on debugger port 9229 in both modes. The permissive proxied
profile additionally adds an inbound deny/debugger exception and `network-bind`
allowance; it also removes redundant explicit PTY file rules that were already
covered by `(allow default)`.

| Profile | Default | File read | File write | Notable allowances |
| --- | --- | --- | --- | --- |
| permissive-open / -proxied | `(allow default)` | Entire host readable | Deny-all except TARGET/TMP/CACHE, `~/.gemini`, `~/.npm`, `~/.cache`, 5 include dirs, tty/dev nodes | Everything else allowed: exec, all mach services, Apple Events, network (open) |
| restrictive-open / -proxied | `(deny default)` | `(allow file-read*)` — entire host readable | Same write allowlist as permissive | exec/fork, curated sysctl-read, `mach-lookup com.apple.sysmond`, tty ioctl; network open/proxied |
| strict-open / -proxied | `(deny default)` | Allowlisted only: `(literal "/")`, TARGET/TMP/CACHE, select `~` dotdirs, `/usr /bin /sbin /Library /System /private /etc /opt /Applications`; plus global `file-read-metadata` | Same write allowlist | Same as restrictive |

Critical source-confirmed observations for Layer 1:

- **`permissive-open` (the default) is effectively "read everything, talk to
  everything, only writes are fenced."** `(allow default)` means credential
  files, SSH keys, browser data, and any TCC-readable path are all readable, all
  mach services (including Apple Events) are reachable, and outbound network is
  unrestricted. The only real containment is write scope.
- Even `strict-open` allows `(allow file-read* (literal "/"))` and broad reads
  of `/usr /Library /private /etc /opt /Applications`, and `file-read-metadata`
  globally. It restricts *content* reads of `$HOME` outside a few dotdirs but is
  not a credential-tight boundary.
- All Layer 1 profiles allow `(allow process-exec)` / `process-fork`, and
  **child processes inherit the profile** (SBPL semantics; comment-confirmed in
  the profiles). There is no per-child re-evaluation.
- Write allowlist always includes `~/.npm` and `~/.cache` and (in the builder)
  PATH-derived and `~/.gemini` dirs — a broad-ish write surface intended for
  package-manager ergonomics.

Layer 2 dynamic profile (`buildSeatbeltProfile`), source-confirmed additions
beyond `(deny default)`:

- Conditional `(deny file-write*)` rules for governance files (`.gitignore`,
  `.geminiignore`, `.git`) and read/write denies for **secret files** (`.env`,
  `.env.*`) via anchored regex. These are tighter defaults, not unconditional
  invariants: governance denies can be omitted by writable/explicit policy, and
  `MacOsSandboxManager` automatically adds `.git` to the write set for detected
  git commands. Granular permission allows are appended after the secret rules,
  while only `forbiddenPaths` are deliberately appended last. H2/H4 therefore
  require live hostile tests rather than trust in source comments.
- Env-driven `forbiddenPaths` become `(deny file-read* file-write* (subpath …))`.
- Network is a single toggle appending `NETWORK_SEATBELT_PROFILE`
  (`allow network-outbound/inbound/bind` + DNS/trust mach services). There is
  **no host-scoped egress allowlist** — it is all-or-nothing per command.

## 3. Access-surface behavior (source-confirmed unless noted)

| Surface | Layer 1 permissive-open (default) | Layer 1 strict | Layer 2 dynamic |
| --- | --- | --- | --- |
| Workspace access | Read all; write only under TARGET_DIR + allowlist | Read allowlisted; write allowlist | Read workspace; write workspace only if not readonly/approved/yolo |
| Read scope | Entire host | `/` literal + system subpaths + few `~` dotdirs | `(deny default)`; workspace, tmp, node/PATH/system paths, detected git dirs, and additional approved paths |
| Write scope | TARGET/TMP/CACHE, `~/.gemini`,`~/.npm`,`~/.cache`, include dirs, tty | same | workspace (conditional), tmp, and approved paths; governance/secret rules have the exceptions and ordering caveats above |
| Network | Unrestricted outbound | Unrestricted outbound | On/off toggle; proxied variant only in Layer 1 |
| Credential/config exposure | High: all readable | Medium: selected `~` dotdirs plus broad system reads | Lower default file scope and `.env*` rules, but permission overrides and environment inheritance still need hostile tests |
| Env inheritance | Full `process.env` passed to `sh -c` | same | `sanitizeEnvironment` is called, but redaction is configuration-dependent except on the GitHub surface |
| Process execution | Allowed; children inherit profile | Allowed; inherit | Allowed within per-command profile; each command re-wrapped |

Env sanitization (Layer 2, source-confirmed, `environmentSanitization.ts`) has
useful Guard-aligned ingredients: an allowlist of benign vars, a
`NEVER_ALLOWED_ENVIRONMENT_VARIABLES` set, `NEVER_ALLOWED_NAME_PATTERNS`
(`/TOKEN/,/SECRET/,/PASSWORD/,/KEY/,/AUTH/,/CREDENTIAL/,/PRIVATE/,/CERT/…`), and
`NEVER_ALLOWED_VALUE_PATTERNS` (private-key headers, GitHub/Google/AWS/Stripe/
Slack token shapes, JWTs, credential-in-URL). Redaction becomes strict on
GitHub-surface runs. Crucial caveat (source-confirmed): otherwise,
`sanitizeEnvironment` returns a full copy of the environment when
`enableEnvironmentVariableRedaction` is false (its default absent configuration),
and `GEMINI_CLI_*` / `GIT_CONFIG_*` are always passed through. Guard may reuse
the pattern vocabulary, but not this opt-in posture or either unconditional
prefix exception.

## 4. Expansion / permission-escalation UX (source-confirmed)

- On a command failure, `parsePosixSandboxDenials` heuristically classifies the
  output as a file or network denial (keyword + regex scan of stdout/stderr,
  e.g. `operation not permitted`, `EACCES`, `sandbox:`), extracting denied
  absolute paths with traversal/`..`/null-byte sanitization.
- `shell.ts` then computes an **expanded permission set** (adds the nearest
  existing parent dir to read+write, may add `network`) and, if it is strictly
  larger, returns a `SANDBOX_EXPANSION_REQUIRED` tool error carrying a
  `sandbox_expansion` confirmation payload for the UI to approve.
- Crucially (source-confirmed, Layer 2 model): approval **re-runs the command
  with an expanded per-command profile**, not "outside the sandbox." The
  escalation grows the allowlist for that command; it does not drop the sandbox.
- Layer 1, by contrast, has no per-command expansion — the profile is fixed for
  the whole process; changing posture means restarting with a different
  `SEATBELT_PROFILE`.

Guard reuse: the *shape* (structured expansion request → explicit user approval
→ re-run tighter, never "run unsandboxed") is compatible with Guard's approval
UX. The *mechanism* (regex-scraping tool stderr to guess paths) is fragile and
must not be trusted as a security boundary — only as a UX hint.

## 5. Host-service escape surfaces (source-confirmed profile reading + macOS facts)

| Surface | Finding |
| --- | --- |
| Apple Events | Layer 1 permissive: `(allow default)` permits AppleEvent mach traffic → scripting other apps is reachable. Restrictive/strict deny by default (only sysmond allowed). Layer 2 base denies default; no AppleEvent service granted. |
| Launch Services / `open(1)` | Not explicitly denied in permissive; launching apps via LS is a known Seatbelt escape class. No profile blocks `open` binary exec specifically. |
| XPC / Mach services | Permissive allows all mach-lookup. Restrictive/strict + Layer 2 allow only a curated global-name list (sysmond, opendirectoryd, logd, trustd, notification_center, etc.). Any allowed service is a potential proxy to host capability. |
| Unix domain sockets | The profiles do not enumerate a deny/allow contract for host Unix sockets, and Layer 2 imports the opaque Apple `system.sb`; socket reachability must be measured rather than inferred from the IP network rules. |
| TCC-protected data | macOS architecture concern, not a Gemini source claim: `sandbox-exec` does not give the child a new signed App Sandbox/TCC identity. Host TCC grants associated with the launching context can therefore remain relevant. A permissive profile that allows reads may expose data the terminal can access. H10 must test observed denial even when launched from a terminal with Full Disk Access; this is a first-class reason native mode is lower assurance. |
| Keychain / trust services | Layer 2 always allows `trustd`; its network block additionally allows `SecurityServer`, `ocspd`, DNS, and configuration services. Whether those IPC paths expose credential operations is not established by source reading and requires H11. |
| Clipboard | Permissive allows the pasteboard path by default. Deny-default profiles do not document a pasteboard contract, while Layer 2 imports `system.sb`; H12 must determine actual reachability. Guard's terminal/clipboard broker has no analogue here. |

Net: Seatbelt constrains file and (optionally) network access but leaves a wide
IPC/host-service perimeter that depends entirely on how tight the profile is.
The permissive default leaves nearly all of it open.

## 6. `sandbox-exec` availability and compatibility (OS fact, not source)

- `sandbox-exec(1)` is **deprecated** by its installed Apple man page. Review on
  macOS 15.7.1 (build 24G231, arm64) confirmed that `/usr/bin/sandbox-exec`
  remains present and prints its expected usage; this evaluation deliberately
  did not execute an SBPL profile. The man page directs application developers
  to App Sandbox rather than offering a supported replacement CLI for ad-hoc
  third-party profiles.
- SBPL is an unversioned, undocumented-in-practice interface: profile primitives
  (`system.sb` import, allowed operations, mach global-names) have changed across
  releases, which is exactly why Gemini's Layer 2 base profile exists ("to handle
  undocumented internal dependencies … to avoid Abort trap: 6").
- Compatibility uncertainty is therefore **high and ongoing**: a profile that
  is tight today can break tools on a later macOS release, and the deprecated
  interface has no stability guarantee suitable for Guard's primary boundary.
  This is a standing argument for keeping Lima primary.

## 7. Reuse vs reject for Guard

Reuse (adapt behind Guard's existing controls):

- `(deny default)` per-command profiles with an explicit allowlist (Layer 2),
  never `(allow default)`.
- Embedding both original and `realpath`-resolved paths in allow/deny rules to
  defeat symlink confusion (source-confirmed dual-path emission).
- Explicit deny rules for secrets/governance (`.env*`, `.git`, credential
  files), with Guard-controlled ordering and hostile tests proving that no later
  approval can override the deny. Gemini's conditional exceptions are a warning,
  not a behavior to copy.
- Environment sanitization by name+value patterns, made mandatory by Guard with
  no opt-out and no unconditional vendor/Git prefix exceptions. Gemini's
  sanitizer supplies pattern ideas, not a safe default configuration.
- Structured "expansion request → explicit approval → re-run *tighter*" UX,
  never "re-run outside the sandbox."
- Temp profile files at `0o600` with explicit best-effort cleanup.

Reject (do not copy):

- `permissive-open` default and any `(allow default)` posture.
- Whole-host `(allow file-read*)` / `(literal "/")` reads (Layer 1 restrictive/
  strict) — incompatible with Guard's credential-tight model.
- Treating Seatbelt as sufficient isolation on its own, or as a Lima substitute.
- Loading any SBPL/profile from the repository or current directory. Native
  policy must be compiled into Guard or loaded from a fixed owner-private,
  signed location; project content can never select or supply its boundary.
- Writable mounting / direct write access to the **real** workspace. Guard keeps
  sanitized staging + copy-back; the native backend must operate on the staged
  copy, not the host workspace, even though Seatbelt's model tempts direct paths.
- All-or-nothing network toggle. Guard keeps exact-host egress approval and the
  proxy/credential broker; a native backend must route egress through the same
  broker, not `(allow network-outbound)`.
- Regex-scraping tool stderr as a security decision (fine as a UX hint only).
- Relying on inherited TCC grants; a native backend must document and, where
  possible, deny TCC-protected paths rather than inherit terminal FDA.

## 8. Guard requirements this evaluation locks in

- **Lima stays recommended / high-assurance.** No change to that posture.
- Any `macos-native` backend is **explicit, experimental, visibly lower-
  assurance, opt-in, and never an automatic fallback** (aligns with the existing
  `Never silently fall back from Lima to native mode` guarantee).
- The native backend must preserve, not bypass: sanitized staging + copy-back,
  exact-host egress approval, credential broker, terminal filter, audit trail,
  and denylist. Seatbelt is an *added* inner fence, not a replacement for any of
  these.
- No direct writable mount of the real workspace under any native profile.

## 9. Hostile-fixture test matrix (required before any go decision)

Every fixture runs under the candidate native profile **and** under Lima; a
fixture passes only if the native profile denies/contains it to the same
observable outcome Guard already guarantees on Lima. Evaluation only — these are
specified here, not implemented.

| ID | Hostile fixture | Must-deny / must-contain assertion |
| --- | --- | --- |
| H1 | Read `~/.aws/credentials`, `~/.ssh/id_*`, browser cookie stores | Denied; not readable from sandboxed tool |
| H2 | Read `.env` / `.env.local` in staged workspace | Denied (read and write) |
| H3 | Write outside staged copy (`$HOME`, `/tmp` escape, `..` traversal) | Denied; writes confined to staged copy |
| H4 | Modify `.git/hooks`, `.git/config` for RCE-on-next-git | Denied (git dir read-only) |
| H5 | Direct outbound to a non-approved host / raw socket | Denied; only broker egress path reachable |
| H6 | Exfil via allowed proxy to unapproved host | Denied by exact-host egress broker, not just network toggle |
| H7 | Apple Events to script another app (e.g. Terminal/Finder) | Denied |
| H8 | `open(1)` / Launch Services to spawn a host app outside sandbox | Denied or contained |
| H9 | Reach a Mach/XPC service not on the allowlist | Denied |
| H10 | Read TCC-protected data (Photos/Mail/`~/Library`) when launched from a terminal with Full Disk Access | Denied by the candidate boundary despite the launch context's grants |
| H11 | Keychain item read / trust-service abuse | Denied or explicitly scoped |
| H12 | Pasteboard read/write bypassing clipboard broker | Denied or brokered |
| H13 | Child process escaping parent profile / privilege via fork-exec | Contained; child inherits equal-or-tighter policy |
| H14 | Env-var credential leak (TOKEN/KEY/JWT/private-key value) into child | Redacted by sanitizer |
| H15 | Profile-break under a newer macOS (SBPL drift) | Fails closed (deny), never fails open |
| H16 | Repository supplies `.gemini/*.sb` or another policy/profile file | Ignored; project content cannot select or alter the native boundary |

## 10. Go/No-Go gate

Proceeding past a design spike to an actual `macos-native` backend requires **all**:

1. H1–H16 pass under the candidate profile with parity to Lima's guarantees,
   recorded as live hostile-fixture runs (same rigor as the Phase 0 Lima/Bwrap
   fixtures).
2. The backend routes all egress through Guard's credential/egress broker with
   exact-host approval — no `(allow network-outbound)` blanket rule.
3. No direct writable access to the real workspace; staged copy + copy-back only.
4. Terminal filter, audit, and denylist are active and demonstrated under native
   mode, not stubbed.
5. A documented fail-closed story for `sandbox-exec` deprecation/removal and
   SBPL drift, including a startup capability probe that refuses to run (rather
   than silently degrade) if the profile cannot be applied.
6. UX and docs label native mode as experimental and lower-assurance at every
   entry point, and it is never selected as an automatic fallback from Lima.
7. Independent adversarial (Codex) review approves the architecture and the
   fixture results.

If any item fails: **no-go**; Lima remains the only supported macOS backend.

## Highest-risk gaps (carry into review)

- **Documentation/behavior gap in the prior art itself:** the public docs
  describe only the permissive Layer-1 model; the stricter Layer-2 engine is
  undocumented on the sandbox page. Guard must not reproduce a split like this.
- **Layer-2 exceptions are wider than its comments suggest:** environment
  redaction is normally opt-in, git commands may receive `.git` write access,
  and later granular permission rules need live proof that they cannot override
  secret denies. Guard must encode these as non-overridable outer invariants.
- **Layer-1 custom-profile lookup can cross the project trust boundary:** a
  selected unknown name falls back to a `.gemini` profile in the current
  project. Guard must make repository-supplied native policy structurally
  unreachable.
- **TCC inheritance** (H10) is the sharpest native-only escape and cannot be
  dismissed by source inspection; behavior depends on both the launch context's
  grants and the candidate SBPL denies.
- **SBPL drift / `sandbox-exec` deprecation** makes any native profile a
  maintenance and fail-open risk (H15) that Lima does not carry.
- **Network is all-or-nothing** in the prior art; Guard's exact-host egress and
  broker have no Seatbelt analogue and must be layered on, not assumed.
- **Denial detection by stderr regex** is not a boundary; treat only as a hint.

## Recommendation

Adopt the reusable Layer-2 tactics (deny-default per-command profiles, dual-path
symlink hardening, secret/governance deny patterns, mandatory Guard-controlled
environment sanitization, tighten-on-approval UX) as *design inputs only*. Do
**not** implement a `macos-native`
backend at this time. Authorize at most a **gated design spike** that produces a
candidate `(deny default)` profile and runs the H1–H16 matrix against it, held
to the go/no-go gate above. Lima remains the recommended, high-assurance macOS
backend regardless of the spike's outcome.

Codex reviewed and corrected this source evaluation. That review approves this
document as a research record only; it does **not** approve a native backend or
waive any go/no-go condition above.
