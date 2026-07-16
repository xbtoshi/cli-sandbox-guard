# alpha.3 known issue — bwrap launcher environment leak (fixed in alpha.4)

This file is a handoff for the maintainer (Codex). It contains **recommended text to publish on the
existing GitHub alpha.3 release** as a known-issue note. The implementing agent does **not** edit
GitHub releases; apply this manually after review.

## Context

A live inside-sandbox probe (see `docs/LIVE_SANDBOX_PROBE_2026-07-16.md`) found that Bubblewrap's
`--clearenv` scrubs only the executed child, while the bwrap launcher itself stays alive as pid 1
inside the sandbox pid namespace with a tool-readable `/proc/1/environ`. On alpha.3 that exposed the
launcher's inherited session environment to the confined tool. Under the Lima backend the leaked
values are guest identity/metadata (not host files); on the direct-Linux backend the same mechanism
can expose the host shell's session environment, which may contain secrets. This is an information
disclosure, not a filesystem/network/seccomp escape — no host-file, host-network, or namespace
breakout was demonstrated.

Fixed in alpha.4 by interposing a fixed-argv `env -i` clean-environment boundary immediately before
bwrap on every backend/mode, proven by the hostile backend probe reading `/proc/1/environ`.

## Recommended release-note text for the published alpha.3 release

> **Known security issue (fixed in 0.3.0-alpha.4): launcher environment disclosure via
> `/proc/1/environ`.**
>
> On 0.3.0-alpha.3, Bubblewrap's `--clearenv` cleared the environment of the sandboxed *child*
> process but not of the bwrap launcher itself. bwrap remains pid 1 inside the sandbox pid namespace,
> and its `/proc/1/environ` was readable by the confined tool. This let a malicious or
> prompt-injected tool read the launcher's inherited session environment (on Linux, potentially host
> shell variables including secrets; under macOS/Lima, guest session metadata such as home path,
> proxy address, and XDG/DBUS/SSH identifiers).
>
> This is an **information-disclosure** issue. It did **not** grant reading of unstaged host files,
> host network access, or any namespace/seccomp escape.
>
> **Fix:** 0.3.0-alpha.4 places a fixed-argument `env -i` clean-environment boundary immediately
> before bwrap on every backend and mode (Linux host and Lima guest; interactive and noninteractive;
> cgroup-enforced and best-effort), so the launcher inherits an empty environment (host) or only a
> fixed non-secret `PATH` (guest). A regression probe reads `/proc/1/environ` and fails closed if any
> inherited variable survives.
>
> **Recommendation:** upgrade to 0.3.0-alpha.4. Treat any credential that was forwarded into an
> alpha.3 session on the direct-Linux backend as potentially observed by the tool if the tool was
> untrusted.

## What not to claim

- Do **not** attribute a specific artifact SHA-256 or build commit to the live probe; the probe did
  not capture binary provenance (`docs/LIVE_SANDBOX_PROBE_2026-07-16.md` records this explicitly).
- Do **not** describe this as a sandbox "breakout"; it is metadata/credential-environment disclosure
  of the launcher process, not a host filesystem or network escape.
