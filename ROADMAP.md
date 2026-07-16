# Sandbox Guard Roadmap

**Status:** version 0.3 alpha planning, 2026-07-15.

Sandbox Guard will keep its trusted Rust staging, policy, synthetic-Git, audit, egress, and
reviewed-apply layers. Existing sandbox projects are useful prior art, but neither Firejail nor
Anthropic Sandbox Runtime replaces the full boundary required for an untrusted AI coding CLI.

## Design principles

- The original repository is never mounted into the untrusted tool boundary.
- Filename policy is enforced while building a sanitized stage, not only by masking host paths at
  runtime.
- Multiply linked, symbolic-link, special-file, traversal, cross-filesystem, and source-mutation
  cases fail closed.
- The tool receives a synthetic Git repository without original objects, history, hooks, config,
  alternates, or credentials.
- Tool writes remain disposable until trusted host code validates and applies them.
- Project-local content cannot widen filesystem, network, credential, or execution policy.
- Network and credential decisions are made by trusted host-side brokers, never by the tool.
- Linux and macOS runners consume the same staged workspace and policy result.
- Every convenience feature must state whether it weakens the boundary.

## Prior-art decisions

### Firejail

Firejail demonstrates mature Linux application profiles, reusable syscall groups, monitoring,
distribution packaging, and canonical command wrapping. We should learn from those operational
features.

We will not adopt these Firejail defaults as the Sandbox Guard security contract:

- a large SUID executable in the trusted computing base;
- direct access to the real writable workspace;
- path-only blacklists that do not close hard-link aliases or historical Git objects;
- inherited host environment variables;
- SSH-agent access for an untrusted coding agent;
- IP/firewall-only egress as a replacement for hostname, DNS, and TLS-SNI validation;
- discarded or persistent private homes without trusted, conflict-checked copy-back.

Firejail may later be evaluated as an optional Linux execution backend, but only behind the same
Rust staging, proxy, credential, audit, and apply layers, and only after it passes the complete
backend test contract.

### Anthropic Sandbox Runtime

Sandbox Runtime demonstrates strong agent-oriented UX: cross-platform runners, domain-filtering
HTTP and SOCKS proxies, violation monitoring, typed policy, credential sentinels, optional TLS
termination, broad integration tests, and a verified release workflow. Those are the most useful
ideas to adapt.

We will not adopt these weaker postures:

- direct host-workspace access instead of sanitized staging;
- permissive read defaults for an untrusted vendor binary;
- masking failures that warn and expose the real credential;
- project-authored settings that can widen the sandbox;
- Apple Events, `open`, trust services, or other host capabilities without an explicit weaker-mode
  declaration;
- generic TLS interception without a vendor-qualified adapter, upstream verification, strict
  limits, and a clear certificate-pinning/mTLS escape policy.

## Phase 0: publishable v0.3 alpha

- [x] Set the release candidate version and create a signed Git tag.
- [x] Publish checksummed macOS ARM64 and Linux x86-64/ARM64 binaries.
- [x] Verify that release artifacts contain the exact binaries tested in CI.
- [x] Add installation, upgrade, rollback, and removal instructions.
- [x] Run and record live Bubblewrap and Lima hostile-fixture tests against the release artifacts.
- [x] Keep the README, security model, and CLI output explicitly labelled as alpha.
- [x] Require an independent adversarial review for changes to a trusted boundary component.

## Phase 1: installation and trusted tool profiles

### One-command setup

- [x] Add `guard setup` with platform detection and idempotent repair.
- [ ] Provision the mountless Lima instance, Bubblewrap, `guard-helper`, and the selected verified
  vendor tool on macOS. Partial: `guard setup --create-instance` now creates the absent mountless
  instance, and the separate `guard setup --start-instance` action starts only an existing,
  declared-mountless stopped instance and verifies its live mounts. Both are confirmed and never
  reconfigure/delete the VM; guest packages, the helper, and the vendor tool remain manual and
  open.
- [ ] Install and verify the Linux runtime dependencies without silently weakening namespace or
  cgroup requirements.
- [x] Add `guard setup --check` and actionable diagnostics for the host/backend components it
  checks; selected vendor-tool provisioning remains a separate item above.
- [x] Add an explicit removal command that deletes only Guard-owned state.

### Declarative profiles

- [x] Define a versioned, deny-unknown-fields Rust schema for trusted vendor profiles.
- [x] Move Grok-specific binary paths, egress hosts, credential handling, session paths, clipboard
  behavior, runtime mounts, and seccomp compatibility into a built-in Grok profile.
- [x] Permit owner-controlled policy to tighten a profile, never widen a built-in boundary.
- [x] Add `guard profile list`, `guard profile show`, `guard profile lint`, and
  `guard profile explain`.
- [x] Require signed profiles before supporting third-party distribution. `guard profile install`
  verifies a detached Ed25519 signature over the exact profile bytes against a pinned signer
  fingerprint and stores it in an internally derived owner-private location; `guard profile list`
  and `show NAME --version VERSION` re-verify installed profiles on every read. Exact-version
  removal remains available even when stored content is corrupt, while retaining the store's path,
  ownership, and symlink checks. Runtime consumption is deliberately deferred: installed profiles
  are content-only and are never runtime-effective this milestone.

## Phase 2: violations, inspection, and approval UX

- [ ] Record denied filesystem, network, environment, syscall, and resource attempts without
  recording secret values or denied file contents.
- [ ] Add `guard events`, `guard audit --tail`, and `guard inspect RUN_ID`.
- [ ] Summarize blocked actions after a run, grouped by capability and exact sandbox-visible path or
  destination.
- [ ] Keep violation monitoring observational: monitor failure must not disable enforcement.
- [x] Add bounded, serialized native approval for capabilities that can be safely granted without
  exposing the real host workspace.
- [ ] Add allow/deny management commands that can create, update, list, forget, and clear exact-host
  decisions without manually editing the private decision file.

## Phase 3: credential sentinel broker and request-aware egress

The main goal is to stop the untrusted CLI from ever learning a reusable real credential while
still allowing approved authenticated API calls.

- [ ] Give the sandbox a random fake credential or format-preserving fake JWT.
- [ ] Keep the sentinel-to-real mapping only in locked host process memory.
- [ ] Bind each credential to an explicit exact-host injection list.
- [ ] Substitute the real credential only inside a trusted proxy after destination validation.
- [ ] Abort or withhold the credential if masking, parsing, injection, or policy validation fails;
  never warn and expose the real value.
- [ ] Ensure audit and debug logs contain credential names and sentinel identifiers at most, never
  real values.
- [ ] Document that brokerage prevents credential theft and replay but cannot prevent an approved
  tool from misusing the credential through the allowed service.

### Qualified TLS termination

- [ ] Implement TLS termination only for adapter-qualified vendor endpoints.
- [ ] Verify the real upstream certificate and hostname independently.
- [ ] Keep opaque CONNECT tunnelling for certificate-pinning and mTLS endpoints, with credential
  injection disabled there.
- [ ] Enforce exact host, port, method, URL path, header, and bounded-body policy before forwarding.
- [ ] Show request details in trusted approval UI only after successful TLS parsing and before any
  upstream application bytes are sent.
- [ ] Redact credentials and cap displayed/logged header and body sizes.
- [ ] Add hostile HTTP parsing, request smuggling, decompression, streaming, WebSocket, and protocol
  upgrade fixtures.

## Phase 4: runner backends

### macOS

- [x] Keep `macos-lima` as the recommended hardened backend.
- [ ] Evaluate an experimental `macos-native` Seatbelt backend for low-friction local use.
  Prior-art source evaluation (Gemini CLI Seatbelt) with a hostile-fixture matrix and go/no-go
  gate is recorded in [docs/MACOS_NATIVE_EVALUATION.md](docs/MACOS_NATIVE_EVALUATION.md);
  implementation remains open and unapproved.
- [ ] Clearly label native mode as a different assurance tier and test Apple Events, Launch
  Services, XPC, Mach services, Unix sockets, TCC, and trust-service escape paths.
- [x] Never silently fall back from Lima to native mode.

### Linux

- [x] Keep `linux-bwrap` as the reference backend.
- [ ] Evaluate Firejail only as an optional distribution-integrated backend.
- [ ] Require backend parity for clean environment, private credentials, network namespace, proxy
  transport, PID boundary, seccomp, cgroups, terminal, clipboard broker, and safe export.
- [ ] Do not copy GPL Firejail implementation code into the MIT-licensed Rust project.

### Other platforms

- [ ] Defer Windows support until Linux and macOS release, installation, and live vendor tests are
  continuous gates.
- [ ] If Windows is added, prefer a dedicated low-privilege user, WFP egress fence, job object,
  private profile, and explicit per-run filesystem grants.

## Phase 5: hardening and resource control

- [x] Scrub the bwrap launcher's own initial exec environment (`env -i` boundary before bwrap on
  every backend/mode), so pid 1's `/proc/1/environ` cannot leak inherited host session variables to
  the confined tool; proven by the hostile backend probe (alpha.4).
- [ ] Replace the focused seccomp deny list with maintained, architecture-generated syscall groups
  qualified against each supported vendor workload.
- [ ] Generate and test filters for x86-64 and ARM64 from one reviewed source definition.
- [ ] Add live probes for every denied syscall family, not only filter-structure tests.
- [ ] Enforce aggregate writable-disk, file-count, memory, PID, CPU, and network-bandwidth quotas.
- [ ] Add crash recovery for interrupted multi-file apply transactions.
- [ ] Add live credential refresh brokerage without exposing the refresh token.
- [ ] Verify installed tool identity automatically at every execution.
- [ ] Implement a signed downloader, rollback policy, and minimal privileged installer.
- [ ] Install a root-owned canonical wrapper only after its resolution and replacement tests pass.

## Phase 6: vendor expansion

- [ ] Keep Grok as the first supported real workflow until it has at least seven days of green live
  pilot use.
- [ ] Add Codex and OpenCode only through trusted profiles and the complete backend fixture suite.
- [ ] Qualify login, token refresh, API calls, subprocesses, terminal behavior, clipboard imports,
  session persistence, updates, and change apply for every supported version.
- [ ] Pin supported vendor versions and fail with an explicit compatibility error outside the
  qualified range.

## Production gates

Sandbox Guard must remain labelled alpha until all applicable gates are closed:

- [ ] One-command installation and verified removal on supported platforms.
- [ ] Signed, reproducible, provenance-bearing release artifacts.
- [ ] Live Linux and Lima isolation tests in continuous integration.
- [ ] Real vendor workflows tested on every supported architecture.
- [ ] Canonical wrapper and verified updater deployed without widening the trusted computing base.
- [ ] Aggregate resource quotas enforced and tested.
- [ ] Maintained seccomp policy with non-vacuous runtime probes.
- [ ] Credential brokerage or an equally explicit residual credential-exposure contract.
- [ ] Independent security audit with no unresolved boundary-crossing blocker.
- [ ] Documentation and audit fields verified against real runtime behavior.

## References

- [Firejail](https://github.com/netblue30/firejail)
- [Firejail LLM agent profile](https://github.com/netblue30/firejail/blob/master/etc/profile-a-l/llm-agent-common.profile)
- [Anthropic Sandbox Runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [Sandbox Runtime credential sentinel](https://github.com/anthropic-experimental/sandbox-runtime/blob/main/src/sandbox/credential-sentinel.ts)
- [Sandbox Runtime integration workflow](https://github.com/anthropic-experimental/sandbox-runtime/blob/main/.github/workflows/integration-tests.yml)
- [Sandbox Guard security model](docs/SECURITY_MODEL.md)
- [Sandbox Guard requirements register](sandbox-guard-requirements.md)
