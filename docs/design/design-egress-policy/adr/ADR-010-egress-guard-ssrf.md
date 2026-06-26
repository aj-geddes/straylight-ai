# ADR-010: Default-Deny Egress Allowlist + SSRF Guard

**Date**: 2026-06-25
**Status**: Proposed

## Context

Straylight makes outbound network connections **on the AI's behalf** on two
independent paths:

1. **The credential-injecting HTTP proxy** (`internal/proxy/proxy.go`,
   `HandleAPICall` → `p.client.Do(upstreamReq)`). The destination URL is the
   service `Target` joined with a caller-supplied `path`/`query`. The shared
   `*http.Client` uses Go's default `http.Transport` / `net.Dialer`, which will
   connect to *any* resolvable address, including `169.254.169.254` (cloud
   instance metadata), link-local, and RFC1918 private hosts.
2. **The command-exec path** (`internal/cmdwrap/wrapper.go`, `Wrapper.Execute`).
   The child process (`git`, `aws`, `curl`, …) runs with cloud/service creds in
   its environment and makes its *own* egress that Straylight does not mediate at
   the socket level at all.

`PRODUCT-STRATEGY.md` §2 is explicit and governing: the proxy stops **credential
exfiltration** (the secret never enters the model's context) but does **not** stop
**credential misuse**. A prompt-injected agent is a *confused deputy* — it can ask
`straylight_api_call` to `GET http://169.254.169.254/latest/meta-data/iam/...`
and the proxy will faithfully attach the real credential and return the body, or
ask `straylight_exec` to run a command that beacons data to an attacker host.
§3.4 names a **default-deny egress allowlist with SSRF blocking** as the
"highest-leverage single control — it attacks the trifecta's exfiltration leg."
This is a **Wave 0** item (§5) and tracks GitHub issue #9.

This ADR designs that control. ADR-011 (policy engine v1) is the complementary
request-shape gate; they are independent and composable.

### Constraints

- The proxy is on the hot path: every agent API call dials through it. The guard
  must add negligible latency and must not break TLS or the existing
  `SetHTTPClient` test seam.
- **DNS rebinding must be defeated.** Validating the *hostname* or a pre-resolved
  IP before `Dial` is insufficient: an attacker controls a domain whose A record
  flips from a public IP (passes a name/URL check) to `169.254.169.254` between
  the check and the actual connect (TOCTOU). The check must run on the **IP the
  dialer actually connects to**, inside `DialContext`, for every address the
  resolver returns.
- The exec path has **no socket Straylight owns**. We cannot wrap a child
  process's `connect(2)` from Go without OS-level sandboxing. The v1 design must
  be honest about this and pick the minimal, real control.
- Must match existing repo idioms: the strategy-registry style of
  `InjectorRegistry` (ADR-009), constructor-injected dependencies wired in
  `serve()`, interfaces declared at the consumer.
- Minimal, incremental v1. Do not build a full network policy DSL.

## Decision Drivers

- **Security** (primary): close the SSRF / metadata-endpoint exfiltration leg by
  default, fail-closed.
- **Correctness under DNS rebinding**: enforce on the resolved IP, not the name.
- **Maintenance**: one guard type, reused by both egress paths; data-driven
  allowlist, no per-service Go code.
- **Dev velocity / backward compat**: existing services keep working; the
  default denylist is opinionated but the allowlist is per-service and explicit.
- **Honesty**: the design names what it does *not* cover (exec socket-level
  egress, exfiltration through an approved host).

## Options Considered

### Option 1: Validate the URL host string before dialing

In `buildUpstreamRequest`, parse `svc.Target`, reject if the host is a private/
metadata literal, then dial normally.

**Pros**: trivial; no transport surgery; covers literal-IP targets.
**Cons**: **does not defeat DNS rebinding** — a hostname that resolves to
`169.254.169.254` passes the string check and is then dialed anyway. Also misses
redirects (a 302 to an internal host re-dials through the default transport).
Rejected as the *primary* mechanism; kept as a cheap pre-filter.

### Option 2: Custom `DialContext` that re-checks the resolved IP (chosen for proxy)

Install a `net.Dialer` whose `Control` / wrapped `DialContext` inspects the
**resolved `net.IP`** of the address being connected to and returns an error if
it is in the denylist and not in the per-service allowlist. This runs on the
actual connect address, so it also covers redirect-driven re-dials and DNS
rebinding (the resolver result is what we test).

**Pros**: defeats DNS rebinding (checks the IP actually dialed); covers every
connection the transport makes including redirects; one hook point; composes with
the existing `*http.Client`.
**Cons**: requires per-request knowledge of *which service's* allowlist applies,
threaded into the dialer (solved via `context.Context`, below); slightly more
plumbing than a string check.

### Option 3: Sandboxed/namespaced egress for the whole container (iptables / nft / seccomp)

Enforce egress at the kernel/network layer for both proxy and child processes.

**Pros**: the only thing that *actually* constrains a child process's own
sockets; defends paths Straylight never sees.
**Cons**: out of scope for an application-level v1; platform-specific
(Linux-only nft/eBPF), complicates the single-container onboarding story, and
cannot express a *per-service* host allowlist (it has no service context). The
right long-term complement, not the v1.

## Decision

Adopt a **single application-level egress guard** (`egress.Guard`) used by **both**
paths, with the enforcement *mechanism* differing by what each path can offer:

- **Proxy path — full IP-level enforcement (Option 2).** A custom
  `net.Dialer.DialContext` re-checks the **resolved IP** for every connection,
  defeating DNS rebinding and covering redirects. The pre-dial URL-host check
  (Option 1) is kept as a fast fail-early filter and for a clear error message.
- **Exec path — pre-flight host extraction + destination-host allowlist
  (best-effort), plus an explicit residual-risk note (Option 1-style, honest).**
  Straylight cannot wrap the child's sockets in v1, so it enforces what it *can*:
  the same `egress.Guard.CheckHost` is applied to any destination host parsable
  from the command/args before launch, and the design records that socket-level
  egress from the child is **not** mediated in v1 (Option 3 is the tracked
  follow-up). This keeps the claim honest per §2.

Chosen because Option 2 is the only one that satisfies the DNS-rebinding
constraint for the path Straylight fully owns, and because reusing one `Guard`
across both paths matches the registry/strategy idiom and keeps the denylist in
exactly one place. Option 3 is deferred, not rejected, and is the documented
paydown for the exec residual risk.

## Consequences

**Positive**
- Metadata-endpoint and private-range SSRF is blocked **by default, fail-closed**
  on the proxy path, on the *actual* connect IP — DNS rebinding and redirect
  re-dials are covered.
- One guard, one denylist, one allowlist model, reused by both paths and testable
  in isolation (no live sockets needed for the IP-classification logic).
- Per-service allowlist is data-driven (Service field + config.yaml), no Go code
  per service, matching the template/registry philosophy.

**Negative**
- The exec path is only partially covered in v1 (pre-flight host check, not
  socket-level). This is a known, documented limitation, not a silent gap.
- A per-service allowlist must be populated for services whose `Target` resolves
  to a non-public IP on purpose (rare; e.g. an internal API). Default-deny means
  these fail until allowlisted — intended.

**Risks**
- *Threading service context into the dialer.* The dialer is shared across
  requests; it must know which service's allowlist applies. **Mitigation**: carry
  the resolved allowlist on the request `context.Context` (a private key set in
  `HandleAPICall`); the dialer reads it back. No global mutable state.
- *Breaking the TLS test seam.* `SetHTTPClient` replaces the whole client in
  tests. **Mitigation**: the guard is installed by wrapping a transport; tests
  that inject `httptest.Server.Client()` either keep the default (guard disabled
  in unit tests via an all-allow guard) or wrap the test transport. The
  constructor takes the guard so tests can pass a permissive one.
- *Over-blocking localhost in dev.* Some users run a local upstream.
  **Mitigation**: loopback (`127.0.0.0/8`, `::1`) is configurable; default-deny,
  but documented `allow_loopback` per service.

**Tech Debt**
- TD: exec socket-level egress is unmediated in v1. Paydown plan: Wave 1+
  container-level egress (nft/eBPF allowlist derived from the same per-service
  host list), or an exec-time network namespace. Tracked against issue #9.
- TD: the pre-dial URL-host check (Option 1) duplicates classification logic with
  the dialer. Paydown: both call the same `Guard.classify(ip)`; the URL check
  resolves+classifies only as an optimization. Keep one source of truth.

## Implementation Notes

### New package: `internal/egress`

Mirrors the `InjectorRegistry` strategy-registry style and the consumer-declared
interface idiom. No dependency on `proxy`, `cmdwrap`, or `services`.

```go
// Package egress enforces a default-deny outbound network policy: SSRF target
// classes (cloud metadata, link-local, private ranges) are blocked unless a
// per-service allowlist explicitly permits the destination host.
package egress

// Decision is the outcome of an egress check.
type Decision struct {
    Allowed bool
    Reason  string // human-readable, safe to log/audit; never contains creds
}

// Policy is the per-service egress allowlist evaluated by a Guard.
// A nil/zero Policy means "default denylist only" (block SSRF classes, allow
// public destinations).
type Policy struct {
    // AllowHosts are destination hostnames (exact or "*.suffix") that are
    // permitted even if they resolve into an otherwise-denied range. Empty =
    // public destinations allowed, SSRF ranges denied.
    AllowHosts []string
    // AllowCIDRs are IP ranges explicitly permitted (e.g. an internal API at
    // 10.x). Empty = no private ranges permitted.
    AllowCIDRs []string
    // AllowLoopback permits 127.0.0.0/8 and ::1 (dev/local upstreams).
    AllowLoopback bool
}

// Guard classifies destinations against the default denylist and a Policy.
type Guard interface {
    // CheckIP classifies a single resolved IP against policy. This is the
    // authoritative check; it runs inside the proxy dialer on the IP actually
    // being connected to (defeats DNS rebinding).
    CheckIP(ip net.IP, policy Policy) Decision

    // CheckHost resolves host and applies CheckIP to every resulting address,
    // denying if ANY resolved address is denied (fail-closed). Used as the
    // pre-dial fast-filter on the proxy path and as the best-effort pre-flight
    // check on the exec path.
    CheckHost(ctx context.Context, host string, policy Policy) Decision
}

// New returns the default Guard seeded with the built-in SSRF denylist.
func New() Guard
```

### The default SSRF denylist (blocked unless allowlisted)

Classified by parsing the resolved `net.IP`; not string matching.

| Range / address | CIDR | Why |
|---|---|---|
| Cloud metadata | `169.254.169.254/32` | AWS/GCP/Azure IMDS — primary SSRF target |
| GCP metadata alias | `metadata.google.internal` (name) → resolved IP | covered by name check + IP check |
| Link-local IPv4 | `169.254.0.0/16` | includes IMDS + cloud link-local |
| Link-local IPv6 | `fe80::/10` | IPv6 link-local |
| Private IPv4 (RFC1918) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | internal networks |
| Carrier-grade NAT | `100.64.0.0/10` | RFC6598 shared address space |
| Unique-local IPv6 | `fc00::/7` | RFC4193 private IPv6 |
| Loopback | `127.0.0.0/8`, `::1` | denied unless `AllowLoopback` |
| Unspecified / "this host" | `0.0.0.0/8`, `::` | spoofs local services |
| IPv4-mapped IPv6 | `::ffff:0:0/96` | unmap, then re-classify the v4 |

Implementation: maintain the denied set as parsed `*net.IPNet` values built once
in `New()`; `CheckIP` unmaps IPv4-in-IPv6, then returns `Allowed:false` if the IP
is in any denied net AND not matched by `policy.AllowCIDRs` / `policy.AllowHosts`
(host match is applied at `CheckHost` resolution time, carrying the matched host
down). `AllowLoopback` toggles the loopback nets out of the denied set for that
check.

### Hook point 1 — Proxy dialer (authoritative, IP-level)

**File**: `internal/proxy/proxy.go`. The `*http.Client` constructed in
`NewProxyWithTTL` gets an explicit `*http.Transport` whose `DialContext` wraps a
`net.Dialer` and re-checks the resolved IP:

- Add a `guard egress.Guard` field to `Proxy`; accept it in the constructor
  (`NewProxyWithTTL(resolver, sanitizer, guard, ttl)`), defaulting to
  `egress.New()` in `NewProxy`.
- Build the client as:
  ```go
  dialer := &net.Dialer{Timeout: 10 * time.Second}
  transport := &http.Transport{
      DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
          host, port, _ := net.SplitHostPort(addr)
          policy := policyFromContext(ctx) // set per-request in HandleAPICall
          // Resolve, then check EVERY candidate IP on the actual dial.
          ips, err := dialer.Resolver.LookupIP(ctx, "ip", host)
          if err != nil { return nil, err }
          for _, ip := range ips {
              if d := guard.CheckIP(ip, policy); !d.Allowed {
                  return nil, fmt.Errorf("egress denied: %s (%s)", host, d.Reason)
              }
          }
          // Dial the vetted IP directly (pin to a checked address to avoid a
          // second, unchecked resolution inside Dial).
          return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
      },
      ForceAttemptHTTP2: true,
  }
  client := &http.Client{Timeout: defaultTimeout, Transport: transport}
  ```
- In `HandleAPICall`, after `p.resolver.Get(req.Service)`, derive the service's
  `egress.Policy` from `svc.Egress` (new Service field, below) and attach it to
  `ctx` via `context.WithValue(ctx, egressPolicyCtxKey{}, policy)` before
  building/sending the request. **No pre-dial `CheckHost` call is made in
  `HandleAPICall`**: the sole authoritative check is inside `DialContext`, which
  resolves and classifies the IP the dialer actually connects to (defeating DNS
  rebinding and covering every redirect re-dial). This is consistent with the
  implementation in `internal/proxy/proxy.go`.
- `SetHTTPClient` is preserved for tests; additionally provide a constructor that
  accepts a permissive `egress.New()`-equivalent all-allow guard for unit tests
  that hit `httptest` loopback servers, OR set `AllowLoopback` in the test
  policy. (Redirect re-dials are automatically covered because every dial flows
  through `DialContext`.)

### Hook point 2 — Exec path (best-effort pre-flight)

**File**: `internal/cmdwrap/wrapper.go`, `Wrapper.Execute`, **before**
`exec.CommandContext` is launched (after the allowlist check at
`checkAllowlist`):

- Add a `guard egress.Guard` and a per-service `egress.Policy` (resolved from the
  Service) to `Wrapper`; accept via `NewWrapper(resolver, sanitizer, guard)`.
- Extract candidate destination hosts from `argv` (URL-shaped args and
  `--host`/`-H` style flags via a conservative parser). For each, call
  `guard.CheckHost(ctx, host, policy)`; if any is denied, return a setup error
  (`cmdwrap: egress denied for host %q: %s`) **before** the credential-bearing
  process starts.
- **Residual risk (documented, not silently ignored):** a child process can open
  sockets to hosts not present as parseable args (env-driven endpoints,
  config-file targets, follow-on connections). v1 does **not** mediate those.
  This is the Option-3 paydown tracked against issue #9.

### Wiring in `serve()`

**File**: `cmd/straylight/main.go`, in the component-graph section (around line
153–155), construct the guard once and inject it into both consumers:

```go
guard := egress.New()                              // built-in SSRF denylist
san   := sanitizer.NewSanitizer()
p     := proxy.NewProxyWithGuard(registry, san, guard)   // dialer enforces IP-level
cmdExec := cmdwrap.NewWrapper(registry, san, guard)      // pre-flight host check
mcpHandler := mcp.NewHandler(p, registry)
mcpHandler.SetCommandExecutor(cmdExec)
```

Per-service `egress.Policy` is resolved inside `HandleAPICall` / `Execute` from
the new `Service.Egress` field (see schema additions below), so no extra wiring
is needed beyond passing the shared `guard`.

### Service & config schema additions

`internal/services/registry.go` — add to `Service`:

```go
// Egress is the per-service outbound allowlist applied by the egress guard.
// When nil, only the built-in SSRF denylist applies (public destinations
// allowed, metadata/private/link-local denied).
Egress *EgressPolicy `json:"egress,omitempty" yaml:"egress,omitempty"`
```

```go
// EgressPolicy is the persisted, declarative form of egress.Policy.
type EgressPolicy struct {
    AllowHosts    []string `json:"allow_hosts,omitempty"    yaml:"allow_hosts,omitempty"`
    AllowCIDRs    []string `json:"allow_cidrs,omitempty"    yaml:"allow_cidrs,omitempty"`
    AllowLoopback bool     `json:"allow_loopback,omitempty" yaml:"allow_loopback,omitempty"`
}
```

`internal/config/config.go` — add to `ServiceConfig`:

```go
Egress *EgressPolicyConfig `yaml:"egress"`
```
```go
type EgressPolicyConfig struct {
    AllowHosts    []string `yaml:"allow_hosts"`
    AllowCIDRs    []string `yaml:"allow_cidrs"`
    AllowLoopback bool     `yaml:"allow_loopback"`
}
```

`validateService` (registry.go) gains: each `AllowCIDR` must `net.ParseCIDR`
cleanly; each `AllowHost` must be a valid hostname or `*.suffix`. Persist via the
existing `saveMetadata` path (serialize `Egress` as a JSON string field, like
`default_headers`) and restore in `LoadFromVault`. No default-deny surprise for
existing services: a service whose `Target` is a public host needs no policy.

### Audit

Add `audit.EventEgressDenied EventType = "egress_denied"` (next to the existing
constants in `internal/audit/audit.go`). The proxy and wrapper emit it on a deny
with `Service`, `Details{"host", "reason"}` — **never** the credential. This makes
SSRF attempts tamper-evidently visible (§3.4).

## Test Plan

`internal/egress/guard_test.go` (pure, no sockets):
- `CheckIP` table test: every denylist row (metadata `169.254.169.254`, link-local
  v4/v6, all three RFC1918 nets, CGNAT, ULA v6, loopback, unspecified,
  IPv4-mapped-IPv6 `::ffff:169.254.169.254`) → denied; sample public IPs
  (`1.1.1.1`, `93.184.216.34`) → allowed.
- Allowlist precedence: a denied IP inside `AllowCIDRs` → allowed; a host in
  `AllowHosts` whose IP is otherwise denied → allowed; `AllowLoopback` toggles
  `127.0.0.1`/`::1`.
- `CheckHost` fail-closed: a host resolving to **multiple** IPs where one is
  private → denied (the "any denied ⇒ deny" rule).

`internal/proxy/proxy_egress_test.go`:
- **DNS-rebinding simulation**: a stub resolver on the dialer returns a public IP
  for the URL-host check but `169.254.169.254` at dial time → request fails with
  `egress denied`, and `p.client.Do` never connects.
- Literal metadata target (`http://169.254.169.254/...`) → denied pre-dial.
- Allowlisted private target (`AllowCIDRs: 10.0.0.0/8`) reaches an `httptest`
  server bound to a private/loopback addr.
- Redirect to an internal host (302 → `http://10.0.0.1/`) → the re-dial is denied
  by `DialContext`.
- Backward compat: existing proxy tests pass with an all-allow / loopback-allowed
  test guard (the `httptest` servers are loopback).

`internal/cmdwrap/wrapper_egress_test.go`:
- A command with a denied URL arg (`curl http://169.254.169.254/...`) → setup
  error, process never launched (assert no exec).
- A command with an allowlisted host arg → proceeds.
- A command with no parseable host → proceeds (documents the residual-risk gap;
  the test asserts current v1 behavior explicitly).

Audit: assert `egress_denied` is emitted on deny with host+reason and **no**
credential material (reuse the `proxy_audit_test.go` redaction assertions).

## Validation Criteria

- 100% of the denylist rows are covered by `CheckIP` tests and all deny.
- The DNS-rebinding test fails the request on the resolved-at-dial IP (proves the
  check is on the connect address, not the name).
- No existing proxy/exec test regresses.
- Reconsider when: container-level egress (Option 3) lands (then the exec
  residual-risk note is retired), or when per-service policies grow beyond
  host/CIDR/loopback (promote `EgressPolicy` to its own ADR).

## Residual Risk (must ship in docs)

An egress allowlist constrains *where* a connection may go; it does **not** stop
**exfiltration THROUGH an approved host**. If a service is allowlisted to a broad
destination (e.g. `*.githubusercontent.com`, a gist/raw endpoint, a webhook
catch-all, or any host that echoes attacker-controlled paths/bodies back out),
a prompt-injected agent can stage data *to* that approved host and an attacker can
retrieve it — the **CamoLeak** class of attack. The guard reduces the exfiltration
surface to the allowlisted set; it cannot reason about whether an allowed host is
itself an exfiltration channel. Keep allowlists **narrow and specific**, prefer
exact hosts over wildcards, and pair this control with the response sanitizer
(defense-in-depth, never a guarantee — §2) and the policy engine (ADR-011, which
bounds method/path so e.g. `POST` to a read-only host is denied before a
credential is attached). This limitation is consistent with §2: no proxy-side
control stops a confused-deputy agent from *attempting* misuse — it makes misuse
**scoped, bounded, and auditable.**
