# ADR-011: Per-Service Policy Engine v1 (Tool-Call Gate)

**Date**: 2026-06-25
**Status**: Proposed

## Context

Per `PRODUCT-STRATEGY.md` §2, hiding the secret addresses **exfiltration** but not
**misuse**: a prompt-injected agent is a *confused deputy* that can call
`straylight_api_call` / `straylight_exec` / `straylight_db_query` with
attacker-chosen arguments, and the proxy attaches the real credential. §3.4 and
the Wave-0 roadmap (§5) call for "a **policy engine that gates tool calls on
arguments and destinations**, not merely on 'does a credential exist' … the only
layer that touches threat class (b)" and, concretely, "**Policy engine v1**: gate
each tool call on method/path/host (per-service allowlist)."

Today there is **no such gate**. `dispatchToolCall`
(`internal/mcp/tools.go`) routes by tool name, then `handleAPICall` → the proxy's
`HandleAPICall` (`internal/proxy/proxy.go`) builds the upstream request and
**injects the credential** with no check on whether *this* service is allowed to
receive *this* HTTP method against *this* path. ADR-010 constrains the destination
IP; this ADR constrains the **request shape** (method / path-prefix / host) so a
read-only service can be denied a `DELETE`, or a service can be pinned to
`/v1/charges` before any credential touches the wire.

This is the request-shape complement to ADR-010's network-layer guard. The two
are independent and composable: ADR-010 answers "may we connect to that IP?",
ADR-011 answers "may this service perform this method on this path/host?".

### Constraints

- **Decide before credential injection.** The gate must run *before* the
  injector attaches the secret (defense: never lend authority to a denied call).
- Minimal v1: method allowlist + path-prefix allowlist + host allowlist,
  **default-deny per field when configured, default-allow when unset** (so
  existing services keep working until an operator opts a service into a policy).
- Match repo idioms: a small evaluator type, consumer-declared interface,
  data-driven per-service config (Service field + config.yaml), wired in
  `serve()`. Same philosophy as the `InjectorRegistry` (ADR-009).
- Returns a structured allow/deny **+ reason** (auditable, safe to surface).
- Do not build a general policy DSL, RBAC, or per-identity rules in v1.

## Decision Drivers

- **Security**: introduce the one control layer that touches *misuse*; fail-closed
  where a policy is set.
- **Simplicity**: three match dimensions, evaluated in-process, no external engine.
- **Placement correctness**: gate runs before injection on every path.
- **Backward compatibility**: a service with no policy behaves exactly as today.
- **Auditability**: deny reason is recorded (§3.4 tamper-evident audit).

## Options Considered

### Option 1: Inline the checks in `handleAPICall`

Add `if method not in allowed { return errorResult }` directly in
`internal/mcp/tools.go` `handleAPICall`.

**Pros**: trivial, no new types.
**Cons**: only covers `straylight_api_call`; `straylight_exec` / `db_query` get
nothing; logic duplicated per tool; not independently testable; the proxy (which
also builds the request) is bypassed if called directly. Rejected.

### Option 2: A `policy.Engine` evaluated at the dispatch seam + proxy seam (chosen)

A small evaluator (`policy.Engine`) with `Evaluate(Request, Policy) Decision`.
Called in two complementary places:
- **`dispatchToolCall`** (`internal/mcp/tools.go`) — the natural per-tool gate;
  resolves the per-service policy and evaluates the request *before* dispatching
  to the handler. Covers all tools uniformly with one seam.
- **`HandleAPICall`** (`internal/proxy/proxy.go`) — a **belt-and-suspenders**
  re-check immediately before injection, so the proxy is safe even if invoked
  outside the MCP handler. The proxy is the source of truth that a credential is
  about to be attached, so it is the correct *last* place to deny.

**Pros**: one evaluator, two well-defined seams; before-injection guarantee at the
proxy; default-allow when unset preserves compat; data-driven; testable in
isolation; mirrors the strategy/registry idiom.
**Cons**: the policy is evaluated twice for `api_call` (dispatch + proxy). This is
intentional defense-in-depth and is cheap (in-memory prefix/string match); the
proxy check is authoritative.

### Option 3: Adopt an external policy engine (OPA/Rego, Pomerium-style)

Embed a general policy engine.

**Pros**: very expressive; future-proof.
**Cons**: massive over-build for v1 (method/path/host); new dependency, new
language (Rego), startup/eval cost, and operator burden — contradicts the
"minimal control that touches misuse" framing and the single-container ethos.
Deferred; the v1 `Policy` struct is shaped so it could be *compiled from* such a
source later without changing call sites.

## Decision

Adopt **Option 2**: a new `internal/policy` package with an `Engine` evaluated at
**both** the `dispatchToolCall` seam (uniform per-tool gate) **and** the
`HandleAPICall` seam (authoritative pre-injection re-check). Policy is per-service,
**default-allow when a dimension is unset, default-deny within a dimension that is
configured** (e.g. setting `AllowedMethods: [GET]` denies everything but GET).
`Evaluate` returns `Decision{Allowed, Reason}`. Denials short-circuit before any
credential injection and are audited.

Chosen over Option 1 (incomplete, untestable) and Option 3 (over-built for v1).
The two-seam placement gives both uniform tool coverage *and* the
before-injection guarantee at the credential boundary, matching §3.4's intent with
the least machinery.

## Consequences

**Positive**
- First control that touches the *misuse* threat class: a service can be pinned to
  least-method/least-path before a credential is ever attached.
- One evaluator reused at two seams; pure function, trivially unit-tested.
- Per-service, data-driven; adding a policy is config, not code.
- Deny reasons are auditable and safe to surface to the agent ("method DELETE not
  permitted for service stripe").

**Negative**
- Two evaluations for `api_call` (dispatch + proxy). Negligible cost; the proxy
  evaluation is the authoritative one.
- Path-prefix matching is coarse (no full glob/regex in v1). A service needing
  fine-grained rules waits for v2. Acceptable per "minimal v1".

**Risks**
- *Policy bypass if a new tool is added but not gated.* **Mitigation**: the gate
  lives in `dispatchToolCall` (one choke point all tools pass through); the proxy
  re-check backs `api_call`. A test asserts every credential-bearing tool resolves
  a policy.
- *Over-deny breaking existing services.* **Mitigation**: default-allow when a
  service has no policy and within any unset dimension; only configured dimensions
  constrain.
- *Path normalization tricks* (`/v1/../admin`, `%2e%2e`). **Mitigation**:
  normalize the path (clean + percent-decode once) before prefix matching; a
  matched prefix is checked against the cleaned path. Document that path matching
  is on the cleaned path.

**Tech Debt**
- v1 path matching is prefix-only. Paydown: v2 adds explicit glob/regex behind the
  same `Policy` shape (no call-site change). Tracked with issue #9.
- The proxy and dispatch both resolve the policy; resolution is duplicated.
  Paydown: a single `PolicyResolver` interface (consumer-declared) used by both,
  fed from the registry.

## Implementation Notes

### New package: `internal/policy`

```go
// Package policy gates tool calls on request shape (HTTP method, path-prefix,
// destination host) against a per-service, default-deny-when-configured policy.
// It is evaluated BEFORE any credential is injected.
package policy

// Request is the credential-free shape of a tool call being evaluated.
type Request struct {
    Service string
    Method  string // upper-cased HTTP method; "" for non-HTTP tools (exec)
    Path    string // cleaned request path; "" when not applicable
    Host    string // destination host (from the service Target / request)
    Tool    string // e.g. "straylight_api_call", "straylight_exec"
}

// Decision is the outcome of an evaluation. Reason is safe to log/audit/surface
// and never contains credential material.
type Decision struct {
    Allowed bool
    Reason  string
}

// Policy is the per-service rule set. A nil/zero Policy allows everything
// (backward compatibility). Within a configured dimension, only listed values
// are permitted (default-deny per dimension).
type Policy struct {
    // AllowedMethods, when non-empty, restricts to these HTTP methods
    // (case-insensitive). Empty = all methods allowed.
    AllowedMethods []string
    // AllowedPathPrefixes, when non-empty, requires the cleaned request path to
    // start with one of these prefixes. Empty = all paths allowed.
    AllowedPathPrefixes []string
    // AllowedHosts, when non-empty, restricts to these destination hosts
    // (exact or "*.suffix"). Empty = the service's own Target host only is
    // implied by the proxy; this dimension is for multi-host services.
    AllowedHosts []string
}

// Engine evaluates Requests against Policies.
type Engine interface {
    Evaluate(req Request, pol Policy) Decision
}

// New returns the default Engine.
func New() Engine
```

`Evaluate` logic (pure, order = cheapest first):
1. If `pol` is zero → `Allowed: true` (compat).
2. Method: if `AllowedMethods` non-empty and `req.Method` not in it →
   `Denied, "method X not permitted for service Y"`.
3. Host: if `AllowedHosts` non-empty and `req.Host` matches none (exact or
   `*.suffix`) → `Denied, "host H not permitted for service Y"`.
4. Path: if `AllowedPathPrefixes` non-empty and cleaned `req.Path` has none as a
   prefix → `Denied, "path P not permitted for service Y"`.
5. Else `Allowed: true`.

Path is cleaned (`path.Clean` after a single percent-decode) before step 4 to
defeat `/v1/../admin` style escapes.

### Enforcement seam 1 — `dispatchToolCall` (uniform per-tool gate)

**File**: `internal/mcp/tools.go`, function `dispatchToolCall` — the seam the task
identifies. Before the `switch req.Tool`:

- Resolve the service name from `req.Arguments` (`stringArg(args, "service")`) and
  load its `policy.Policy` via a new consumer-declared interface on the handler
  (`PolicyResolver { PolicyFor(service string) policy.Policy }`, satisfied by the
  registry).
- Build a `policy.Request` from the arguments (method/path for `api_call`; tool
  name + service for `exec`/`db_query`, where method/path are empty in v1).
- `engine.Evaluate(...)`; on deny, **return `errorResult("Error: blocked by
  policy: " + decision.Reason)` immediately** (before any handler runs, hence
  before any credential injection) and emit an audit deny event.

`dispatchToolCall`'s signature gains `eng policy.Engine, pr PolicyResolver` (or,
to avoid a long parameter list, these are fields on `Handler` and
`dispatchToolCall` becomes a method — preferred, matching how `h.proxy` etc. are
already handler fields). The `Handler` gets `SetPolicy(eng, resolver)` alongside
the existing `SetCommandExecutor` etc.

### Enforcement seam 2 — `HandleAPICall` (authoritative pre-injection re-check)

**File**: `internal/proxy/proxy.go`, function `HandleAPICall`, **immediately after**
`svc, err := p.resolver.Get(req.Service)` and **before** either
`buildUpstreamRequestWithAuth` or `buildUpstreamRequest` (both of which end in
credential injection):

```go
pol := p.policyFor(svc)            // from svc.Policy, resolved like Egress
decision := p.policy.Evaluate(policy.Request{
    Service: req.Service,
    Method:  strings.ToUpper(req.Method),
    Path:    req.Path,
    Host:    hostOf(svc.Target),
    Tool:    "straylight_api_call",
}, pol)
if !decision.Allowed {
    if p.auditLog != nil { /* emit policy_denied */ }
    return nil, fmt.Errorf("blocked by policy: %s", decision.Reason)
}
```

The proxy gains a `policy policy.Engine` field (constructor-injected, defaulting
to `policy.New()`), mirroring how the egress `guard` is added in ADR-010. This
guarantees the gate holds even when the proxy is exercised directly in tests or
future callers, and that it sits exactly at the credential boundary.

### Service & config schema additions

`internal/services/registry.go` — add to `Service`:

```go
// Policy gates tool calls on HTTP method, path-prefix, and destination host.
// When nil, all requests are permitted (backward compatibility); within a
// configured dimension, only listed values are allowed (default-deny).
Policy *ToolPolicy `json:"policy,omitempty" yaml:"policy,omitempty"`
```

```go
// ToolPolicy is the persisted, declarative form of policy.Policy.
type ToolPolicy struct {
    AllowedMethods      []string `json:"allowed_methods,omitempty"       yaml:"allowed_methods,omitempty"`
    AllowedPathPrefixes []string `json:"allowed_path_prefixes,omitempty" yaml:"allowed_path_prefixes,omitempty"`
    AllowedHosts        []string `json:"allowed_hosts,omitempty"         yaml:"allowed_hosts,omitempty"`
}
```

`internal/config/config.go` — add to `ServiceConfig`:

```go
Policy *ToolPolicyConfig `yaml:"policy"`
```
```go
type ToolPolicyConfig struct {
    AllowedMethods      []string `yaml:"allowed_methods"`
    AllowedPathPrefixes []string `yaml:"allowed_path_prefixes"`
    AllowedHosts        []string `yaml:"allowed_hosts"`
}
```

Validation (`validateService`): each method must be a known HTTP verb; each path
prefix must start with `/`; each host must be a valid hostname or `*.suffix`.
Persisted/restored via the existing `saveMetadata` / `LoadFromVault` JSON-string
field convention (same as `default_headers` and ADR-010's `egress`). A
`PolicyFor(service)` method on `Registry` maps `Service.Policy` → `policy.Policy`
(zero value when nil).

Example `config.yaml`:
```yaml
services:
  stripe:
    type: http_proxy
    target: https://api.stripe.com
    policy:
      allowed_methods: [GET, POST]
      allowed_path_prefixes: ["/v1/charges", "/v1/customers"]
```

### Wiring in `serve()`

**File**: `cmd/straylight/main.go`, in the component-graph section (≈ line
153–155), construct one engine and inject it into both the proxy and the MCP
handler:

```go
eng := policy.New()
p   := proxy.NewProxyWithGuard(registry, san, guard, eng) // proxy re-check seam
mcpHandler := mcp.NewHandler(p, registry)
mcpHandler.SetPolicy(eng, registry)                       // dispatch gate seam
```

(`registry` satisfies `PolicyResolver` via the new `PolicyFor` method; no extra
type is wired.)

### Audit

Add `audit.EventPolicyDenied EventType = "policy_denied"` (next to the existing
constants in `internal/audit/audit.go`). Emitted at both seams on deny with
`Service`, `Tool`, and `Details{"method", "path", "host", "reason"}` — never the
credential. Reuses the existing `emitToolCallAuditEvent` redaction discipline.

## Test Plan

`internal/policy/engine_test.go` (pure):
- Zero policy → allow (compat).
- Method gate: `AllowedMethods:[GET]` allows GET, denies POST/DELETE
  (case-insensitive: `get` allowed).
- Path-prefix gate: `AllowedPathPrefixes:["/v1/charges"]` allows
  `/v1/charges/ch_1`, denies `/v1/refunds`; `/v1/../admin` is cleaned and denied.
- Host gate: exact and `*.suffix` matching; non-match denied.
- Combined: a request must pass *all configured* dimensions; failing any one
  denies with the corresponding reason.

`internal/mcp/dispatch_policy_test.go`:
- `straylight_api_call` with a denied method/path → `isError` result with
  "blocked by policy", and the proxy stub's `HandleAPICall` is **never called**
  (asserts no credential path reached).
- Allowed call → dispatched normally.
- `straylight_exec` with a service policy → evaluated (v1 gates by tool+service;
  assert deny when a hypothetical exec-policy denies the tool).
- `policy_denied` audit event emitted with method/path/host/reason and no creds.

`internal/proxy/proxy_policy_test.go`:
- Direct `HandleAPICall` with a denied method → error before injection; assert the
  injector is never invoked (no `Authorization` header ever set; use a recording
  resolver to prove `ReadCredentials`/`GetCredential` is not reached on deny).
- Allowed method/path → request proceeds and credential is injected as today.
- Backward compat: services with `Policy == nil` behave exactly as the existing
  proxy tests.

## Validation Criteria

- Every credential-bearing tool (`api_call`, `exec`, `db_query`) flows through the
  `dispatchToolCall` gate; a test asserts none bypasses it.
- A denied `api_call` reaches **neither** the injector **nor** the upstream client
  (proven by recording resolver + nil upstream).
- No existing test regresses with `Policy == nil`.
- Reconsider when: per-identity or per-time rules are needed, or path matching
  needs glob/regex (→ promote to a v2 ADR, possibly Option 3 / external engine).

## Residual Risk

The policy engine bounds *which* method/path/host a service may be driven to; it
does **not** make a confused-deputy agent benign. Within the allowed surface, a
prompt-injected agent can still issue legitimate-looking calls (a permitted `POST
/v1/charges` is still a charge). And, as in ADR-010, an allowlisted host can be an
exfiltration channel **through** an approved destination (CamoLeak). Per §2, no
proxy-side control stops a prompt-injected agent from *attempting* to use its
authorized tools — this engine makes that misuse **scoped, bounded, and
auditable**, and is the minimal Wave-0 control that touches threat class (b). It
is strictly complementary to ADR-010 (network) and to short-lived least-privilege
credentials and human-approval tiers (later waves).
