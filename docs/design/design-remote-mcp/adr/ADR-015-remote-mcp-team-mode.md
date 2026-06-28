# ADR-015: Remote MCP / Team Mode — Streamable HTTP Transport + OAuth 2.1 Resource Server

**Date**: 2026-06-28
**Status**: Proposed
**Issue**: #12 (Wave 3 — multi-client & team / remote MCP — final roadmap item)
**Branch**: feat/12-remote-mcp
**Builds on**: ADR-003 (stdio transport + `/api/v1/mcp/*` internal API), ADR-010
(egress `Guard`/SSRF), ADR-011 (per-service policy engine), ADR-012 (OpenBao as
Straylight's OIDC *issuer* — the role this ADR must reconcile against)
**Relates to**: PRODUCT-STRATEGY.md §2 (exfiltration-vs-misuse), §3.2 (no-passthrough),
§3.4 (isolation controls), §5 Wave 3, §8 Q3 (remote-mode timing)

---

## Context

Straylight today reaches every AI client through **one stdio path** (ADR-003): a
thin host binary (`straylight-mcp`) speaks JSON-RPC over stdin/stdout to the client
and forwards each tool call to the container's internal HTTP API at
`POST /api/v1/mcp/tool-call` (`internal/mcp/handler.go`). That path is single-user,
single-host, and carries **no client identity** — it is implicitly trusted because
it is a localhost child process of one developer's editor.

Wave 3 (PRODUCT-STRATEGY.md §5, §8 Q3) unlocks what stdio structurally cannot:
**multiple AI clients over the network, each carrying a per-user identity.** The
target clients — Claude Code (remote), the Claude API connector, Cursor, VS Code —
all support the MCP **Streamable HTTP** transport and the MCP **authorization**
profile. Connecting them safely is not "expose the existing API over the LAN"; the
MCP authorization spec (stable 2025-06-18, verified against the mcp-protocol-auth
findings and PRODUCT-STRATEGY.md §6) imposes a precise contract:

- The MCP server is an **OAuth 2.1 Resource Server (RS)**. It does **not** issue the
  client's tokens; it **validates** access tokens minted by a trusted external
  Authorization Server (AS) — the user's IdP (Okta / Entra / Google / Auth0).
- It publishes **RFC 9728 Protected Resource Metadata** at
  `/.well-known/oauth-protected-resource`, naming the trusted AS(es).
- It validates token **audience** (RFC 8707 `resource` indicator / RFC 9068 `aud`),
  **issuer**, **expiry**, and **signature** (via the AS JWKS). On a missing/invalid
  token it returns **401 with `WWW-Authenticate`** pointing at the PRM (discovery).
- Transport rules: a **single MCP endpoint** (POST, optional SSE upgrade),
  **`MCP-Protocol-Version`** negotiation, **`MCP-Session-Id`**, **mandatory Origin
  validation** + localhost-bind / DNS-rebinding defense.
- **Token-passthrough is FORBIDDEN.** The inbound client token is never forwarded
  downstream; downstream credentials are still injected server-side from the vault.
  Per-user identity (from the validated token) *scopes* which services/policies
  apply — it is an authorization input, never a relayed bearer.
- **Confused-deputy mitigation**: per-client/per-user consent before any provider
  OAuth; exact `redirect_uri` matching; hardened state/cookies.

### The role-reconciliation problem (THE conceptual crux)

Straylight now plays **two different OAuth/OIDC roles** that must not be conflated:

| | Straylight as OIDC **Issuer** (ADR-012) | Straylight as Resource **Server** (this ADR) |
|---|---|---|
| Spec role | OpenID Provider (asserts *Straylight's own workload* identity) | OAuth 2.1 Resource Server (consumes *the user's* identity) |
| Endpoint | `/.well-known/openid-configuration`, `/.well-known/jwks.json` (`internal/oidc`, `routes_oidc.go`) | `/.well-known/oauth-protected-resource` (PRM) |
| Token direction | **Mints** identity tokens, presents them *to clouds* (AWS/GCP/Azure STS) | **Validates** access tokens *from AI clients* |
| Audience | the cloud STS (`sts.amazonaws.com`, WIF pool, FIC) | Straylight's own MCP resource URI |
| Signing keys | Straylight's private keys (OpenBao identity engine) | the **external IdP's** public keys (fetched from *their* JWKS) |
| Trust | clouds trust Straylight's issuer | Straylight trusts the user's IdP |

These are **opposite directions of the same federation graph** and they coexist
cleanly because they touch disjoint endpoints, disjoint key material, and disjoint
audiences. ADR-012's issuer answers *"who is this Straylight container, to a cloud?"*.
This ADR's RS answers *"who is this human, to Straylight?"*. The only shared
infrastructure is the HTTP mux and the egress `Guard` (used here to SSRF-gate the
JWKS fetch). **No code, key, or audience is reused between the two roles** — and the
PRM MUST NOT advertise Straylight's own issuer as the AS, because Straylight does
not (in Phase 1) issue client access tokens; it delegates that to the user's IdP.

### Why this is genuinely hard, and what must NOT regress

- The stdio path (ADR-003) and the existing `/api/v1/mcp/*` internal API are
  **load-bearing** for every shipped install. They are localhost, unauthenticated,
  single-user *by design*. Remote MCP must be a **new, separately-bound, opt-in
  surface** that adds authentication — never a change to the trusted localhost path.
- PRODUCT-STRATEGY.md §2 is the governing honesty discipline: hiding the secret
  solves exfiltration, not misuse. Per-user identity here is what finally lets the
  Wave-0 controls (ADR-011 policy, ADR-010 egress) be **scoped per user** — a real
  misuse-bounding gain, not just a connectivity feature.
- The blast-radius caution (PRODUCT-STRATEGY.md §4, TeamPCP): a network-exposed
  broker holding the vault is the crown-jewel target. Remote mode must be the
  *most* hardened surface in the product, and must remain off by default.

### Constraints

- **Design only.** No Go is written here; this ADR specifies endpoints, headers,
  interfaces, schema, placement, phasing, and tests. **No Go file is touched.**
- **Backward compatibility is non-negotiable.** The stdio shim, ADR-003's host
  binary, and the existing `/api/v1/mcp/tool-list` + `/api/v1/mcp/tool-call`
  endpoints MUST keep working byte-for-byte. Remote MCP is **additive**: a new
  endpoint, a new optional listener, new nil-gated `Config` fields.
- **Reuse, don't duplicate, tool dispatch.** The Streamable-HTTP endpoint MUST route
  into the *same* `mcp.dispatchToolCall` / `toolDefinitions` (`internal/mcp`) the
  internal API uses. The new surface is a **protocol adapter + auth gate**, not a
  second tool implementation. (Pattern-transfer: the existing internal API is
  already an *adapter* over `dispatchToolCall`; the remote endpoint is a second
  adapter — JSON-RPC-over-Streamable-HTTP — over the same core.)
- **Match repo idioms.** Nil-gated `server.Config` DI (every subsystem is an
  interface or pointer that defaults to a 501/no-op when unset); the
  `applyMiddlewareChain` composition; consumer-declared interfaces; validate-at-
  startup; per-service config; audited at the boundary (`audit.Event` already has a
  `SessionID` field — use it for per-user attribution).
- **No-passthrough by construction**, mirroring ADR-012: the validated client token
  is an *authorization input* to identity/scoping; there is **no code path** that
  attaches it to a downstream request. Downstream creds come only from the vault via
  the existing `Injector`/`proxy` path.
- **SSRF discipline.** The only new outbound fetch is the AS **JWKS**; it MUST route
  through the existing egress `Guard.CheckHost` before dial (same rule ADR-014 used
  for spec/discovery fetches).
- **Localhost-by-default, opt-in remote.** Remote mode binds a *separate* address
  and is disabled unless explicitly configured. The existing dashboard/internal
  surface stays localhost-only.

---

## Decision Drivers

- **Security (primary)**: spec-compliant RS token validation; mandatory Origin /
  DNS-rebinding defense; no-passthrough by construction; consent for confused-deputy;
  the most-hardened surface in the product.
- **Backward compatibility**: stdio + internal API frozen; remote is purely additive
  and off by default.
- **Coverage of the four clients** with one endpoint (Claude Code, Claude connector,
  Cursor, VS Code) — the §5 Wave-3 multi-client unlock.
- **Single-evaluator reuse**: one tool core (`dispatchToolCall`), two transport
  adapters; the new surface adds auth + protocol framing only.
- **Incrementalism**: a minimal Phase 1 that delivers a *working authenticated remote
  MCP endpoint* and is independently TDD-able, with the heavy bits explicitly
  deferred.
- **Honesty (PRODUCT-STRATEGY.md §2)**: per-user identity is sold as misuse-bounding
  (scoped policy/egress + per-user audit), never as prompt-injection immunity.

---

## Scope

**IN (this ADR; shippable Wave-3 *core*):**
1. **Streamable HTTP MCP transport** — a single new endpoint
   (`POST /mcp`, optional SSE), `MCP-Protocol-Version` negotiation, `MCP-Session-Id`
   lifecycle, mandatory `Origin` validation + DNS-rebinding defense, on a **separate
   opt-in listener**, routing into the existing `dispatchToolCall`.
2. **OAuth 2.1 Resource Server** — `/.well-known/oauth-protected-resource` (RFC 9728
   PRM); inbound access-token validation (issuer, audience per RFC 8707/9068, expiry,
   signature via the external AS JWKS); `401 + WWW-Authenticate` discovery path.
3. **No-passthrough + per-user scoping model** — validated identity → an
   `Identity` value carried on the request context → fed into the *existing* policy
   engine (ADR-011) and audit `SessionID`; the token is never relayed downstream.
4. **Confused-deputy consent (Phase-1 minimal)** — per-client/per-user consent record
   gating any *provider* OAuth initiated on a remote user's behalf; exact
   `redirect_uri` allowlist matching; hardened `state` + cookies for the existing
   `internal/oauth` callback.

**DEFERRED (Wave-3.5; contracts sketched in Part F, NOT implemented here):**
- **URL-mode elicitation** flows (MCP 2025-11-25) for out-of-band credential
  onboarding.
- The **full human-approval-tier UI** (approval tiers exist as a policy concept;
  the remote approval UX is deferred).
- **Multi-tenant per-user credential partitioning** beyond v1 (separate vault
  namespaces / per-user service ownership). Phase 1 ships **per-user
  authorization/scoping over a shared service catalog**, not per-user credential
  stores.
- **Straylight-as-AS** (issuing its own client tokens / Dynamic Client Registration
  RFC 7591 / acting as its own gateway IdP) — Phase 1 delegates identity entirely to
  the user's external IdP.

---

## Options Considered

### Decision A — How does the remote MCP endpoint relate to the existing `/api/v1/mcp/*` internal API and the stdio shim?

#### Option A1: New Streamable-HTTP adapter on a separate listener, sharing `dispatchToolCall` (CHOSEN)

A new `internal/mcphttp` package (or `internal/mcp/streamable.go`) implements the
JSON-RPC-2.0-over-Streamable-HTTP protocol handler. It does protocol framing
(`initialize`/`tools/list`/`tools/call`, SSE, session, version), enforces the RS
auth gate, then calls the **same** `mcp.dispatchToolCall` the internal API calls.
It is mounted on a **separate, opt-in listener** (e.g. `RemoteListenAddress`), with
its **own** middleware chain (Origin-validating, no browser-CORS), leaving the
localhost mux untouched.

**Pros**: zero duplication of tool logic (the §"reuse don't duplicate" constraint);
the trusted localhost path is physically separate from the authenticated network
path, so a remote-mode bug cannot weaken stdio; the auth/Origin requirements differ
fundamentally from the dashboard's CORS model, so a separate chain is *cleaner* than
overloading `applyMiddlewareChain`; matches the nil-gated DI idiom (off when
`RemoteListenAddress`/`MCPResourceServer` unset). Pattern: the internal API and the
remote endpoint become *two adapters over one core* — the same shape ADR-012 used
(`cloud.Provider` static-vs-keyless branch over one engine).
**Cons**: a second listener + a second middleware chain to maintain. Acceptable: the
chains differ enough (Origin vs CORS, RS auth vs none) that sharing would be more
fragile than duplicating the small composition.

#### Option A2: Add a Streamable-HTTP handler to the existing mux behind the existing chain

Mount `POST /mcp` on `s.mux` next to `/api/v1/mcp/*`, reuse `applyMiddlewareChain`.

**Pros**: one listener, one chain, smallest wiring diff.
**Cons**: conflates the **trusted-localhost** surface with the **authenticated-
network** surface on one bind address and one CORS-shaped chain. To serve remote
clients the bind must leave localhost — which would *also* expose the unauthenticated
dashboard/internal API to the network unless every existing route grows an auth gate.
That is exactly the regression the backward-compat constraint forbids. Rejected: it
couples the security posture of two surfaces that must stay independent.

#### Option A3: Replace the stdio shim with a local Streamable-HTTP client

Drop stdio; have all clients (even local) speak Streamable HTTP to a localhost MCP
endpoint.

**Pros**: one transport everywhere.
**Cons**: breaks ADR-003's shipped stdio path (every existing install), loses the
lowest-latency local path, and forces auth machinery onto the single-user local case
that doesn't need it. Violates backward-compat hard. Rejected.

**Decision: A1.** A new Streamable-HTTP adapter on a separate, opt-in listener with
its own Origin-validating + RS-auth chain, sharing the existing `dispatchToolCall`
core. stdio and `/api/v1/mcp/*` are untouched.

### Decision B — Is Straylight the Authorization Server, or only a Resource Server, in Phase 1?

#### Option B1: Resource Server only; delegate identity to the user's external IdP (CHOSEN for Phase 1)

PRM names the customer's IdP (Okta/Entra/Google/Auth0) as the trusted AS. Straylight
validates tokens that IdP issued; it issues nothing client-facing.

**Pros**: smallest correct surface; no token-issuance, no DCR (RFC 7591), no consent-
to-Straylight-as-IdP, no client-secret storage; reuses the enterprise's existing SSO
(the §3.2 "validate the OIDC path on Okta/Auth0" target); the RS role is the *only*
role the MCP spec strictly mandates of an MCP server. Cleanly disjoint from ADR-012's
issuer role (the table above). Spec-compliant token validation is a self-contained,
highly-testable unit (issuer/aud/exp/sig).
**Cons**: requires the operator to register an OAuth client (or rely on the client's
DCR) at *their* IdP and configure the resource indicator — a one-time setup step,
documented. Clients that only support DCR against the RS itself (not all do) need the
Wave-3.5 AS/DCR work.
**Decision rationale**: the MCP spec separates AS and RS precisely so a resource
server need not be an AS. Phase 1 takes the RS-only path; Straylight-as-AS is an
explicit Wave-3.5 deferral (Part F).

#### Option B2: Straylight as its own Authorization Server (embedded AS + DCR)

Straylight issues client access tokens, supports Dynamic Client Registration, runs
its own consent screen, brokers the user's upstream IdP login.

**Pros**: clients that only do DCR-against-the-server work out of the box; one-stop
setup; full control of token claims/audience.
**Cons**: a large surface (token endpoint, PKCE verifier store, DCR, client
registry, consent UI, refresh/rotation) with serious security obligations; risks
**conflating** with ADR-012's issuer (two issuers in one container, easy to
mis-wire); much more than a "smallest shippable Phase 1" needs. Rejected for Phase 1;
sketched as Wave-3.5 (Part F.4) behind the same RS validation seam.

**Decision: B1** for Phase 1 (RS-only, external IdP). The token-validation interface
is shaped so a future embedded AS (B2) plugs in as just another trusted issuer
without changing call sites.

### Decision C — Where does per-user identity attach, and how does it scope behavior?

#### Option C1: Validated identity → request-context `Identity` → existing policy engine + audit (CHOSEN)

The RS middleware validates the token, builds an `Identity{Subject, Issuer, Email,
Scopes, SessionID}`, stores it on the request context, and (for remote calls)
`dispatchToolCall` reads it to (a) stamp `audit.Event.SessionID`/actor and (b)
enrich the `policy.Request` so per-user/per-scope rules (an additive ADR-011
dimension) can deny. The token itself stops at the gate.

**Pros**: reuses ADR-011's evaluator (one policy engine, now per-user aware) and the
audit `SessionID` field that already exists; no-passthrough holds because identity is
a *value*, not a relayed token; minimal new surface. The §3.4 misuse-bounding story
becomes real: policy + egress now scope *per human*.
**Cons**: requires a small additive field on `policy.Request` (e.g. `Subject`,
`Scopes`) and a context key. Both are additive and nil-safe (local stdio path passes
no identity → today's behavior).

#### Option C2: Per-user credential partitioning (separate vault paths per user)

Each remote user gets their own service/credential namespace.

**Pros**: strongest isolation; a user can only use credentials they own.
**Cons**: a major data-model and vault-layout change (per-user ownership, migration,
sharing semantics) — far beyond a shippable Phase 1, and orthogonal to "connect
clients with identity." Deferred (Part F.3).

**Decision: C1** for Phase 1 (identity scopes a *shared* catalog via policy + audit);
C2 (per-user credential stores) is Wave-3.5.

---

## Decision (summary)

1. **New Streamable-HTTP MCP adapter** (`internal/mcphttp`) on a **separate, opt-in
   listener** with its own Origin-validating chain, routing into the existing
   `mcp.dispatchToolCall`. stdio (ADR-003) and `/api/v1/mcp/*` are **unchanged**.
2. **Straylight is an OAuth 2.1 Resource Server (B1)**: publishes RFC 9728 PRM naming
   the user's external IdP as the AS; validates inbound access tokens
   (issuer/audience/expiry/signature via the AS JWKS, SSRF-gated); `401 +
   WWW-Authenticate` for discovery. This is **distinct from** ADR-012's OIDC *issuer*
   role; the two are reconciled by disjoint endpoints, keys, audiences, and direction.
3. **No-passthrough by construction**: the validated token becomes an in-process
   `Identity` value (C1) feeding the existing policy engine + audit; **no code path
   relays it downstream**. Downstream creds are still vault-injected server-side.
4. **Confused-deputy consent (minimal)**: a per-client/per-user consent record gates
   provider OAuth initiated for a remote user; exact `redirect_uri` allowlist; hardened
   `state` + cookies on the `internal/oauth` callback.
5. **Explicit deferrals (Part F)**: URL-mode elicitation, the approval-tier UI,
   per-user credential partitioning, and Straylight-as-AS/DCR — contracts sketched,
   not built.
6. **Phasing (Part E)** makes Phase 1 = "transport + RS validation + identity→audit"
   a self-contained, independently-TDD-able, mergeable increment.

---

## Part A — Streamable HTTP MCP transport

### A.1 The endpoint and the protocol surface

A single MCP endpoint on the remote listener (the spec's "one endpoint" model):

```
POST /mcp        # JSON-RPC 2.0 request(s); response is application/json
                 #   OR, when the client sends Accept: text/event-stream and the
                 #   server has streamed/long-running output, an SSE stream.
GET  /mcp        # optional: open a standalone SSE stream for server->client msgs
                 #   (notifications). Phase 1 MAY return 405 if no server-initiated
                 #   messages are needed; tool calls are request/response.
DELETE /mcp      # optional: explicit session termination (clears MCP-Session-Id).
```

Method mapping into the existing core (no new tool logic):

| MCP JSON-RPC method | Maps to |
|---------------------|---------|
| `initialize` | version/capabilities handshake; assigns `MCP-Session-Id` |
| `tools/list` | `mcp.toolDefinitions` (the same slice the internal API serves) |
| `tools/call` | builds a `mcp.ToolCallRequest` → `mcp.dispatchToolCall(ctx, …)` |
| `ping` | liveness |

`dispatchToolCall` already takes the full dependency set (proxy, services, scanner,
fileReader, dbExecutor, cmdExecutor, audit, policy engine, resolver). The remote
adapter is constructed with the **same dependencies** the internal `mcp.Handler` is
wired with in `serve()` — it is a sibling caller, not a fork.

### A.2 `MCP-Protocol-Version` negotiation

- `initialize` carries the client's requested protocol version. The server replies
  with the highest version it supports that is `<=` the client's (or its own latest
  if the client omits it, per the spec's default-to-latest-known rule).
- Every subsequent request MUST carry the `MCP-Protocol-Version` header matching the
  negotiated version; a mismatch or unsupported version → `400` with a JSON-RPC error
  naming supported versions.
- Pin the **stable 2025-06-18** profile as the baseline (PRODUCT-STRATEGY.md §6: the
  RFC stack is version-mixed; implement to the stable spec, advertise the versions
  actually supported). Newer (2025-11-25) elicitation features are gated out of
  Phase 1 (Part F.1).

### A.3 `MCP-Session-Id` lifecycle

- On `initialize`, the server MAY assign a cryptographically-random
  `MCP-Session-Id` (≥128 bits, `crypto/rand` — mirror `generateRequestID` but longer)
  and return it as a response header.
- Clients echo it on subsequent requests. The server keeps a **bounded, TTL'd**
  session table (in-memory `map[sessionID]sessionState` under an `sync.RWMutex`,
  with idle-expiry — the same shape as the lease cache). Session state holds the
  negotiated version and the bound `Identity` (so re-validation per request is cheap
  but the identity is re-checked for token expiry every call).
- `DELETE /mcp` (or idle expiry) drops the session. A request bearing an unknown/
  expired `MCP-Session-Id` → `404` (per spec, prompting re-`initialize`).
- **Sessions are not an auth substitute**: the access token is validated on **every**
  request regardless of session (a session never extends a token's lifetime). The
  session binds protocol state, not authority.

### A.4 Origin validation + DNS-rebinding / localhost-bind defense (MANDATORY)

This is the spec's hard transport-security requirement and the highest-risk control:

1. **Mandatory `Origin` validation.** The remote chain validates the `Origin` header
   against a configured allowlist (`MCPAllowedOrigins`) on **every** request. Unlike
   the dashboard CORS middleware (which merely withholds the ACAO header for unknown
   origins), the remote chain **rejects** a request with a disallowed/missing Origin
   with `403` *before* any handler runs. This is anti-DNS-rebinding, not browser CORS.
2. **Bind discipline.** Default bind is **loopback** (`127.0.0.1:<port>`); binding a
   non-loopback address is an explicit operator choice (`MCPRemoteBind`) and SHOULD
   be fronted by TLS (operator-provided reverse proxy or a configured cert). The
   product never auto-binds `0.0.0.0`.
3. **`Host` header check.** Reject requests whose `Host` is not in an allowlist of
   expected hostnames (defense-in-depth against rebinding that forges Origin-less
   requests).
4. **No wildcard origins.** `MCPAllowedOrigins` rejects `*`; each origin is exact.

### A.5 The remote middleware chain (distinct from `applyMiddlewareChain`)

A dedicated composition for the remote listener, in order:

```
RequestLogging
  -> SecurityHeaders            (reuse; HSTS auto-set under TLS)
  -> OriginValidate (REJECT)    (new; mandatory allowlist, 403 on fail)
  -> RateLimiter                (reuse; remote gets its own, tighter limit)
  -> MaxBodySize                (reuse)
  -> ResourceServerAuth (401)   (new; token validation + Identity on context)
  -> mcphttp.Handler            (protocol framing -> dispatchToolCall)
```

Note the **ordering rationale**: Origin/Host rejection precedes auth (cheap network-
layer defense first); auth precedes the handler (no unauthenticated reaches dispatch);
the PRM + `WWW-Authenticate` discovery endpoints are mounted *outside* the auth gate
(they must be reachable unauthenticated to bootstrap discovery — see Part B).

---

## Part B — OAuth 2.1 Resource Server

### B.1 Protected Resource Metadata (RFC 9728)

A new unauthenticated endpoint on the remote listener:

```
GET /.well-known/oauth-protected-resource
{
  "resource": "https://mcp.example.com",          // this RS's canonical resource URI
  "authorization_servers": [                        // the trusted AS(es) = user's IdP
    "https://example.okta.com/oauth2/default"
  ],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["straylight.mcp"],          // optional, advisory
  "resource_documentation": "https://.../docs"
}
```

- `resource` MUST equal the audience the RS validates tokens against (RFC 8707 /
  9068). Clients use it as the `resource` indicator when requesting a token from the
  AS, so the AS mints a token *audience-scoped to this RS* — the linchpin that makes
  audience validation meaningful.
- `authorization_servers` names the customer's IdP. **It MUST NOT name Straylight's
  own OIDC issuer** (ADR-012) — that issuer serves cloud federation, not client auth,
  and has no token endpoint for clients.
- This endpoint is **public** (like the existing OIDC discovery in `routes_oidc.go`),
  served with a cacheable `Cache-Control` (reuse the `oidcCacheControl` pattern).

### B.2 The `WWW-Authenticate` discovery handshake

A request to `/mcp` with no/invalid token gets:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="straylight",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
  error="invalid_token", error_description="..."
```

Per RFC 9728 §5.1, `resource_metadata` points the client at the PRM, which names the
AS; the client then runs its own OAuth 2.1 + PKCE (S256) flow against that AS, with
the `resource` indicator set to our `resource`, and retries with the bearer token.
Straylight initiates none of this client-side flow — it only advertises where to go.

### B.3 Token validation (the core RS unit)

A new `internal/mcpauth` package, with a single, highly-testable validator:

```go
// Package mcpauth implements OAuth 2.1 Resource Server token validation for the
// remote MCP endpoint. It validates access tokens minted by a trusted external
// Authorization Server (the user's IdP). It NEVER mints tokens and NEVER relays
// the validated token downstream (no-passthrough by construction).
package mcpauth

// Identity is the validated, no-secret representation of the calling user. It is
// the ONLY thing derived from the inbound token that crosses into the request
// path; the raw token is discarded after validation.
type Identity struct {
    Subject   string            // token `sub`
    Issuer    string            // token `iss` (a trusted AS)
    Audience  string            // token `aud` == our resource URI (verified)
    Email     string            // optional, for audit display
    Scopes    []string          // token `scope`/`scp`, for per-user policy
    ExpiresAt time.Time
    Claims    map[string]string // selected, non-sensitive claims for audit
}

// TokenValidator validates a raw bearer token and returns an Identity, or an
// error classified for the WWW-Authenticate response.
type TokenValidator interface {
    // Validate checks signature (AS JWKS), issuer (trusted set), audience
    // (== resource, RFC 8707/9068), expiry, and not-before. On success it
    // returns the Identity; the raw token is not retained.
    Validate(ctx context.Context, rawToken string) (*Identity, error)
}

// ValidatorConfig wires a JWT validator.
type ValidatorConfig struct {
    Resource          string            // our canonical resource URI (expected aud)
    TrustedIssuers    []string          // allowed `iss` values (the AS list)
    JWKSProvider      JWKSProvider       // fetches+caches AS signing keys (SSRF-gated)
    AllowedAlgs       []string           // e.g. ["RS256","ES256"]; never "none"/HS*
    ClockSkew         time.Duration      // small leeway for exp/nbf
}

// JWKSProvider fetches and caches the AS's public signing keys. The fetch MUST
// route through the egress Guard.CheckHost before dial (SSRF defense), mirroring
// ADR-014's discovery/import fetch discipline.
type JWKSProvider interface {
    KeyFor(ctx context.Context, issuer, kid string) (crypto.PublicKey, error)
}
```

**Validation rules (all MUST pass; fail-closed):**
1. **Signature** verified against the AS JWKS (by `kid`), algorithm in `AllowedAlgs`
   — explicitly reject `alg:none` and symmetric algs (no shared secret with the AS).
2. **Issuer** ∈ `TrustedIssuers`.
3. **Audience** contains our `resource` (RFC 8707/9068) — the anti-confused-deputy
   linchpin: a token minted for *another* RS is rejected here.
4. **Expiry/NBF** within `ClockSkew`.
5. On any failure → a classified error → `401 + WWW-Authenticate` (B.2). On success →
   `Identity` on the request context; **the raw token is dropped**.

- **JWKS cache** mirrors the OIDC-discovery cache discipline: fetch
  `<issuer>/.well-known/openid-configuration` → `jwks_uri` → keys; cache with a TTL;
  refetch on unknown `kid`; **every fetch through the egress `Guard`**.
- **Opaque-token / introspection** (RFC 7662) is out of Phase 1 (most IdPs issue JWT
  access tokens); the `TokenValidator` interface allows an introspection
  implementation later without changing call sites.

### B.4 Reconciliation with ADR-012's issuer (made concrete in wiring)

- `internal/oidc` + `routes_oidc.go` (`/.well-known/openid-configuration`,
  `/.well-known/jwks.json`) stay exactly as they are — **Straylight's issuer for
  cloud federation**, served on the existing (localhost) surface.
- The RS's PRM + JWKS *consumption* live in `internal/mcpauth` and the remote
  listener — a **different package, different endpoint, different keys**.
- A wiring invariant (test-enforced): the RS's `TrustedIssuers` MUST NOT contain
  Straylight's own issuer URL, and the PRM's `authorization_servers` MUST NOT be
  Straylight's issuer. The two roles are kept provably disjoint.

---

## Part C — No-passthrough + per-user scoping model

### C.1 No-passthrough, by construction (mirrors ADR-012)

- The only consumer of the raw token is `TokenValidator.Validate`, which returns an
  `Identity` and **discards** the token. There is **no field, no context value, and
  no function** that carries the raw token past the auth middleware.
- The downstream request path (`proxy` + `Injector`) is **unchanged**: it injects
  credentials from the vault for the named service, exactly as for a stdio call. It
  has no parameter through which an inbound token could be passed, so passthrough is
  structurally impossible (the same guarantee ADR-012 gives for minted tokens).
- A test asserts that for a remote `tools/call`, the outbound request carries only
  the vault-injected credential and **never** the inbound bearer.

### C.2 Per-user scoping (C1) — identity feeds the existing evaluators

- The RS middleware puts `*Identity` on the request context. The remote adapter
  passes it into a (Phase-1 additive) `policy.Request` field set:
  ```go
  // policy.Request additive fields (omitempty; zero = today's behavior):
  //   Subject string   // Identity.Subject (the human), "" for local stdio
  //   Scopes  []string // Identity.Scopes, nil for local stdio
  ```
  ADR-011's `Engine.Evaluate` gains optional per-user dimensions (e.g. a
  `Policy.AllowedSubjects` / `RequiredScopes`), defaulting to allow-all when unset —
  so existing services and the local path are unaffected. This is the §3.4 win:
  policy + egress now **scope per human**, not just per service.
- **Audit**: `dispatchToolCall` (remote path) stamps `audit.Event.SessionID` with the
  session/subject and adds `Details["actor"]=Identity.Subject` /
  `Details["issuer"]=Identity.Issuer` (no token, no secret) — the `SessionID` field
  already exists on `audit.Event`. Per-user audit is the accountability half of the
  misuse-bounding story.
- **Nil-safety**: the local stdio path passes no `Identity`; `policy.Request.Subject`
  is `""`, every new policy dimension is unset → byte-identical local behavior.

### C.3 What Phase 1 does NOT claim (honesty, §2)

Per-user identity bounds and attributes misuse; it does **not** make a prompt-injected
remote agent safe. A compromised session can still call its *authorized* tools within
its *scoped* policy. The honest claim: remote mode adds **per-user authentication,
per-user policy scoping, and per-user audit** — it shrinks and attributes the blast
radius; it does not remove it (PRODUCT-STRATEGY.md §2).

---

## Part D — Confused-deputy consent (Phase-1 minimal)

The confused-deputy risk (CSA; MCP spec security best practices; PRODUCT-STRATEGY.md
§5 Wave-3) is that the broker, holding upstream authority, is tricked into running a
provider OAuth flow that binds a *different* user's/client's grant. Phase-1 mitigations:

### D.1 Per-client / per-user consent before provider OAuth

- Before the broker initiates *any* provider OAuth (`internal/oauth` StartOAuth) **on
  behalf of a remote-authenticated user**, it requires an explicit, recorded consent
  for the `(Identity.Subject, client_id, provider)` tuple. Absent a consent record,
  the start endpoint returns a consent-required response (and, in Phase 1, the consent
  is granted via the dashboard, not auto-granted by the AI).
- Consent records are keyed by subject + client + provider, stored server-side (a
  small KV under OpenBao or the existing config store), and are revocable.
- **Scope of D.1 in Phase 1**: the *core* remote MCP endpoint (tool calls against
  already-configured services) does **not** trigger provider OAuth — credentials are
  pre-provisioned. D.1 matters when a remote user drives credential *onboarding*,
  which in Phase 1 is **dashboard-only** (URL-mode elicitation that would let the AI
  drive it is deferred, Part F.1). So Phase 1's consent surface is small and the
  hardening (D.2/D.3) is the load-bearing part.

### D.2 Exact `redirect_uri` matching

- The OAuth callback (`/api/v1/oauth/callback`) and any remote-mode redirect MUST
  match a **pre-registered, exact** `redirect_uri` (no prefix/substring/wildcard
  matching). This is the primary confused-deputy + open-redirect defense. The
  allowlist is configuration, validated at startup.

### D.3 Hardened `state` + cookies

- `state` is a high-entropy, single-use, server-stored nonce bound to the initiating
  session/subject and the expected `redirect_uri`; verified and consumed on callback;
  expired after a short TTL.
- The OAuth flow cookie (if any) is `Secure` (under TLS), `HttpOnly`, `SameSite=Lax`/
  `Strict`, host-scoped, short-lived. The callback rejects a `state` whose bound
  subject/session does not match the presenter.

---

## Part E — Phased implementation plan

Each phase is independently TDD-able, independently mergeable, and additive (no phase
changes the stdio path or the existing `/api/v1/mcp/*`/dashboard behavior; each is
revertible by removing its listener/registration).

| Phase | Deliverable | New surface | Depends on | Risk | Runtime change |
|-------|-------------|-------------|------------|------|----------------|
| **1** | RS token validation + PRM + `WWW-Authenticate` | `internal/mcpauth` (`TokenValidator`, `JWKSProvider` SSRF-gated), `/.well-known/oauth-protected-resource`, `Config.MCPResourceServer` | egress `Guard` | Med (crypto correctness; SSRF) | none until enabled |
| **2** | Streamable-HTTP transport + separate listener + Origin/rebinding chain | `internal/mcphttp`, remote listener, `OriginValidate`, `MCP-Session-Id`/version, route into `dispatchToolCall` | Phase 1 (auth gate), `internal/mcp` core | Med–High (transport correctness; Origin defense) | new opt-in listener |
| **3** | Identity → policy + audit (per-user scoping) | additive `policy.Request.{Subject,Scopes}` + optional policy dims; context key; remote `dispatchToolCall` stamps `SessionID`/actor | Phases 1–2, ADR-011 | Low–Med (additive, nil-safe) | none for local |
| **4** | Confused-deputy consent + exact-redirect + state hardening | consent store, exact `redirect_uri` allowlist, hardened `state`/cookies on `internal/oauth` | Phase 3 (identity) | Med (touches live OAuth flow) | behavioral for remote-initiated OAuth only |

**Ordering rationale**: the RS validator (Phase 1) is pure and self-contained — build
and prove it first (it is the security crux and needs zero transport). The transport
(Phase 2) is useless without the auth gate, so it follows. Identity-scoping (Phase 3)
is additive enrichment of existing evaluators. Consent hardening (Phase 4) touches the
live OAuth flow last, behind a flag, once identity exists to bind consent to.

### Recommended shippable Phase-1 subset (smallest working authenticated remote MCP)

**The smallest increment that delivers a *working authenticated remote MCP endpoint*
is Phases 1 + 2 + the audit half of Phase 3** — i.e.:

- **Phase 1** (RS validation + PRM + `WWW-Authenticate`) — the security core.
- **Phase 2** (Streamable-HTTP endpoint on a separate Origin-validating listener,
  routing into `dispatchToolCall`) — the connectivity.
- **The audit slice of Phase 3** (stamp `audit.Event.SessionID`/actor from the
  validated `Identity`) — accountability, which is cheap (the field exists) and is
  required to honestly claim per-user attribution.

**Defer to a fast-follow within Wave 3**: the per-user *policy* dimensions
(`policy.Request.Subject`/`RequiredScopes`) and all of Phase 4 (consent), because:
- Phases 1+2+audit already deliver the headline: Claude Code / connector / Cursor /
  VS Code connect remotely, authenticate as a real user via their IdP, run tools with
  vault-injected creds and **no token passthrough**, and every action is attributed to
  that user in the audit log. That is independently demonstrable and mergeable.
- The per-user policy dimensions are an additive enrichment of ADR-011 best landed
  once at least two real per-user rules are needed (avoid premature abstraction).
- Phase 4 (consent) only bites when a *remote user drives credential onboarding*,
  which Phase 1 keeps dashboard-only (elicitation deferred) — so exact-`redirect_uri`
  + hardened `state` (D.2/D.3) are the parts worth pulling forward into Phase 4-early
  as a small hardening PR, while the consent-record machinery (D.1) can wait for the
  elicitation work it actually guards.

This subset is **off by default** (no remote listener unless `MCPResourceServer` +
`RemoteListenAddress` are configured), so it ships with zero risk to existing installs.

### Wiring (matches the nil-gated `server.Config` DI idiom)

Additive `server.Config` fields, all nil/zero = remote mode off (today's behavior):

```go
// server.Config additive fields (Wave 3; nil/zero => remote MCP disabled):
//   RemoteListenAddress string                 // e.g. "127.0.0.1:9471"; "" = off
//   MCPResourceServer   *mcpauth.ResourceServer  // PRM + validator; nil = off
//   MCPAllowedOrigins   []string               // exact origins; no "*"
//   MCPRemoteRateLimit  Options                 // tighter limits for the network surface
```

`serve()` constructs the remote listener only when these are set, wiring the remote
adapter with the **same** `proxy`/`services`/`policy`/`audit` dependencies the
internal `mcp.Handler` already receives. The existing `server.New`/`registerRoutes`/
`applyMiddlewareChain` and the dashboard listener are untouched.

---

## Part F — Explicit DEFER list (Wave-3.5) and contract sketch

Out of scope for this ADR's implementation, sketched so the seams exist and the
deferral is deliberate.

### F.1 URL-mode elicitation (MCP 2025-11-25)

Server-driven, out-of-band credential onboarding: the server returns an elicitation
that hands the user a URL to complete OAuth/key-entry in a browser, so the secret
never reaches the LLM (PRODUCT-STRATEGY.md §5 Wave-3). Sketch: a new JSON-RPC
elicitation response carrying a one-time URL into the existing dashboard onboarding
flow; the AI gets only a "complete setup at <url>" message. Deferred because it
requires the 2025-11-25 protocol surface, a one-time-URL store, and is the feature
that *creates* the D.1 consent obligation. The transport (Part A) is versioned so
adding it later is a capability bump, not a redesign.

### F.2 Full human-approval-tier UI

Approval tiers exist as a policy concept (PRODUCT-STRATEGY.md §3.4). The remote
approval UX — an out-of-band "approve this high-impact action" prompt with argument
preview, surfaced to the user via the dashboard or an elicitation — is deferred. The
policy engine already has the decision seam; the *UI/round-trip* is the deferred part.

### F.3 Multi-tenant per-user credential partitioning

Phase 1 ships per-user *authorization/scoping over a shared service catalog* (C1).
Per-user *credential ownership* (separate vault namespaces, sharing semantics,
migration) is a larger data-model effort (Decision C2). Sketch: a `tenant`/`owner`
dimension on `services.Service` + vault path prefixing + per-owner ACLs in the policy
engine. Deferred to Wave-3.5; the `Identity.Subject` is the natural partition key when
it lands.

### F.4 Straylight-as-Authorization-Server + Dynamic Client Registration (RFC 7591)

For clients that only do DCR-against-the-server, an embedded AS (token endpoint, PKCE
verifier store, client registry, consent screen, Straylight-brokered upstream IdP
login). Sketch: it plugs in behind the same `TokenValidator` seam (the AS becomes just
another trusted issuer — its own), with strict separation from ADR-012's *workload*
issuer (a third, client-facing issuer, distinct keys/audience). Deferred: it is a
large security surface and Phase-1's RS-only model serves the four target clients via
their existing IdPs. (PRODUCT-STRATEGY.md §6: DCR is still "SHOULD," not required.)

---

## Consequences

**Positive**
- Unlocks the four target AI clients over the network with **per-user IdP identity** —
  the §5 Wave-3 multi-client capability stdio structurally cannot provide.
- The RS role is **spec-compliant and disjoint** from ADR-012's issuer role; the two
  federation directions coexist by construction (disjoint endpoints/keys/audiences).
- **No-passthrough holds by construction** (same guarantee shape as ADR-012): the
  validated token becomes an in-process `Identity`, never a relayed bearer.
- Per-user identity makes the Wave-0 controls (ADR-011 policy, ADR-010 egress) and the
  audit trail **scope per human** — the first real per-user misuse-bounding (§3.4).
- **Zero regression**: a separate opt-in listener with its own chain leaves stdio,
  `/api/v1/mcp/*`, and the dashboard byte-for-byte unchanged; remote is off by default.
- One tool core (`dispatchToolCall`), two transport adapters — no duplicated tool
  logic.

**Negative**
- A second listener + a second middleware chain to maintain (justified: the security
  postures differ — Origin-reject + RS-auth vs CORS-only).
- The RS requires a one-time operator setup at the user's IdP (register a client /
  resource indicator) — documented, but real onboarding friction for the team SKU.
- Remote mode is the product's highest-value attack surface (PRODUCT-STRATEGY.md §4
  TeamPCP); it must remain off by default and the most-hardened path.

**Risks + mitigations**
- *Token-validation flaw (accept a forged/expired/wrong-aud token)* → fail-closed
  validator; reject `alg:none`/symmetric; mandatory issuer+audience+sig+exp; an
  extensive negative-test battery (Part G). Audience check is the confused-deputy
  linchpin and is non-optional.
- *DNS-rebinding / unauthenticated network exposure* → mandatory Origin **reject**
  (not just CORS withhold) + Host allowlist + loopback-default bind + no `0.0.0.0`
  auto-bind; the dashboard/internal surface never moves off localhost.
- *Token passthrough creeps in* → structural: no field/context/param carries the raw
  token past the gate; a test proves the outbound request never contains the inbound
  bearer.
- *SSRF via JWKS/discovery fetch* → every AS fetch routes through the egress
  `Guard.CheckHost` before dial, with size/content-type caps (ADR-014 discipline).
- *Confused deputy on provider OAuth* → exact `redirect_uri` allowlist + single-use
  subject-bound `state` + hardened cookies; consent record for remote-initiated flows.
- *Role confusion (RS vs issuer)* → test-enforced invariant: PRM `authorization_servers`
  and RS `TrustedIssuers` MUST NOT contain Straylight's own issuer URL.
- *Session table growth / DoS* → bounded, TTL'd, idle-expiring session map; sessions
  never extend token lifetime (re-validate every request).

**Tech Debt**
- **TD-1**: Phase-1 ships per-user audit/identity but defers per-user *policy*
  dimensions (`policy.Request.Subject`/`RequiredScopes`); land them when ≥2 real
  per-user rules exist (avoid premature abstraction).
- **TD-2**: opaque-token introspection (RFC 7662) not implemented; JWT-only in Phase 1
  (behind the `TokenValidator` seam, so additive later).
- **TD-3**: no Straylight-as-AS / DCR (Part F.4); clients must use their own IdP.
- **TD-4**: per-user credential partitioning deferred (Part F.3); Phase 1 scopes a
  shared catalog.
- **TD-5**: TLS termination for non-loopback bind is operator-provided (reverse proxy)
  in Phase 1; an integrated cert flow is a follow-up.

---

## Part G — Test plan

**`internal/mcpauth` — token validation (Phase 1, load-bearing security unit)**
- Valid JWT (good sig via fake AS JWKS, trusted `iss`, `aud`==resource, unexpired) →
  `Identity` with the expected subject/scopes; the raw token is **not** retained.
- Reject: bad signature; `alg:none`; symmetric alg; untrusted `iss`; `aud` missing /
  pointing at *another* RS (confused-deputy guard); expired/`nbf`-future (beyond skew);
  malformed/empty bearer. Each → a classified error mapping to `401 +
  WWW-Authenticate` with the right `error=`.
- `JWKSProvider`: unknown `kid` triggers a (single, SSRF-gated) refetch; an AS
  discovery/JWKS URL resolving to a link-local/metadata IP is **denied by the egress
  Guard before dial**; cache hit avoids refetch.
- **Role-disjointness invariant**: a config whose `TrustedIssuers` (or PRM
  `authorization_servers`) contains Straylight's own issuer URL fails a startup
  validation/test.

**RS HTTP surface (Phases 1–2)**
- `GET /.well-known/oauth-protected-resource` → PRM with `resource`==expected
  audience and `authorization_servers`==the configured IdP (never Straylight's issuer);
  public, cacheable.
- `POST /mcp` with no token → `401` + `WWW-Authenticate` naming `resource_metadata`.
- `POST /mcp` with a valid token → reaches `dispatchToolCall`; with an invalid token →
  `401` (handler never runs).

**`internal/mcphttp` — transport (Phase 2)**
- `initialize` negotiates `MCP-Protocol-Version` (highest ≤ client; default-to-latest
  when omitted); a subsequent request with a mismatched version header → `400`.
- `MCP-Session-Id` assigned on `initialize`, echoed and accepted on follow-ups;
  unknown/expired session id → `404`; `DELETE /mcp` terminates; idle TTL expiry drops.
- `tools/list` returns the **same** `toolDefinitions` the internal API returns
  (parity test); `tools/call` dispatches into `dispatchToolCall` and returns the same
  `ToolCallResult` shape.
- **Origin defense**: a disallowed/missing `Origin` → `403` **before** auth/handler;
  a forged `Host` → reject; `*` in `MCPAllowedOrigins` rejected at config validation.

**No-passthrough + identity (Phase 3 / audit slice)**
- A remote `tools/call` to a configured service: the **outbound** request carries the
  vault-injected credential and **never** the inbound bearer (passthrough-impossible
  assertion).
- The emitted `audit.Event` carries `SessionID`/actor==`Identity.Subject` and
  issuer in `Details`, and **no token / no secret** (reuse ADR-011 redaction asserts).
- **Backward-compat**: a stdio/internal-API `tools/call` (no `Identity`) behaves
  byte-identically — `policy.Request.Subject==""`, no new policy dimension engaged,
  same `ToolCallResult`.

**Confused-deputy (Phase 4)**
- A `redirect_uri` not exactly in the allowlist (incl. a prefix/substring near-match)
  → rejected.
- A replayed or subject-mismatched `state` on callback → rejected; a fresh single-use
  `state` succeeds once and is then consumed.
- Provider OAuth initiated for a remote subject without a consent record → consent-
  required; with one → proceeds.

**`serve()` / integration (smoke)**
- With `RemoteListenAddress`/`MCPResourceServer` **unset**: no remote listener exists;
  stdio + `/api/v1/mcp/*` + dashboard behave exactly as before (the off-by-default
  backward-compat guarantee).
- With them set: a real MCP client handshake (Origin OK, valid IdP token) lists tools
  and runs one `straylight_api_call` end-to-end through the proxy with the credential
  never appearing — the Wave-3 thesis demonstrated.

---

## Validation Criteria

- An MCP client (Claude Code / connector / Cursor / VS Code) connects to `POST /mcp`,
  authenticates with an access token its IdP minted (audience == our `resource`), and
  runs `straylight_api_call` with the credential vault-injected and **no token
  passthrough**.
- A token with the wrong audience, wrong issuer, bad signature, or expired is rejected
  with `401 + WWW-Authenticate` pointing at the PRM.
- A request with a disallowed/missing `Origin` is rejected with `403` before any
  handler runs; the product never auto-binds a non-loopback address.
- The PRM's `authorization_servers` and the RS's `TrustedIssuers` never contain
  Straylight's own OIDC issuer (role-disjointness, test-enforced).
- The stdio shim and `/api/v1/mcp/*` are byte-for-byte unchanged; remote mode is off
  unless explicitly configured (full existing suite green with remote disabled).
- Every remote tool call is attributed to the validated user in the audit log with no
  secret material.
- **Reconsider when**: a target client requires DCR-against-the-server (revisit
  Straylight-as-AS, Part F.4); URL-mode elicitation is needed for remote onboarding
  (Part F.1, which activates the D.1 consent surface); per-user credential ownership
  is required (Part F.3).

---

## Decision Required (maintainer must confirm before implementation)

1. **RS-only vs Straylight-as-AS for Phase 1.** Recommendation: **RS-only (B1)** —
   delegate client identity to the user's external IdP (Okta/Entra/Google/Auth0),
   publish PRM naming that IdP, validate its tokens. This is the smallest correct,
   spec-mandated surface and keeps the role cleanly disjoint from ADR-012's issuer.
   Confirm that requiring an external IdP (vs an embedded AS/DCR) is acceptable for
   the Wave-3 team SKU; DCR-against-the-server clients are explicitly Wave-3.5.

2. **Bind/TLS posture for the remote listener.** Recommendation: **loopback-default
   bind, operator-provided TLS/reverse-proxy for any non-loopback exposure, never
   auto-`0.0.0.0`.** Confirm this (vs an integrated TLS cert flow in Phase 1, which
   would enlarge scope). This is the one operational decision that gates real network
   exposure.

3. **Phase-1 subset.** Recommendation: ship **Phase 1 (RS validation + PRM) +
   Phase 2 (Streamable-HTTP transport + Origin defense) + the audit slice of Phase 3**
   as the minimum working authenticated remote MCP endpoint, deferring per-user
   *policy* dimensions and the consent-record machinery (D.1) as fast-follows, while
   pulling exact-`redirect_uri` + hardened `state` (D.2/D.3) forward as a small
   hardening PR. Confirm this scoping (vs. including full Phase 3/4 in the first merge).
