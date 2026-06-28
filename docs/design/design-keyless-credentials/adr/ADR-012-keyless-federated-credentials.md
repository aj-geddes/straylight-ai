# ADR-012: Keyless-by-Default Federated Credentials (RFC 8693 Token-Exchange Engine)

**Date**: 2026-06-26
**Status**: Proposed
**Issue**: #10 (Wave 1 — keyless-by-default)
**Branch**: wave1/keyless-oidc

## Context

`PRODUCT-STRATEGY.md` §3.2 is unambiguous, and the code confirms it: **all three
cloud providers are backed by long-lived static secrets in the vault.**

- `internal/cloud/aws.go` — `AssumeRole` requires **static admin AWS keys** to
  call STS. Those keys are the standing crown-jewel (`PRODUCT-STRATEGY.md` §4's
  TeamPCP caution applies directly to *us*).
- `internal/cloud/gcp.go` — a **static service-account JSON private key**
  (`GCPConfig.ServiceAccountJSON`) is stored and used to mint access tokens.
- `internal/cloud/azure.go` — a **static `client_secret`** (`AzureConfig.ClientSecret`)
  is stored and posted in a `client_credentials` grant.

Every one of these can be made **keyless**. They reduce to one abstract op
(`PRODUCT-STRATEGY.md` §3.2): *present identity proof → receive short-lived
provider credentials → cache to ~5 min pre-expiry → refresh.* That is exactly the
shape of **RFC 8693 OAuth 2.0 Token Exchange**, and GCP Workload Identity
Federation literally *is* an RFC 8693 endpoint.

A hard constraint governs the whole design (`PRODUCT-STRATEGY.md` §6, verified):
**OpenBao does NOT bundle the aws/gcp/azure secrets engines** — they were removed
at the fork and live only as external plugins. So Straylight cannot lean on
"Vault-grade for free" for cloud STS; the exchange is **our own code in
`internal/cloud`**. What OpenBao *does* ship and we *do* use: the **identity-token
issuer** (an OIDC provider with `.well-known/openid-configuration` + JWKS) — the
trust root the clouds federate *against*.

This ADR designs (1) a generic token-exchange engine; (2) the keyless conversion
of each provider with full backward compatibility; (3) OpenBao as the OIDC trust
root, with the explicit per-session-vs-per-deployment identity decision the
maintainer must confirm; (4) the per-credential refresh mutex for self-rotating
tokens (Slack/Atlassian); (5) GitHub App 1-hour installation tokens; and (6) MCP
no-passthrough compliance for every minted token.

This is the **federation complement** to the Wave-0 controls: ADR-010 bounds the
network, ADR-011 bounds the request shape; ADR-012 removes the standing secret so
that even a fully compromised broker leaks tokens with a 15-minute–1-hour TTL
instead of admin keys good until manual rotation.

### Constraints

- **Design only.** No Go is written in this ADR; it specifies interfaces,
  schema, placement, phasing, and tests.
- **Backward compatibility is non-negotiable.** Existing static-credential cloud
  services (`GCPConfig.ServiceAccountJSON`, `AzureConfig.ClientSecret`, AWS admin
  keys) MUST keep working unchanged. Keyless is **opt-in by config / auto where
  the config makes it unambiguous**, never a forced migration.
- **Match repo idioms.** Provider/Manager + cache (`internal/cloud`), expiry-aware
  lease cache (`internal/lease`), strategy registry (`InjectorRegistry`,
  `policy.Engine`), consumer-declared interfaces, per-service config + vault
  metadata, audited at the credential boundary.
- **No new external dependency without justification.** Prefer the standard
  library + the existing `golang.org/x/oauth2` family (already implied by the GCP
  comment) over new SDKs. AWS STS already abstracts behind the `STSClient`
  interface — extend it, do not couple to the SDK at the engine layer.
- **MCP no-passthrough (`PRODUCT-STRATEGY.md` §2, §3.2):** every downstream token
  the engine mints MUST be fresh and audience-scoped (RFC 8707 `resource` /
  per-provider audience), **never** a relayed inbound token.
- **The identity-proof source must be unreachable by AI tool paths** — same
  invariant as the unseal key (`PRODUCT-STRATEGY.md` §3.3): if the model can read
  the OpenBao identity token (or the GitHub App private key), federation buys
  nothing.

## Decision Drivers

- **Security**: eliminate standing cloud secrets; shrink blast radius to a token
  TTL; keep the identity-proof private; satisfy the MCP no-passthrough mandate.
- **Backward compatibility**: zero breakage for existing static services.
- **Simplicity / single-container ethos**: one engine, three adapters; reuse the
  lease cache; no external policy/STS engine.
- **Incrementalism**: ship the engine, then AWS (flagship), then GCP/Azure, then
  refresh-mutex + GitHub App — each independently valuable.
- **Maintainability**: the per-provider exchange is data + a small adapter, the
  same way injectors and DB engines are wired today.

## Options Considered

### Decision A — Where does the token-exchange engine live relative to `cloud.Provider` and `Injector`?

#### Option A1: New `internal/tokenexchange` package; cloud Providers and a new Injector both consume it (chosen)

A standalone `internal/tokenexchange` package owns the abstract op (identity-proof
source → per-provider exchange adapter → expiry-aware cache). The existing
`cloud.AWSProvider/GCPProvider/AzureProvider` gain a **keyless code path** that
delegates to it; a future `Injector` (e.g. for non-cloud federated HTTP services)
can reuse the same engine behind the `proxy.Injector` seam.

**Pros**: single home for the RFC 8693 logic; both the `exec` cloud path
(`cloud.Provider`) and the HTTP `Injector` path can use it without duplication;
testable in isolation with a fake identity source and a fake exchange adapter;
matches the "one evaluator, two seams" idiom of ADR-011.
**Cons**: one more package; cloud providers must branch static-vs-keyless. The
branch is small and explicit, and it is exactly where backward compatibility
lives, so this is acceptable.

#### Option A2: Fold the exchange into each `cloud.Provider` directly

Add the WebIdentity/WIF/FIC calls inside `aws.go`/`gcp.go`/`azure.go`.

**Pros**: no new package; smallest diff for the cloud-only case.
**Cons**: triplicates the identity-proof acquisition, the cache-with-proactive-
refresh, and the no-passthrough audience logic across three files; gives the
`Injector` seam nothing to reuse; the identity source becomes a hidden dependency
of three providers. Rejected — it re-creates the problem ADR-009's registry
solved for injection.

#### Option A3: Lean on OpenBao's cloud secrets engines / WIF plugins

Mount the `aws`/`gcp`/`azure` secrets engines in OpenBao and let it do STS.

**Pros**: "Vault-grade for free" if it were true.
**Cons**: **Not available.** `PRODUCT-STRATEGY.md` §6 (verified) — OpenBao does
not bundle these engines; they are external plugins in `openbao/openbao-plugins`,
which would mean shipping/managing plugin binaries inside the single container,
contradicting the zero-touch ethos and adding a supply-chain surface. Rejected;
we implement the exchange ourselves and use OpenBao only as the **OIDC issuer**.

**Decision: A1.** New `internal/tokenexchange` package; cloud Providers branch
to it for the keyless path; the `Injector` seam can reuse it later.

### Decision B — Identity trust root (THE decision the maintainer must confirm)

`PRODUCT-STRATEGY.md` §8 Q1/Q2 explicitly defer this. It determines the Wave-1
identity-proof source, so it must be settled before implementation.

#### Option B1: OpenBao identity-token issuer as the trust root, single embedded identity per deployment (RECOMMENDED default)

Straylight enables OpenBao's identity-token issuer (it ships in core — the
"identity" engine listed in §6). OpenBao publishes
`/.well-known/openid-configuration` + JWKS at its issuer URL; each cloud is
configured **once** to trust that issuer (AWS IAM OIDC provider, GCP Workload
Identity Pool provider, Entra federated identity credential). The broker requests
a signed identity token (audience-scoped per exchange) from OpenBao and presents
it to the cloud. Identity is **per-deployment** (one container = one workload
identity).

**Pros**: zero new infrastructure — the issuer is already in the container; one
trust relationship per cloud per deployment to set up; matches the single-
container north star; the identity-proof never leaves the container except as an
audience-scoped JWT to the specific cloud STS.
**Cons**: the **issuer URL must be network-reachable by the clouds** to fetch
JWKS — for a localhost-only single container that means either (a) the clouds
fetch JWKS at provider-config time only is NOT how it works (they re-fetch), so a
publicly-reachable issuer or a pre-registered static JWKS is required. **This is
the load-bearing operational caveat** and is called out below as the maintainer
decision. Per-deployment identity means per-session audit/revocation granularity
is coarser (mitigated by short TTLs + the per-exchange audience + the audit
trail).

#### Option B2: SPIRE-consumer (SPIFFE Workload API) for fleets

In multi-node/fleet deployments, Straylight consumes a SPIFFE SVID from a SPIRE
agent (Workload API) as the identity proof, federating SPIRE's trust domain to the
clouds.

**Pros**: industrial-strength workload identity, attestation, automatic SVID
rotation; the right answer at fleet scale; the identity-proof source is pluggable
behind the same `IdentitySource` interface.
**Cons**: requires SPIRE server+agent infrastructure — far beyond the single-
container ethos for the default install. Correct for a team/fleet SKU, overkill
for the flagship one-container experience.

#### Option B3: CI OIDC (GitHub Actions / GitLab) as identity proof

When Straylight runs inside CI, use the CI-provided OIDC token directly.

**Pros**: zero issuer to host — the CI platform is the issuer; clouds already
support GitHub/GitLab OIDC out of the box.
**Cons**: only applies in CI; not a general runtime identity for a self-hosted
broker. A useful *third* `IdentitySource` implementation, not the default.

**Decision: B1 is the recommended default, with B2/B3 as pluggable
`IdentitySource` implementations behind one interface.** See the explicit
maintainer-confirmation callout in **Decision Required** below.

### Decision C — Per-session vs per-deployment workload identity (§8 Q2)

#### Option C1: Per-deployment identity (RECOMMENDED for Wave 1)

One workload identity for the container; per-exchange audience scoping and the
audit trail provide the bounding.

**Pros**: one trust relationship per cloud; low token-exchange volume; simplest.
**Cons**: cannot revoke a *single AI session's* federated access independently;
audit attributes to the deployment, not the session.

#### Option C2: Per-AI-session scoped identity tokens

Mint a fresh OpenBao identity token per AI session (distinct `sub`/claims),
enabling per-session audit + revocation.

**Pros**: aligns with zero-knowledge; per-session revocation; finer audit.
**Cons**: multiplies token-exchange volume; the cloud-side trust policy must
accept a claim that varies per session (a wildcard `sub` condition), which
*loosens* the cloud-side condition unless paired with a session registry. Higher
complexity for Wave 1.

**Decision: C1 for Wave 1**, with the engine designed so the `IdentitySource` can
later vary claims per session (C2) without changing the exchange adapters. The
`IdentityRequest` carries an optional `SessionID`/claims map that a future
per-session source populates; Wave-1 sources leave it deployment-scoped.

## Decision (summary)

1. New `internal/tokenexchange` package implementing a generic RFC-8693-shaped
   engine: `IdentitySource` → per-provider `ExchangeAdapter` → expiry-aware cache
   with proactive refresh (reusing `internal/lease`'s renewal-window pattern).
2. The three `cloud.Provider`s gain a **keyless branch** that delegates to the
   engine; the **static branch is unchanged** (backward compatibility).
3. **OpenBao identity-token issuer is the default trust root (B1)**, per-deployment
   identity (C1); SPIRE (B2) and CI-OIDC (B3) are alternative `IdentitySource`s.
   **The issuer-reachability model is the one decision the maintainer must confirm
   before implementation (see Decision Required).**
4. A `tokenexchange.RefreshGuard` (per-credential mutex + single-flight) with
   atomic write-back to OpenBao for self-rotating tokens (Slack/Atlassian).
5. GitHub App support: store **only** the App private key; mint 1-hour installation
   tokens via the same engine + refresh guard; never store a PAT.
6. Every minted token is fresh and audience-scoped; the engine has **no API to
   relay an inbound token** (no-passthrough by construction).

## Consequences

**Positive**
- Eliminates the three standing cloud secrets — the single biggest reduction in
  the broker's blast radius and the direct answer to the TeamPCP caution (§4).
- One RFC 8693 engine serves cloud `exec` creds, federated HTTP injection, and
  GitHub App tokens — the pattern, not three copies.
- Backward compatible: static services are untouched; keyless is opt-in/auto.
- Self-rotating tokens stop corrupting themselves under concurrent AI tool calls
  (the §3.2 "mandatory engine detail").
- No-passthrough by construction: the engine cannot relay an inbound token.

**Negative**
- The keyless path requires per-cloud one-time trust setup (IAM OIDC provider /
  WIF pool / Entra FIC) outside Straylight — documented as onboarding steps.
- B1's issuer must be reachable by the clouds for JWKS — an operational constraint
  on the otherwise localhost-only container (the maintainer decision).
- A static-vs-keyless branch is added to each provider.

**Risks**
- *Issuer not reachable → all keyless exchanges fail.* **Mitigation**: keyless is
  opt-in; static path remains; a startup readiness check verifies the issuer's
  discovery doc is reachable before advertising keyless; clear error surfaced.
- *Clock skew → token `iat`/`exp` rejected by cloud STS.* **Mitigation**: the
  cache refreshes ~5 min pre-expiry (well inside skew tolerance) and the identity
  token is minted fresh per exchange with a short, standard `exp`.
- *Identity token leaks to an AI tool path.* **Mitigation**: same invariant as the
  unseal key — the token is minted in-process, never written to a vault path the
  service tools can read, never placed in injected env beyond the resulting
  short-lived cloud creds; audited as a mint event, not stored.
- *Refresh stampede / self-rotating token corruption.* **Mitigation**: the
  per-credential `RefreshGuard` (mutex + single-flight) with atomic write-back.
- *Cloud-side trust condition too broad (e.g. `sub` wildcard).* **Mitigation**:
  documented least-privilege provider conditions; per-exchange audience (`aud`)
  pinned to the specific provider; recommend repository/role-scoped conditions.

**Tech Debt**
- Wave 1 ships per-deployment identity (C1). Per-session identity (C2) is deferred;
  the `IdentityRequest` is shaped to carry session claims so the upgrade is a new
  `IdentitySource`, not a call-site change. Tracked under issue #10 follow-up.
- GCP optional SA impersonation (token → impersonated SA access token) is a second
  hop; Wave 1 implements direct WIF federation; impersonation is a flagged
  follow-up where a service needs an SA's own permissions.
- Okta/Auth0 generic-OIDC validation (§3.2) is a *validation task*, not new engine
  code; deferred to a Wave-1 tail / Wave-2 checkpoint.

## Implementation Notes

### New package: `internal/tokenexchange`

The package owns three collaborators and a cache. All signatures below are the
contract for the Developer; they mirror the `cloud.Provider`/`Manager` and
`lease.Manager` shapes already in the repo.

```go
// Package tokenexchange implements a generic RFC 8693-shaped token-exchange
// engine: an identity-proof source (OpenBao identity token / SPIRE SVID / CI
// OIDC) is exchanged, via a per-provider adapter, for short-lived downstream
// credentials, which are cached with proactive pre-expiry refresh.
//
// Every minted credential is fresh and audience-scoped. The engine has no API to
// relay an inbound token (MCP no-passthrough by construction).
package tokenexchange

import (
    "context"
    "time"
)

// IdentityProof is a signed assertion of the broker's workload identity, suitable
// as the subject_token of an RFC 8693 exchange. It is never persisted to a path
// reachable by AI tools.
type IdentityProof struct {
    // Token is the signed JWT / SVID (the RFC 8693 subject_token).
    Token string
    // TokenType is the RFC 8693 subject_token_type, e.g.
    // "urn:ietf:params:oauth:token-type:jwt" or "...:id_token".
    TokenType string
    // Issuer is the trust-root issuer URL (for audit / diagnostics).
    Issuer string
    // ExpiresAt bounds reuse of the proof itself.
    ExpiresAt time.Time
}

// IdentityRequest parameterizes a request for an identity proof.
type IdentityRequest struct {
    // Audience is the intended consumer of the proof (per-exchange, RFC 8707
    // style): the cloud provider's STS audience. Pins the proof to one consumer.
    Audience string
    // SessionID, when non-empty, requests a session-scoped proof (Decision C2,
    // deferred). Wave-1 sources ignore it (deployment-scoped, C1).
    SessionID string
    // Claims are optional extra claims a session-scoped source may embed.
    Claims map[string]string
}

// IdentitySource produces a fresh IdentityProof for a given audience. It is the
// pluggable trust root: OpenBao issuer (default), SPIRE Workload API (fleets),
// or CI OIDC.
type IdentitySource interface {
    // Identity returns a freshly-minted, audience-scoped identity proof.
    Identity(ctx context.Context, req IdentityRequest) (*IdentityProof, error)
    // SourceType identifies the source: "openbao", "spire", or "ci-oidc".
    SourceType() string
}

// ExchangeInput is the provider-agnostic input to an exchange.
type ExchangeInput struct {
    // Proof is the identity assertion to exchange.
    Proof *IdentityProof
    // Audience is the downstream audience/resource (RFC 8707) the resulting
    // credential is scoped to. Must be set; the engine refuses empty audiences.
    Audience string
    // Provider-specific parameters (role ARN, WIF pool, FIC client ID, scopes,
    // requested TTL) are carried in Params; each adapter documents its keys.
    Params map[string]string
    // RequestedTTL is the desired credential lifetime; the adapter clamps to the
    // provider's allowed range.
    RequestedTTL time.Duration
}

// ExchangedCredential is the short-lived downstream credential.
type ExchangedCredential struct {
    // EnvVars is the injectable representation (AWS_*, CLOUDSDK_*, AZURE_*), or a
    // single bearer token under "token" for HTTP/GitHub use.
    EnvVars map[string]string
    // ExpiresAt is when the credential becomes invalid.
    ExpiresAt time.Time
    // Audience echoes the scoping audience for audit (proves no passthrough).
    Audience string
    // Scope is a human-readable audit description (no secret material).
    Scope string
}

// ExchangeAdapter performs one provider's RFC 8693 exchange: identity proof ->
// short-lived provider credential. One implementation per provider.
type ExchangeAdapter interface {
    // Exchange calls the provider's STS/token endpoint with the identity proof
    // and returns short-lived credentials. Implementations MUST set the
    // downstream audience and MUST NOT echo the inbound proof as the result.
    Exchange(ctx context.Context, in ExchangeInput) (*ExchangedCredential, error)
    // ProviderType identifies the adapter: "aws", "gcp", "azure", "github_app",
    // "generic_oidc".
    ProviderType() string
}

// Engine ties an IdentitySource to a set of ExchangeAdapters and a cache with
// proactive refresh. It is safe for concurrent use.
type Engine struct { /* identitySource, adapters map[string]ExchangeAdapter,
                        cache, refreshGuard, logger */ }

// EngineConfig wires the engine.
type EngineConfig struct {
    Source   IdentitySource
    Adapters map[string]ExchangeAdapter // keyed by ProviderType()
    // RefreshWindow is the pre-expiry lead time for proactive refresh.
    // Default: 5 minutes (PRODUCT-STRATEGY.md §3.2).
    RefreshWindow time.Duration
}

// NewEngine constructs an Engine. Mirrors cloud.NewManager / lease.NewManager.
func NewEngine(cfg EngineConfig) *Engine

// Credential returns a valid (cached or freshly exchanged) credential for the
// given cache key and provider. On a cache hit within the refresh window it
// returns the cached value and schedules a background refresh; on a miss it
// performs the exchange synchronously. cacheKey is typically the service name.
func (e *Engine) Credential(ctx context.Context, cacheKey, provider string, in ExchangeInput) (*ExchangedCredential, error)

// Invalidate drops a cached credential, forcing a fresh exchange next call.
// Mirrors cloud.Manager.InvalidateCache.
func (e *Engine) Invalidate(cacheKey string)

// Close stops the background refresh goroutine. Mirrors lease.Manager.Close.
func (e *Engine) Close()
```

**Cache + proactive refresh.** Reuse the proven structure of
`internal/lease/cache.go`: a `sync.RWMutex`-guarded map keyed by cacheKey, a
single background ticker goroutine that, per tick, collects entries within
`RefreshWindow` of expiry and re-exchanges them via a single-flight guard, swapping
the entry on success and dropping it on repeated failure. The `LeaseState`
(`Active`/`Renewing`/`Expired`) two-phase-lock discipline transfers directly — do
not re-invent it; if practical, factor the generic "expiry-aware map + renewal
loop" out of `internal/lease` so both consumers share it (deferrable; the safe
Wave-1 move is to mirror the pattern).

### Where it sits relative to `cloud.Provider` and `Injector`

- **`cloud.Provider` (exec creds):** each provider keeps its `Provider` interface
  and `GenerateCredentials` signature. Internally it branches:
  - *static path* (today's behavior) when the keyless config is absent;
  - *keyless path* → builds an `ExchangeInput` and calls the injected `*Engine`.
  `cloud.Manager` is unchanged at the seam: it still caches per service name, and
  the engine's own cache sits one level down (the Manager cache can be bypassed
  for keyless services so the engine is the single source of freshness — see
  Backward Compatibility). The providers gain an optional `*tokenexchange.Engine`
  field via their `*ProviderConfig` (nil = static-only, preserving current tests).
- **`proxy.Injector` (HTTP creds):** a future `FederatedBearerInjector`
  (registered in `DefaultInjectorRegistry`) resolves a bearer token from the
  engine for federated HTTP services and GitHub App services. Wave 1 wires the
  GitHub App case; the generic OIDC-HTTP injector is a small follow-up reusing the
  same engine. This is the §3.2 "behind the existing `Injector` interface" placement.

### Per-provider keyless mechanics + schema additions + backward compatibility

The unifying backward-compat rule: **a provider uses the keyless path only when
its keyless config block is present AND the static secret is absent (or
`prefer_keyless` is set); otherwise it uses today's static path unchanged.** No
existing config field changes meaning; all new fields are additive and optional.

#### AWS — add `AssumeRoleWithWebIdentity` alongside `AssumeRole`

- **Mechanics**: the AWS adapter calls STS `AssumeRoleWithWebIdentity` with the
  OpenBao identity token as `WebIdentityToken`, the configured `RoleARN`, and the
  existing `RoleSessionName`/`DurationSeconds`/inline `Policy`. **No static admin
  keys** — the request is signed by nothing (WebIdentity is an unsigned STS call).
  Result maps to the same `AWS_ACCESS_KEY_ID`/`SECRET_ACCESS_KEY`/`SESSION_TOKEN`/
  `DEFAULT_REGION` env vars as today, so the `exec` injection is unchanged.
- **`STSClient` extension** (keeps the SDK behind the existing interface):
  ```go
  type STSAssumeRoleWithWebIdentityInput struct {
      RoleARN          string
      SessionName      string
      WebIdentityToken string // the OpenBao identity token (subject)
      DurationSeconds  int32
      Policy           *string
  }
  // Added to the STSClient interface (test mocks implement it):
  AssumeRoleWithWebIdentity(ctx context.Context, in STSAssumeRoleWithWebIdentityInput) (*STSCredentials, error)
  ```
- **Config additions** (`internal/cloud.AWSConfig` and
  `config.CloudServiceAWSConfig`), additive:
  ```yaml
  cloud_config:
    engine: aws
    aws:
      role_arn: arn:aws:iam::123456789012:role/StraylightRole
      region: us-east-1
      # NEW (opt-in keyless):
      web_identity: true        # use AssumeRoleWithWebIdentity instead of AssumeRole
      audience: sts.amazonaws.com   # token aud claim / STS audience (RFC 8707)
  ```
- **Backward compat**: `web_identity` defaults false → today's `AssumeRole` with
  static admin keys (unchanged). Set `web_identity: true` → keyless; the admin
  keys are no longer read. Existing AWS services keep working verbatim.

#### GCP — Workload Identity Federation replacing the static SA-JSON

- **Mechanics**: the GCP adapter posts to `sts.googleapis.com/v1/token` with
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (this endpoint
  *is* RFC 8693), `subject_token` = the OpenBao identity token, `audience` = the
  WIF pool provider resource name, `requested_token_type` = access_token. Optional
  second hop: **SA impersonation** (`generateAccessToken`) to act as a specific
  service account (deferred follow-up). Result maps to
  `CLOUDSDK_AUTH_ACCESS_TOKEN` (+ `CLOUDSDK_CORE_PROJECT`) as today.
- **Config additions** (`internal/cloud.GCPConfig` and
  `config.CloudServiceGCPConfig`), additive:
  ```yaml
  cloud_config:
    engine: gcp
    gcp:
      project_id: my-project
      scopes: ["https://www.googleapis.com/auth/cloud-platform"]
      # NEW (opt-in keyless):
      workload_identity:
        audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/straylight/providers/openbao"
        service_account_email: ""   # optional impersonation target (deferred)
  ```
- **Backward compat**: `GCPConfig.ServiceAccountJSON` (stored in vault) still
  works exactly as today. When `workload_identity` is present and no SA-JSON is
  stored, the keyless path is used. If both are present, `workload_identity`
  wins only when `prefer_keyless: true` is set — otherwise the stored SA-JSON path
  is preserved (least surprise for existing deployments).

#### Azure — federated identity credential + `jwt-bearer` client assertion

- **Mechanics**: the Azure adapter posts to the Entra token endpoint with
  `grant_type=client_credentials`,
  `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
  and `client_assertion` = the OpenBao identity token, against an app registration
  that has a **federated identity credential (FIC)** trusting the OpenBao issuer +
  subject. **No `client_secret`** is posted or stored. Result maps to
  `AZURE_ACCESS_TOKEN` (+ tenant/subscription/client) as today.
- **Config additions** (`internal/cloud.AzureConfig` and
  `config.CloudServiceAzureConfig`), additive:
  ```yaml
  cloud_config:
    engine: azure
    azure:
      tenant_id: <tenant>
      subscription_id: <sub>
      scope: "https://management.azure.com/.default"
      # NEW (opt-in keyless):
      federated_identity:
        client_id: <app-client-id>
        audience: "api://AzureADTokenExchange"   # standard FIC audience
  ```
- **Backward compat**: `AzureConfig.ClientSecret` (in vault) still works. When
  `federated_identity` is present and no `client_secret` is stored, the keyless
  (assertion) path is used. The static `client_credentials` flow is untouched for
  existing services.

#### Service / vault-storage schema impact

- `services.Service` needs **no new persisted field** for cloud keyless — the
  keyless knobs live in the per-service `CloudServiceConfig` (config.yaml) and in
  the in-memory `cloud.ServiceConfig` the Manager builds. This keeps the change in
  the config + cloud layers, where the existing static fields already live.
- For **GitHub App** (HTTP/`Injector` path), the App private key is a credential
  field stored in vault via the existing multi-field format
  (`writeCredentials`/`ReadCredentials`), `auth_method = "github_app"`, fields
  `{app_id, installation_id, private_key}`. No PAT is ever stored. The injector
  reads these and asks the engine for a fresh installation token.
- Validation extends `validateService` / config validation: a cloud service with
  a keyless block must carry the matching required fields (AWS `role_arn`+audience,
  GCP WIF `audience`, Azure FIC `client_id`+audience); a `github_app` service must
  carry `app_id`+`installation_id`+`private_key`.

### OpenBao as the OIDC trust root (Decision B1)

`internal/vault.Client` gains the issuer-management methods (thin wrappers over
OpenBao's identity-token API, in the same style as the existing
`EnableSecretsEngine`/`ConfigureDatabaseConnection` helpers):

```go
// ConfigureIdentityIssuer sets the issuer URL OpenBao advertises in its
// .well-known/openid-configuration. The URL must be reachable by the clouds that
// will fetch JWKS (see Decision Required).
func (c *Client) ConfigureIdentityIssuer(issuerURL string) error

// CreateIdentityRole defines a named identity-token role (audience template, TTL,
// claim template) clouds federate against.
func (c *Client) CreateIdentityRole(name string, audiences []string, ttl string, claims map[string]any) error

// GenerateIdentityToken mints a signed identity token for the given role/audience.
// This is the IdentityProof.Token for the OpenBao IdentitySource. Minted
// in-process; never persisted to a service-readable path.
func (c *Client) GenerateIdentityToken(role, audience string) (token string, expiresAt time.Time, err error)
```

`tokenexchange.openbaoSource` implements `IdentitySource` by calling
`GenerateIdentityToken(role, req.Audience)`. The issuer's discovery doc + JWKS are
served by OpenBao itself (core identity engine); Straylight's job is to configure
the role and verify reachability at startup.

**Trust setup (one-time, per cloud, documented in onboarding):** create the AWS
IAM OIDC identity provider / GCP Workload Identity Pool provider / Entra FIC, each
pointing at the OpenBao issuer URL and constraining `sub`/`aud` to the broker's
identity-role. These are operator steps outside Straylight; the ADR/implementation
guide ships the exact snippets.

### Per-credential refresh mutex (Slack single-use RT, Atlassian rotating RT)

The §3.2 "mandatory engine detail." Concurrent AI tool calls would otherwise race
to use a single-use/rotating refresh token and corrupt it.

```go
// RefreshGuard serializes refreshes per credential key and collapses concurrent
// refreshes into a single flight, then atomically writes the rotated token back
// to OpenBao before releasing waiters.
type RefreshGuard struct { /* mu per key (keyed mutex) + singleflight + vault */ }

// Do runs fn (the refresh exchange) under the per-key lock with single-flight
// semantics. fn returns the new credential fields; Do writes them back to OpenBao
// atomically (RotateCredential / UpdateCredentials) and returns them. Concurrent
// callers for the same key wait and receive the single refreshed result.
func (g *RefreshGuard) Do(ctx context.Context, key string, fn func(ctx context.Context) (map[string]string, error)) (map[string]string, error)
```

- **Per-key mutex** (`map[string]*sync.Mutex` guarded by an outer mutex, or
  `golang.org/x/sync/singleflight` keyed by credential) ensures exactly one
  rotation per credential at a time.
- **Atomic write-back** uses the registry's existing
  `RotateCredential`/`UpdateCredentials` → `vault.WriteSecret` (KV v2 write is the
  atomic unit), then `proxy.InvalidateCache(name)` + `engine.Invalidate(name)` so
  the next call reads the rotated token. The old RT is discarded only after the
  new one is persisted (write-then-swap), so a crash mid-rotation leaves a usable
  token.
- This guard is the **same** single-flight the engine's proactive refresh uses;
  Slack/Atlassian are modeled as `ExchangeAdapter`s whose "exchange" is a refresh-
  token grant, routed through the guard.

### GitHub App 1-hour installation tokens (replace stored PATs)

- Store **only** the App private key (+ app_id, installation_id) in vault; never a
  PAT.
- A `github_app` `ExchangeAdapter`: sign a short-lived App JWT (RS256, ≤10 min,
  `iss=app_id`) with the stored private key → POST
  `/app/installations/{id}/access_tokens` → receive a 1-hour installation token.
- Cache + proactively refresh via the engine (≤1 h TTL, refresh ~5 min pre-expiry)
  and the `RefreshGuard` (so concurrent tool calls share one mint).
- The `FederatedBearerInjector` attaches the installation token as
  `Authorization: token <installation_token>` (GitHub's scheme) at request time.
- **No-passthrough**: the installation token is minted fresh and scoped to the
  installation; no inbound token is ever relayed.

### MCP no-passthrough compliance (built in, not bolted on)

- `ExchangeInput.Audience` is **required**; `Engine.Credential` and every adapter
  reject an empty audience. The minted credential echoes its `Audience` for audit.
- There is **no engine API that accepts an inbound client token to forward** — the
  only input is an `IdentityProof` minted by a trusted `IdentitySource`, never a
  request-borne token. No-passthrough is therefore structural, not a runtime check
  that could be bypassed.
- Audit a `token_minted` event (provider, audience, cacheKey, expiry — never the
  token) at each mint, reusing the ADR-011 audit discipline.

## Phased Implementation Plan

Strictly incremental; each phase is independently shippable and testable. Matches
`PRODUCT-STRATEGY.md` §5 Wave-1 ordering (engine → AWS flagship → GCP/Azure →
refresh-mutex + GitHub App).

- **Phase 1 — Engine + OpenBao issuer (foundation).**
  `internal/tokenexchange` (interfaces, cache+refresh mirroring `internal/lease`,
  `RefreshGuard`); `vault.Client` issuer methods; `openbaoSource`. No provider
  changes yet. Fully unit-tested with fakes. Ships behind no user-visible change.
- **Phase 2 — AWS flagship (`AssumeRoleWithWebIdentity`).**
  Extend `STSClient`; add the AWS adapter; branch `AWSProvider`; additive config.
  This is the headline: a real AWS service with zero stored admin keys.
- **Phase 3 — GCP WIF + Azure FIC.**
  GCP and Azure adapters; branch the two providers; additive config; keep static
  paths. (GCP SA impersonation flagged as a follow-up.)
- **Phase 4 — Refresh-mutex + GitHub App.**
  Wire `RefreshGuard` into the engine's refresh path; model Slack/Atlassian
  refresh as guarded adapters with atomic write-back; add the `github_app` adapter
  + `FederatedBearerInjector`; store only the App private key.
- **Deferred beyond Wave 1 (flagged):** per-session identity (C2); GCP SA
  impersonation; generic OIDC-HTTP injector + Okta/Auth0 validation; SPIRE
  `IdentitySource` for fleets (B2); factoring the shared expiry-cache out of
  `internal/lease`.

## Test Plan

`internal/tokenexchange/engine_test.go`:
- Cache hit within TTL returns cached credential without calling the adapter.
- Cache entry within `RefreshWindow` triggers exactly one background refresh
  (single-flight): N concurrent `Credential` calls → 1 adapter `Exchange` call.
- Miss performs a synchronous exchange; result cached with correct `ExpiresAt`.
- **No-passthrough**: `Credential` with empty `ExchangeInput.Audience` errors;
  the engine never returns the `IdentityProof.Token` as the credential.
- `Invalidate` forces a fresh exchange; `Close` stops the refresh goroutine
  (no goroutine leak — assert with a tick-counting fake clock or done channel).

`internal/tokenexchange/refreshguard_test.go`:
- 50 concurrent `Do` for the same key → `fn` runs once; all callers get the same
  result; the new credential is written back exactly once.
- Different keys refresh concurrently (no cross-key serialization).
- `fn` error → write-back NOT performed; old credential remains (write-then-swap).

`internal/cloud/aws_test.go` (extend):
- Mock `STSClient.AssumeRoleWithWebIdentity` → keyless path returns AWS_* env vars;
  **no static admin keys read** (assert the static `AssumeRole` mock is untouched).
- `web_identity: false` (default) → existing `AssumeRole` behavior unchanged
  (regression guard for backward compat).

`internal/cloud/gcp_test.go` / `azure_test.go` (extend):
- WIF path: fake `sts.googleapis.com` token-exchange endpoint → `CLOUDSDK_*` env.
- FIC path: fake Entra endpoint accepts `client_assertion`, rejects if a
  `client_secret` is sent (proves the secret is gone).
- Static SA-JSON / `client_secret` paths unchanged (regression guards).

`internal/vault/client_test.go` (extend):
- `ConfigureIdentityIssuer` / `CreateIdentityRole` / `GenerateIdentityToken`
  against a fake OpenBao identity endpoint; token has the requested `aud`.

`internal/tokenexchange/github_app_test.go`:
- Stored private key → signed App JWT → fake installations endpoint → 1-hour
  installation token; concurrent injects share one mint via the guard; no PAT path
  exists.

Cross-cutting:
- **Backward-compat suite**: a config with only static cloud fields produces
  byte-identical behavior to the pre-ADR providers (golden env-var maps).
- **Audit**: `token_minted` emitted with provider/audience/expiry and **no token
  material**; reuses the ADR-011 redaction assertions.

## Validation Criteria

- A configured keyless AWS service performs `straylight_exec` with **zero static
  AWS keys in vault** (verified by inspecting the service's vault path).
- For each provider, the static-config path remains byte-identical (golden tests).
- Concurrent tool calls on a Slack/Atlassian-style rotating credential never
  corrupt the token (single-flight + atomic write-back proven under race detector).
- No engine code path returns or relays an inbound/identity token as a downstream
  credential (no-passthrough test green).
- The OpenBao issuer's discovery doc + JWKS are reachable at startup before the
  keyless path is advertised; otherwise the static path is used and a clear
  diagnostic is logged.
- **Reconsider when**: per-session identity (C2) is required; a fleet deployment
  needs SPIRE (B2); or the issuer-reachability model (Decision Required) proves
  operationally untenable for the default single-container install.

## Decision Required (maintainer must confirm before implementation)

**The identity trust-root model — Decision B1 + C1 — is recommended but must be
explicitly confirmed**, because it carries one load-bearing operational
constraint:

> **Recommendation:** Default to **OpenBao's identity-token issuer as the trust
> root, with per-deployment workload identity** (B1 + C1). SPIRE (B2) and CI-OIDC
> (B3) are pluggable `IdentitySource` alternatives for fleets/CI; per-session
> identity (C2) is deferred but the interfaces are shaped to add it without
> changing call sites.

> **The constraint to confirm:** for clouds to federate against OpenBao, they must
> be able to fetch the issuer's JWKS. The flagship container binds **localhost
> only** (`PRODUCT-STRATEGY.md` §3.3), which the clouds cannot reach. The
> maintainer must choose how the issuer is exposed for keyless:
> 1. **Publicly-reachable issuer endpoint** (a minimal, JWKS/discovery-only public
>    surface — *not* the OpenBao API port), or
> 2. **Pre-registered static JWKS** in each cloud's OIDC provider config (no live
>    fetch; requires re-registration on key rotation), or
> 3. **Keyless cloud federation is enabled only in deployments that already have a
>    reachable issuer** (e.g. behind a team gateway / Wave-3 remote mode), and the
>    flagship single-container ships keyless **GitHub App** (no external issuer
>    needed) first, with cloud keyless gated on this choice.

This is the single decision that gates Phase 2/3 (cloud keyless). Phase 1 (engine)
and Phase 4's GitHub App path do **not** depend on it and can proceed regardless.
