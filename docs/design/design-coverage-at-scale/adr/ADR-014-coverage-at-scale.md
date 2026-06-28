# ADR-014: Coverage at Scale — Data-Driven Auth, Generic Signers, OpenAPI Import, Community Template Registry

**Date**: 2026-06-28
**Status**: Proposed
**Issue**: #11 (Wave 2 — "coverage at scale")
**Branch**: feat/11-coverage-at-scale
**Builds on**: ADR-009 (injection-strategy dispatch / `Injector` interface + registry)
**Relates to**: PRODUCT-STRATEGY.md §3.1 (universal coverage), §3.2 (OIDC passthrough — separate Wave)

---

## Context

Straylight reaches services through a declarative model: a `ServiceTemplate` lists
`AuthMethod`s, each carrying an `InjectionConfig`; the proxy looks up an `Injector`
in the `InjectorRegistry` (ADR-009) and calls `Inject(req, fields, config)` on the
hot path. Today that ships **16 built-in templates** and **5 runtime injectors**
(`bearer_header`, `custom_header`, `multi_header`, `query_param`, `basic_auth`),
plus `oauth` handled by the OAuth flow and `named_strategy` as an escape hatch.

This architecture is the same one n8n, Vault, Steampipe, and Zapier use to cover
huge catalogs (PRODUCT-STRATEGY.md §3.1). The work is **extension, not redesign**.
Two concrete gaps and one structural ceiling block "coverage at scale":

1. **Declared-but-missing strategies.** `aws_sigv4` and `github_app_jwt` are
   referenced by templates (`internal/services/auth_methods.go`: the `aws`,
   `github` templates set `Injection{Type: named_strategy, Strategy: "aws_sigv4"}`
   / `"github_app_jwt"`) and are `validInjectionTypes`-legal via
   `InjectionNamedStrategy`, but **no injector is registered** for them in
   `DefaultInjectorRegistry()`. A user who picks "AWS Access Key" gets a runtime
   `proxy: no injector registered for type "named_strategy"`-class failure. ADR-009
   explicitly parked these as "Phase 2".

2. **The long tail needs Go.** Every bespoke API auth (a header *and* a query
   param; an `X-Date` plus a signed header; a token in the body) currently needs
   either a new injector type (Go + an ADR) or a forced fit into `multi_header`.
   There is no single data-driven primitive that covers arbitrary
   `{headers, query, body}` placement from credential fields.

3. **Adding a service means editing Go.** `ServiceTemplates` is a compiled `[]ServiceTemplate`
   literal. Adding "Notion" or "Linear" requires a code change, build, and release —
   not a config drop. The same is true of OAuth providers (`internal/oauth/providers.go`
   `Providers` is a compiled map). This caps catalog growth at maintainer throughput.

### Scale target

The thesis (PRODUCT-STRATEGY.md §3.1, §4) is **breadth as the moat** vs. Infisical
Agent Vault. The 10x question: *how do we get from ~16 templates to hundreds — and
cover the long tail of bespoke auth — without N Go injectors and N template edits?*
The answer is to push variability into **data** (config rendered by a few generic
engines) and make the catalog **runtime-loadable**.

### Constraints

- **Hot path.** Every agent API call goes through the proxy and one `Inject`
  call. New injectors must add no measurable per-request latency beyond what they
  intrinsically require (signers do hashing; that is unavoidable and bounded).
- **Backward compatibility, hard requirement.** Existing templates, the 5 built-in
  injectors, `oauth`, and the legacy flat-`Inject` path must be byte-for-byte
  unchanged. New work is purely additive: new injector *types*, new optional
  `InjectionConfig` fields, a new loader, a new importer package.
- **Validation is the trust boundary.** Runtime-loaded templates are untrusted
  input. They MUST pass the *exact same* `ValidateTemplate` /
  `ValidateAuthMethod` path the built-ins pass (`internal/services/auth_methods.go`),
  extended for the new injection types. No loaded template may smuggle a
  capability a built-in template could not declare.
- **SSRF discipline.** The OpenAPI importer fetches a remote spec URL; the
  `custom_auth` body injector and signers may read request bodies. The importer's
  fetch MUST route through the existing egress `Guard` (`internal/egress/guard.go`
  `CheckHost`) so a spec URL can't be used for SSRF against link-local/metadata.
- **No secrets to the AI.** Unchanged invariant: injectors run inside the proxy;
  credential *values* never enter a template error, an importer draft, or the MCP
  surface. Importer drafts contain **field shapes**, never values.
- **Match repo idioms.** Consumer-declared interfaces; data-driven per-item config;
  one registry constructed once and injected; validate-at-startup (the `init()` in
  `auth_methods.go` already panics on a bad pattern — loaded templates get the same
  fail-fast treatment, but at *load* time, isolated per file).
- **Design only.** This ADR proposes; **no Go files are touched here.** Phasing is
  set so each piece is independently TDD-able and mergeable.

---

## Decision Drivers

- **Coverage per unit of Go** (primary): maximize services reachable per line of new
  Go. A data-driven injector + a loader covers hundreds of services with zero
  per-service code.
- **Backward compatibility**: additive only; existing behavior frozen.
- **Security**: validation parity for loaded templates; SSRF-safe import; signer
  correctness (a wrong signature is a hard failure, not a silent 401-on-retry loop).
- **Testability**: each piece (injector, signer, importer, loader) is a unit with a
  clear contract; no piece needs a full proxy or live network to test.
- **Maintenance**: a new service is a YAML PR reviewed by a human, not a Go change
  + release.

---

## Scope

**IN (this ADR, shippable Wave-2 core):**
1. Generic `custom_auth` injector — data-driven `{headers, query, body}` rendering.
2. Generic signers — `aws_sigv4` (region+service parameterized; STS session token)
   and new `hmac_signature` (algorithm/encoding/header/timestamp/template).
3. OpenAPI 3.1 importer — spec → **draft** `ServiceTemplate` (servers→Target,
   securitySchemes→AuthMethods, default scheme→DefaultHeaders), marked
   "draft, needs review".
4. Runtime-loadable community template registry — YAML/JSON `ServiceTemplate`s
   loaded from a directory through `ValidateTemplate`; plus a data-driven
   OAuth-provider table (authorize/token URLs, scopes, PKCE flag, token-parser
   expression).

**DEFERRED (Wave-2.5, contract sketched in Part F, not implemented here):**
- Non-HTTP protocol executors (SSH / gRPC / message-queue) behind a non-HTTP
  injection contract.
- `mutual_tls` (OpenBao `pki` client certs) — needs transport-layer (mTLS dialer)
  work, not header injection.
- `github_app_jwt` runtime injector — the *other* declared-but-missing strategy.
  It needs a JWT mint + an installation-token *exchange round-trip with caching*
  (closer to the §3.2 OIDC token-exchange engine than to a stateless signer);
  scoped out of this ADR to keep the signer work stateless and self-contained.
  (Deferred but tracked: see Part F.4.)

---

## Part A — Generic `custom_auth` injector

### A.1 The problem class

This is the **Strategy + Template Method** pattern, the same one `custom_header`
already is, generalized from "one header" to "any combination of headers, query
params, and body fields, each rendered from any credential field." n8n's "Custom
Auth" credential and Postman's auth helpers are the reference manifestations
(PRODUCT-STRATEGY.md §3.1, §11 — "n8n custom auth"). It is the highest-leverage
coverage primitive after bearer/basic because it collapses an open-ended set of
future injector types into **one** data-driven injector.

### A.2 Config schema (extends `InjectionConfig`)

Add one optional field to `services.InjectionConfig` (purely additive; the existing
fields and their zero-values are untouched):

```go
// InjectionConfig (additive field — Wave 2)
type InjectionConfig struct {
    Type           InjectionType     `json:"type"            yaml:"type"`
    HeaderName     string            `json:"header_name,omitempty"     ...`
    HeaderTemplate string            `json:"header_template,omitempty" ...`
    QueryParam     string            `json:"query_param,omitempty"     ...`
    Headers        map[string]string `json:"headers,omitempty"         ...`
    Strategy       string            `json:"strategy,omitempty"        ...`
    // NEW (Wave 2): data-driven custom_auth spec. Nil for all existing configs.
    Custom         *CustomAuthSpec   `json:"custom,omitempty" yaml:"custom,omitempty"`
}

// CustomAuthSpec is the data-driven placement spec for the custom_auth injector.
// Each value is a Go text/template string rendered against the credential fields
// (plus a small safe function set). Keys are literal header/param/body-key names.
type CustomAuthSpec struct {
    // Headers maps header name -> template (e.g. "X-Api-Key" -> "{{.api_key}}").
    Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
    // Query maps query param name -> template (e.g. "token" -> "{{.token}}").
    Query map[string]string `json:"query,omitempty" yaml:"query,omitempty"`
    // Body, when non-empty, injects rendered values into the request body.
    // BodyMode selects how (see below). Keys are JSON pointers or form keys.
    Body map[string]string `json:"body,omitempty" yaml:"body,omitempty"`
    // BodyMode is "json" (merge into a JSON object body) or "form"
    // (application/x-www-form-urlencoded). Empty => body injection disabled.
    BodyMode string `json:"body_mode,omitempty" yaml:"body_mode,omitempty"`
}
```

### A.3 Template language and the rendering contract

- The template engine is Go `text/template` (already used by `renderTemplate` in
  `internal/proxy/proxy.go`), but the **data context changes from a single
  `.Secret` to the whole credential field map**. `{{.api_key}}`, `{{.token}}`,
  `{{.client_id}}` resolve to credential field values; `{{.secret}}`/`{{.Secret}}`
  is preserved as an alias to the primary token field for backward symmetry.
- A **bounded, safe function set** is registered: `upper`, `lower`, `base64`,
  `hex`, `urlquery`, `now` (RFC3339 / unix), `sha256hex`. **No** filesystem, env,
  or network functions. This is an allowlist, not the full template std-funcs.
- Rendering is **fail-closed**: a template that references a missing field, or a
  parse error, returns an `error` from `Inject` (wrapped with `custom_auth:` and
  the offending key — *never* the value). The proxy already wraps and audits
  injector errors.
- **Body injection ordering** runs *after* header/query so a custom_auth method can
  add an HMAC over the final body (composes with `hmac_signature` when chained via
  a future `named_strategy`; for v1 they are separate auth methods).

### A.4 Registry integration (ADR-009 pattern, unchanged shape)

`custom_auth` is a new closed enum value and a new registered injector — exactly
the ADR-009 "implement interface, register in map, add to template" path:

```go
// internal/services/auth_methods.go
const InjectionCustomAuth InjectionType = "custom_auth"
// add to validInjectionTypes; add a ValidateAuthMethod case:
//   custom_auth requires a non-nil Custom with at least one of Headers/Query/Body.

// internal/proxy/injectors.go
type CustomAuthInjector struct{} // stateless; implements Injector

// internal/proxy/injector.go DefaultInjectorRegistry()
r.Register(string(services.InjectionCustomAuth), &CustomAuthInjector{})
```

`Inject(req, fields, config)` reads `config.Custom`, renders each template against
`fields`, sets headers via `req.Header.Set`, merges query via `req.URL.Query()` +
`Encode()` (same as `QueryParamInjector`), and — when `BodyMode != ""` — reads,
merges, and rewrites `req.Body` (resetting `ContentLength` and `Body`). Stateless,
so it fits the registry's shared-instance model.

### A.5 What this covers with zero new Go per service

Header+query combos, non-`Authorization` header names with prefixes/suffixes,
date-stamped headers, simple body-token APIs, dual-key schemes ("key id" header +
"secret" header) — the entire bespoke long tail. New such services become a
template (built-in *or* community-loaded), never a code change.

---

## Part B — Generic signers

Both are **stateless `Injector` implementations** registered under their named
strategy. They keep the ADR-009 contract (`Inject(req, fields, config) error`) and
carry only injected, side-effect-free dependencies (a clock for determinism in
tests). This finally implements one of the two ADR-009 "Phase 2" strategies
(`aws_sigv4`) and adds a new one (`hmac_signature`).

### B.1 `aws_sigv4` (implements declared-but-missing strategy)

AWS Signature Version 4. Parameterized by **region + service** so the *same* signer
serves AWS, Cloudflare R2, Backblaze B2 (S3-compat), MinIO, and DigitalOcean
Spaces (PRODUCT-STRATEGY.md §3.1). Passes STS `session_token` when present.

```go
// InjectionConfig additive fields for the signer family (all omitempty):
//   SignRegion  string  // e.g. "us-east-1"; may be overridden by a credential field "region"
//   SignService string  // e.g. "s3", "execute-api", "sts"
// (Stored under a nested SignSpec to avoid InjectionConfig bloat — see B.3.)

// internal/proxy/signers.go (new file, same package as injectors.go)
type AWSSigV4Injector struct {
    now func() time.Time // injectable clock; defaults to time.Now (testability)
}
func (a *AWSSigV4Injector) Inject(req *http.Request, fields map[string]string, cfg services.InjectionConfig) error
```

Behavior (the canonical SigV4 algorithm, no AWS SDK dependency required for the
signing math — it is a well-specified HMAC chain):

1. Read `access_key_id`, `secret_access_key` (required), `session_token`,
   `region` (optional; falls back to `cfg.Sign.Region`) from `fields`.
2. Compute the canonical request (method, canonical URI, canonical query, signed
   headers incl. `host` and `x-amz-date`, **payload hash** of the body — read,
   hash with SHA-256, restore the body reader; for unsigned-payload services emit
   `UNSIGNED-PAYLOAD`).
3. Derive the signing key (`AWS4` + secret → date → region → service →
   `aws4_request`, HMAC-SHA256 chain), sign the string-to-sign.
4. Set `Authorization: AWS4-HMAC-SHA256 Credential=.../...,
   SignedHeaders=..., Signature=...`, plus `X-Amz-Date` and, if present,
   `X-Amz-Security-Token: {session_token}`.
5. **Determinism for tests**: the clock is injected; tests pin `now` and assert the
   exact signature against an AWS-documented test vector.

**Coverage payoff**: one signer + a per-target `SignService`/`SignRegion` in the
template covers every S3-compatible store and every SigV4 AWS service via
`custom`/template `Target` — no new Go per provider.

### B.2 `hmac_signature` (new generic signer)

Covers Stripe/GitHub/Slack/Shopify-style request signing **from data alone**
(PRODUCT-STRATEGY.md §3.1). The variability is captured as config, not code:

```go
// HMACSpec (nested in InjectionConfig.Sign or its own field):
type HMACSpec struct {
    Algorithm    string `yaml:"algorithm"`     // "sha256" | "sha512"
    Encoding     string `yaml:"encoding"`       // "hex" | "base64"
    HeaderName   string `yaml:"header_name"`    // e.g. "X-Signature"
    HeaderPrefix string `yaml:"header_prefix"`  // e.g. "sha256=" (GitHub style)
    SecretField  string `yaml:"secret_field"`   // credential field holding the key
    // SignedString is a template for the string that gets HMAC'd, rendered against
    // {timestamp, method, path, body, and credential fields}, e.g.:
    //   "{{.timestamp}}.{{.body}}"  (Slack)   or   "{{.body}}"  (GitHub webhook style)
    SignedString string `yaml:"signed_string"`
    // IncludeTimestamp adds a timestamp header (TimestampHeader) and exposes
    // {{.timestamp}} to SignedString. Format is unix seconds (configurable later).
    IncludeTimestamp bool   `yaml:"include_timestamp"`
    TimestampHeader  string `yaml:"timestamp_header"` // e.g. "X-Timestamp"
}

type HMACInjector struct{ now func() time.Time }
func (h *HMACInjector) Inject(req *http.Request, fields map[string]string, cfg services.InjectionConfig) error
```

Behavior:
1. Resolve the key from `fields[SecretField]`.
2. If `IncludeTimestamp`, compute `ts = now()`, set `TimestampHeader: ts`, expose
   `{{.timestamp}}`.
3. Render `SignedString` against `{timestamp, method, path, body, ...fields}`
   (body read + restored, as in SigV4).
4. `mac = HMAC(Algorithm, key, signed_string)`; encode per `Encoding`.
5. `req.Header.Set(HeaderName, HeaderPrefix + encoded)`.
6. Fail-closed on unknown algorithm/encoding (validated at template-load time too).

### B.3 Where the signer config lives (avoiding `InjectionConfig` bloat)

To keep `InjectionConfig` legible, nest signer params rather than flattening:

```go
type InjectionConfig struct {
    ... existing ...
    Custom *CustomAuthSpec `json:"custom,omitempty" yaml:"custom,omitempty"` // Part A
    Sign   *SignSpec       `json:"sign,omitempty"   yaml:"sign,omitempty"`   // Part B
}
type SignSpec struct {
    AWS  *AWSSignSpec `json:"aws,omitempty"  yaml:"aws,omitempty"`  // region, service
    HMAC *HMACSpec    `json:"hmac,omitempty" yaml:"hmac,omitempty"`
}
```

Validation: `aws_sigv4` requires `Sign.AWS != nil` (with a non-empty `Service`);
`hmac_signature` requires `Sign.HMAC != nil` (with `Algorithm`, `Encoding`,
`HeaderName`, `SecretField`, `SignedString` all set). Both become new closed enum
values (`InjectionAWSSigV4 = "aws_sigv4"`, `InjectionHMACSignature = "hmac_signature"`)
**and** remain reachable as `named_strategy` `Strategy:"aws_sigv4"` for the existing
`aws` template — the registry can register the signer under *both* the new type
name and the legacy strategy name, preserving the in-tree `aws` template verbatim
(backward-compat: it keeps `named_strategy` + `aws_sigv4`).

### B.4 Migration of the existing `aws` template (backward-compatible)

The current `aws` template uses `Injection{Type: named_strategy, Strategy: "aws_sigv4"}`
and supplies `region` as a credential field but **no `SignService`**. To keep it
working unchanged while making it correct: register the SigV4 injector under the
`named_strategy`/`aws_sigv4` dispatch key (ADR-009 already routes `named_strategy`
by `Strategy`), default `SignService` to `"execute-api"` *only if* a future config
adds one — but since AWS's generic endpoint needs a service, the recommended fix is
a **separate follow-up** that adds `Sign.AWS.Service` to the `aws` template's auth
methods. The ADR's commitment is: **the signer exists and is registered**; wiring
the in-tree `aws` template to pass a service is a one-line template edit tracked as
TD-1 (it does not block shipping the signer for community/imported templates that
*do* specify a service).

---

## Part C — OpenAPI 3.1 importer

### C.1 Placement

New package **`internal/openapi`** (pure, dependency-light: parse + map; no proxy,
no vault). It exposes one primary function:

```go
// internal/openapi/import.go
package openapi

// ImportResult is a DRAFT ServiceTemplate plus provenance and review flags.
type ImportResult struct {
    Template services.ServiceTemplate // draft; Status/Meta marks it draft
    Warnings []string                 // unmapped schemes, ambiguous servers, etc.
    Source   string                   // spec URL or "file"
}

// FromSpec parses an OpenAPI 3.0/3.1 document (JSON or YAML) and maps it to a
// draft ServiceTemplate. It does NOT fetch; the caller supplies bytes (so the
// caller owns SSRF-safe fetching via the egress Guard).
func FromSpec(spec []byte, source string) (ImportResult, error)
```

Fetching is **separate** and SSRF-gated:

```go
// internal/openapi/fetch.go
// FetchSpec resolves specURL through the egress Guard (CheckHost) BEFORE dialing,
// enforces a size cap and content-type, and returns raw bytes for FromSpec.
func FetchSpec(ctx context.Context, g egress.Guard, specURL string) ([]byte, error)
```

### C.2 Exposure surface (one importer, two front doors — both thin)

- **Dashboard endpoint** (primary, human-in-the-loop fits the "draft, needs review"
  model): `POST /api/v1/templates/import` with body `{spec_url}` *or* a multipart
  file upload. Returns the draft `ServiceTemplate` JSON + warnings. The dashboard
  shows the draft in the existing template-review UI; the human edits and saves it
  into the community templates dir (Part D). This reuses the existing
  `/api/v1/templates*` route family (`internal/server/routes_*`).
- **MCP tool** (optional, deferred to Phase 4): `straylight_import_openapi` is a
  *control-plane* tool. It is **not** wired in the core Wave-2 phases because (a)
  importing is an operator action better suited to the dashboard's review flow, and
  (b) an MCP tool that fetches arbitrary URLs widens the SSRF surface to the AI.
  If added later it MUST route through the same `FetchSpec`+`Guard` and return only
  the draft (field shapes, never values).

**Recommendation: ship the dashboard endpoint; defer the MCP tool.** This keeps the
"draft, needs review" human gate central and keeps the AI off the import path.

### C.3 Mapping (OpenAPI 3.1 Security Scheme vocabulary → Straylight model)

PRODUCT-STRATEGY.md §3.1: adopt the OAS Security Scheme Object as the canonical
template language so any published spec imports mechanically.

| OpenAPI source | Straylight target | Notes |
|----------------|-------------------|-------|
| `servers[0].url` | `ServiceTemplate.Target` | First absolute server; templated server vars left as warnings |
| top-level `security` default scheme | `DefaultHeaders` (for fixed headers like content-type from a default `apiKey` header) | Best-effort |
| `securitySchemes[*]` type=`http` scheme=`bearer` | `AuthMethod{Injection: bearer_header}` | field `token` |
| `securitySchemes[*]` type=`http` scheme=`basic` | `AuthMethod{Injection: basic_auth}` | fields `username`,`password` |
| `securitySchemes[*]` type=`apiKey` in=`header` | `AuthMethod{Injection: custom_header, HeaderName: name}` | field `token` |
| `securitySchemes[*]` type=`apiKey` in=`query` | `AuthMethod{Injection: query_param, QueryParam: name}` | field `token` |
| `securitySchemes[*]` type=`apiKey` in=`cookie` | `AuthMethod{Injection: custom_auth, Custom.Headers:{Cookie:"name={{.token}}"}}` | OAS cookie apiKey → custom_auth Cookie header |
| `securitySchemes[*]` type=`oauth2` | `AuthMethod{Injection: oauth}` + an OAuth-provider table draft entry (Part D) from `flows.authorizationCode.{authorizationUrl,tokenUrl,scopes}` | PKCE inferred where present |
| `securitySchemes[*]` type=`openIdConnect` | `AuthMethod{Injection: oauth}` + warning to run `.well-known` discovery to fill URLs | discovery is a follow-up |
| `securitySchemes[*]` type=`mutualTLS` | **warning only**: emitted as a note; `mutual_tls` is DEFERRED (Part F) | not mapped to a working method |

Every imported template is marked **draft** and carries `Warnings`. Unmappable or
ambiguous schemes produce a warning, never a silent or wrong method. The output is
a starting point a human reviews and commits — exactly the "fastest path from ~16
templates to hundreds" lever (§3.1).

### C.4 Validation

`FromSpec` runs the produced draft through `services.ValidateTemplate` before
returning. A draft that cannot be made valid (e.g. no mappable auth method)
returns the partial template **plus** a blocking warning, so the human sees why.

---

## Part D — Runtime-loadable community template registry + OAuth-provider data table

### D.1 Template loader

The catalog moves from "compiled-only" to "compiled built-ins **+** runtime-loaded
community templates," with the loaded ones held to the same validation bar.

```go
// internal/services/loader.go (new)
// LoadCommunityTemplates reads every *.yaml/*.yml/*.json file in dir, unmarshals
// each into a ServiceTemplate, runs ValidateTemplate, and returns the valid ones.
// Invalid files are skipped with a per-file error (one bad file never aborts the
// rest, and never panics — unlike the compiled-in init() which may panic).
func LoadCommunityTemplates(dir string) (loaded []ServiceTemplate, errs []error)

// MergeTemplates overlays community templates onto built-ins by ID. Built-ins
// always win on ID collision (a community file cannot silently shadow a shipped
// template); a collision is reported as a warning.
func MergeTemplates(builtin, community []ServiceTemplate) (merged []ServiceTemplate, warnings []string)
```

- **Where it plugs in**: a new optional `templates_dir` in `config.Config`
  (default `<dataDir>/templates/`). `serve()` calls `LoadCommunityTemplates` once
  at startup and merges into the catalog the dashboard/MCP `services`/`templates`
  endpoints serve. Adding "Notion" is dropping `notion.yaml` in that dir and
  restarting — **a config drop, not Go** (§3.1, §3.2 "config PR, not Go").
- **Trust boundary**: loaded templates are validated by the *same*
  `ValidateTemplate`/`ValidateAuthMethod` (extended for `custom_auth`/`aws_sigv4`/
  `hmac_signature`). A loaded template can only declare capabilities a built-in
  could — it cannot inject arbitrary Go, only the existing closed set of injection
  types. **No code execution path is opened** by loading a template.
- **Fail-isolated**: unlike the compiled `init()` that `MustCompile`s all patterns
  (panic on any bad pattern), the loader compiles each file's patterns defensively
  and demotes a bad file to a skipped-with-error, so one community file can't take
  down startup.
- **Regex DoS guard**: loaded templates' `Field.Pattern`s are user-ish input;
  compile them but cap pattern length and reject obviously catastrophic constructs
  (tracked as a hardening item; v1 caps length + compiles, leaving full ReDoS
  analysis as TD-2).

### D.2 OAuth-provider data table

Today `internal/oauth/providers.go` `Providers` is a compiled `map[string]Provider`
with `AuthURL`, `TokenURL`, `DeviceCodeURL`, `DefaultScopes`, `ExtraAuthParams`,
`DefaultClientID`. Make it **data-loadable** and richer:

```go
// Provider gains (additive, all omitempty / backward-compatible):
type Provider struct {
    Name            string
    AuthURL         string
    TokenURL        string
    DeviceCodeURL   string
    DefaultScopes   []string
    ExtraAuthParams map[string]string
    DefaultClientID string
    // NEW (Wave 2):
    PKCE            bool   `yaml:"pkce"`             // require PKCE (S256) on the auth-code flow
    TokenParser     string `yaml:"token_parser"`     // expression to extract the access token
                                                      // from a non-standard token response
                                                      // (e.g. Slack: {{.authed_user.access_token}})
    DiscoveryURL    string `yaml:"discovery_url"`     // OIDC .well-known to auto-fill AuthURL/TokenURL
}

// internal/oauth/loader.go (new)
// LoadProviders reads provider YAML/JSON from dir and overlays onto the built-in
// Providers map (built-ins win on name collision, same rule as templates).
func LoadProviders(dir string) (map[string]Provider, []error)
```

- `PKCE` lets the auth-code flow opt into S256 challenge/verifier per provider
  (needed for Twitter/X, many modern providers) — data, not code.
- `TokenParser` is a **bounded template expression** (same safe-func allowlist as
  `custom_auth`) evaluated against the parsed token-response JSON to extract the
  access token / refresh token when a provider doesn't return the RFC 6749 shape
  (Slack's `authed_user.access_token` is the canonical example; the existing
  Google `verification_url` quirk shows why provider-specific parsing belongs in
  data). It does **not** execute arbitrary code — it is a field-extraction
  expression over already-parsed JSON.
- `DiscoveryURL` supports the §3.1 `openIdConnect` auto-fill: at provider load,
  fetch `.well-known/openid-configuration` (SSRF-gated via the egress `Guard`) and
  fill `AuthURL`/`TokenURL` if absent. Discovery is best-effort with a warning.
- Adding "Notion OAuth" or "Linear OAuth" becomes a provider-table entry (a config
  PR), not a Go change (§3.1).

---

## Part E — Phased implementation plan

Each phase is independently TDD-able, independently mergeable, and additive (no
phase changes existing behavior; each is revertible by removing its registration /
loader call).

| Phase | Deliverable | New surface | Depends on | Risk | Runtime change |
|-------|-------------|-------------|------------|------|----------------|
| **1** | `custom_auth` injector + `CustomAuthSpec` | `InjectionCustomAuth` enum, `InjectionConfig.Custom`, `CustomAuthInjector`, validation case | ADR-009 registry | Low (stateless, pure render) | none |
| **2** | `hmac_signature` signer | `InjectionHMACSignature` enum, `SignSpec.HMAC`, `HMACInjector`, validation | Phase-1 SignSpec scaffolding | Low–Med (signing math; test-vector-backed) | none |
| **3** | `aws_sigv4` signer (implements ADR-009 declared strategy) | `InjectionAWSSigV4` enum + `named_strategy` dual-register, `SignSpec.AWS`, `AWSSigV4Injector` | Phase-2 SignSpec | Med (canonical request correctness; STS token) | none |
| **4** | Community template loader + merge | `internal/services/loader.go`, `config.templates_dir`, `serve()` load+merge call | Phases 1–3 (so loaded templates can use new types) | Med (untrusted input; validation parity) | none (new optional dir) |
| **5** | OpenAPI importer (dashboard endpoint) | `internal/openapi` pkg, `FetchSpec`(egress-gated), `FromSpec`, `POST /api/v1/templates/import` | Phases 1–4 (maps to all injection types; output saved into loader dir) | Med (parsing breadth; SSRF on fetch) | none |
| **6** | OAuth-provider table loader + new fields | `Provider.{PKCE,TokenParser,DiscoveryURL}`, `internal/oauth/loader.go`, discovery fetch (egress-gated) | egress Guard | Med (PKCE flow change is behavioral) | none (new optional dir) |

**Ordering rationale**: injectors first (they are pure, lowest-risk, and the loader
+ importer must be able to *target* the new types before those features are useful);
loader before importer (the importer's output lands in the loader's dir); OAuth
table last (it touches the live auth-code flow and has the most behavioral surface).

### Recommended Phase-1 subset (most shippable, highest leverage)

**Ship Phase 1 (`custom_auth`) first, alone, as the minimum lovable Wave-2
increment.** Rationale:
- **Highest coverage per line of Go** of any item here: one stateless injector
  unlocks the entire bespoke-header/query/body long tail with zero per-service code
  (PRODUCT-STRATEGY.md §3.1 calls it "the highest-leverage coverage primitive after
  bearer/basic").
- **Lowest risk**: pure, stateless, no network, no new runtime/deploy change, no
  untrusted-input ingestion; it composes with the existing registry exactly as
  ADR-009 prescribed ("implement interface, register, add to template").
- **Unblocks everything after it**: the loader (Phase 4) and importer (Phase 5)
  become meaningfully more valuable once `custom_auth` exists, because most
  imported/community templates that aren't plain bearer/apiKey map to `custom_auth`.
- **Independently demonstrable**: add one built-in `custom_auth` template (or a
  test fixture) and show a dual-key API working end-to-end through the proxy with
  the credential never appearing — the §3.1 thesis made tangible without any of the
  heavier machinery.

Phases 2–3 (signers) are the natural fast-follow (they finish the ADR-009 "Phase 2"
debt and absorb S3-compat + webhook-signing APIs). Phases 4–6 (loader, importer,
OAuth table) convert breadth from "maintainer Go edits" to "config PRs" and are the
catalog-scale multiplier — sequence them after the injector primitives land.

---

## Part F — Explicit DEFER list (Wave-2.5) and contract sketch

These are **out of scope for this ADR's implementation** but sketched so the
seams exist and the deferral is deliberate, not an oversight.

### F.1 Non-HTTP protocol executors (SSH / gRPC / message queues)

PRODUCT-STRATEGY.md §3.1: "same credential model, different injection site." The
HTTP `Injector` interface (`Inject(*http.Request, fields, config)`) is
HTTP-specific. The non-HTTP analog is a broader executor contract:

```go
// SKETCH ONLY — Wave-2.5, not implemented here.
// A protocol executor takes a declarative AuthMethod + credential fields and a
// protocol-specific request descriptor, and performs the authenticated action.
type ProtocolExecutor interface {
    // Protocol returns the wire protocol this executor handles ("ssh","grpc","amqp").
    Protocol() string
    // Execute performs the action with credentials injected at the protocol's
    // natural site (SSH: short-lived cert via OpenBao ssh engine; gRPC: bearer in
    // the "authorization" metadata; MQ: SASL OAUTHBEARER/SCRAM). Returns a
    // sanitized result; the credential value never crosses back to the AI.
    Execute(ctx context.Context, am services.AuthMethod, fields map[string]string, req ProtocolRequest) (ProtocolResult, error)
}
```

This needs a registry mirroring `InjectorRegistry`, a result-sanitization path per
protocol, and (for SSH) integration with the OpenBao `ssh` engine for short-lived
certs. It is a larger executor-contract effort (closer in scope to ADR-013's
data-plane wiring) and is **deferred** to Wave-2.5.

### F.2 `mutual_tls`

OAS `mutualTLS` and OpenBao `pki` client certs. This is **transport-layer**, not
header injection: it requires presenting a client certificate at TLS handshake
time, which means a per-service `tls.Config` on the proxy's outbound dialer keyed
by the credential's client cert/key (ideally minted short-lived by OpenBao `pki`).
That touches the dialer and the egress path, not the `Injector` interface.
**Deferred**; the importer emits a *warning* (not a working method) for
`mutualTLS` schemes (Part C.3).

### F.3 OAuth discovery and PKCE behavioral depth

Phase 6 lands the *data* (`PKCE`, `DiscoveryURL`, `TokenParser`) and best-effort
discovery. Full `.well-known` discovery caching, dynamic client registration
(RFC 7591), and per-provider refresh-mutex semantics (PRODUCT-STRATEGY.md §3.2 —
Slack/Atlassian single-use refresh tokens) are §3.2 OIDC-passthrough Wave work, not
this ADR.

### F.4 `github_app_jwt` runtime injector

The *other* ADR-009 declared-but-missing strategy. Deferred from this ADR because
it is **not a stateless signer**: it mints a JWT *and* exchanges it for an
installation access token with a network round-trip and a cache (1-hour tokens,
§3.2). That belongs with the §3.2 token-exchange engine (RFC 8693 shape) and the
expiry-aware lease cache, not with the stateless `aws_sigv4`/`hmac_signature`
work here. Tracked as Wave-2.5 / §3.2.

---

## Consequences

**Positive**
- One stateless injector (`custom_auth`) collapses an open-ended set of future
  injector types into data; the bespoke long tail needs zero per-service Go.
- The two signers absorb S3-compatible stores (one signer, many providers) and
  webhook/request-signing APIs from data alone; ADR-009's `aws_sigv4` debt is paid.
- The loader + OAuth table turn catalog growth from "maintainer Go edits + release"
  into "human-reviewed config PRs," directly serving the §3.1 breadth-as-moat
  thesis vs. Infisical.
- The OpenAPI importer is the fastest path from ~16 templates to hundreds, with a
  human "draft, needs review" gate that keeps quality and keeps the AI off the
  import path.
- Every item is additive and registry-shaped (ADR-009): existing templates,
  injectors, and the legacy path are byte-for-byte unchanged.

**Negative**
- More injection types and a nested `SignSpec`/`CustomAuthSpec` enlarge
  `InjectionConfig`'s surface (mitigated by nesting + omitempty; existing configs
  serialize identically).
- Runtime-loaded templates and provider tables are new untrusted-input ingestion
  points; the security rests on validation parity (the same `ValidateTemplate`
  path) and the closed injection-type set — correct, but a place to be vigilant.
- The importer's mapping is best-effort; some specs produce thin or warning-laden
  drafts that need real human work (by design — "draft, needs review").

**Risks + mitigations**
- *Loaded template smuggles a capability* → validation parity (same path) + closed
  injection-type enum; a loaded template can only declare what a built-in could.
  A test asserts loaded templates and built-ins pass identical validation.
- *Signer correctness (wrong signature → silent auth-loop)* → both signers are
  test-vector-backed (AWS-documented SigV4 vectors; HMAC RFC vectors) with an
  injected clock for determinism; a wrong signature is a hard, audited failure.
- *SSRF via spec URL or discovery URL* → all remote fetches route through the
  existing egress `Guard.CheckHost` before dial, with size/content-type caps.
- *Template parse panic on bad community file* → the loader is fail-isolated
  (per-file error, never panic), unlike the compiled `init()`.
- *Regex DoS in loaded `Field.Pattern`* → length cap + defensive compile in v1
  (full ReDoS analysis tracked as TD-2).
- *PKCE rollout breaks an existing OAuth flow* → `PKCE` defaults false; only
  provider entries that opt in change behavior; covered by per-provider tests.

**Tech Debt**
- **TD-1**: the in-tree `aws` template still lacks a `Sign.AWS.Service`; the signer
  is registered and correct, but wiring the shipped `aws` template to pass a service
  is a follow-up template edit (community/imported templates that specify a service
  work immediately).
- **TD-2**: loaded `Field.Pattern` ReDoS hardening is length-cap-only in v1; full
  catastrophic-backtracking analysis is a follow-up.
- **TD-3**: OAuth `DiscoveryURL` is best-effort, no caching/refresh; full OIDC
  discovery + dynamic client registration is §3.2 Wave work.
- **TD-4**: `custom_auth` body injection supports `json`/`form` modes only; XML or
  multipart body signing is out of scope (warned, not supported).

---

## Part G — Test plan

**`internal/proxy` — `custom_auth` (Phase 1, load-bearing)**
- Renders headers from multiple credential fields (dual-key API): assert exact
  header values; assert the credential value never appears in any returned error.
- Renders query params; merges with existing query (no clobber) — same semantics
  as `QueryParamInjector`.
- Body injection: `json` mode merges into an existing JSON object body and resets
  `ContentLength`/`Body`; `form` mode produces correct urlencoded body.
- Fail-closed: missing field in a template, parse error, unknown safe-func → error
  wrapped with the offending key, **never the value**.
- Backward-compat: a config with `Custom == nil` is never reached by this injector;
  existing `custom_header`/`multi_header` tests still pass unchanged.

**`internal/proxy` — signers (Phases 2–3)**
- `aws_sigv4`: against AWS-documented SigV4 **test vectors** with a pinned clock —
  exact `Authorization`, `X-Amz-Date`; `session_token` → `X-Amz-Security-Token`;
  payload hash for a non-empty body; region from field overrides config; S3-compat
  target (R2/MinIO host) signs identically given the same region/service.
- `hmac_signature`: HMAC-SHA256/512 over a templated string with/without timestamp;
  hex vs base64 encoding; header prefix (GitHub `sha256=`); Slack-style
  `{{.timestamp}}.{{.body}}`; unknown algorithm/encoding → validation error.
- Both: body read + restore leaves `req.Body` re-readable downstream.

**`internal/services` — validation + loader (Phase 4)**
- `ValidateAuthMethod` accepts well-formed `custom_auth`/`aws_sigv4`/`hmac_signature`
  and rejects each malformed shape (missing `Custom`, missing `Sign.AWS.Service`,
  missing `HMAC` required fields) with a specific error.
- `LoadCommunityTemplates`: valid YAML/JSON loads; one invalid file is skipped with
  a per-file error while the rest load; **no panic** on a bad pattern (contrast the
  compiled `init()`); a loaded template passes the *same* `ValidateTemplate` as a
  built-in (parity test).
- `MergeTemplates`: built-in wins on ID collision; collision reported as a warning.

**`internal/openapi` — importer (Phase 5)**
- `FromSpec` maps each securityScheme type to the documented target (table C.3),
  including cookie-apiKey → `custom_auth` Cookie header and oauth2 → oauth + a
  provider-table draft; emits warnings for `mutualTLS`, templated server vars, and
  unmappable schemes; output passes `ValidateTemplate` or returns a blocking
  warning; every result is marked draft.
- `FetchSpec`: a spec URL resolving to a link-local/metadata IP is **denied by the
  egress Guard before dial**; oversized/wrong-content-type spec is rejected.

**`internal/oauth` — provider table (Phase 6)**
- `LoadProviders`: loads new entries; built-in wins on name collision.
- `PKCE=true` provider produces an S256 challenge/verifier on the auth-code flow;
  `PKCE=false` (default) flow is unchanged (regression guard).
- `TokenParser` extracts a token from a Slack-shaped (`authed_user.access_token`)
  response; standard RFC 6749 responses still parse with `TokenParser` empty.
- `DiscoveryURL` fills `AuthURL`/`TokenURL` from a `.well-known` doc; an SSRF-y
  discovery URL is denied by the Guard.

**`serve()` / integration (smoke)**
- Built-in catalog unchanged when `templates_dir` is empty/absent (backward-compat).
- Dropping a valid `custom_auth` community template into `templates_dir` makes it
  appear in `/api/v1/templates` and usable end-to-end through the proxy with the
  credential never appearing in the response (the §3.1 thesis, demonstrated).

---

## Validation Criteria

- One stateless `custom_auth` injector covers a dual-key + body-token API with
  **zero per-service Go** (Phase-1 acceptance).
- `aws_sigv4` matches AWS test vectors exactly and serves an S3-compatible host
  with only a region/service config change.
- A new service ("Notion") is added as a YAML drop in `templates_dir` with **no Go
  change** and passes the identical `ValidateTemplate` the built-ins pass.
- An OpenAPI 3.1 spec imports to a draft `ServiceTemplate` whose mappable schemes
  become working auth methods and whose unmappable schemes become warnings.
- No remote fetch (spec import or OIDC discovery) reaches a denied destination —
  the egress Guard gates every fetch.
- Existing templates, the 5 built-in injectors, `oauth`, and the legacy flat-`Inject`
  path are byte-for-byte unchanged (full existing suite green).
- **Reconsider when**: non-HTTP executors are needed (Wave-2.5 `ProtocolExecutor`),
  `mutual_tls` demand appears (dialer-level mTLS), or the §3.2 OIDC token-exchange
  engine lands (revisit `github_app_jwt` + refresh-mutex + discovery caching).

---

## Maintainer confirmation needed (before implementation)

1. **`templates_dir` location/default** — `<dataDir>/templates/` proposed; confirm
   (it must be a path the AI's `read_file`/`exec` tools do **not** treat specially,
   but loaded templates carry no secrets, so it is lower-sensitivity than openbao).
2. **Importer front door** — confirm dashboard `POST /api/v1/templates/import` only
   for Wave-2 (MCP `straylight_import_openapi` deferred to keep the AI off the
   fetch path). 
3. **`aws` template wiring (TD-1)** — confirm the in-tree `aws` template's
   `Sign.AWS.Service` addition is an acceptable follow-up template edit (vs.
   blocking the signer merge on it).
