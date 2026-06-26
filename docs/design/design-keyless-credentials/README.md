# Design Package: Wave-1 Keyless-by-Default Federated Credentials

**Date**: 2026-06-26
**Author**: Architect Agent
**Status**: Proposed
**Issue**: #10 · **Branch**: wave1/keyless-oidc

## Summary

Convert Straylight's three cloud providers off long-lived **static** secrets
(`internal/cloud/aws.go` admin keys, `gcp.go` SA-JSON, `azure.go` client_secret)
to short-lived **federated** credentials, powered by a generic RFC 8693
token-exchange engine and rooted in OpenBao's identity-token issuer. This is the
federation complement to Wave-0: ADR-010 bounds the network, ADR-011 bounds the
request shape, ADR-012 removes the standing secret so a compromised broker leaks
TTL-bounded tokens, not admin keys. Keyless is **opt-in/auto where config makes it
unambiguous**; every existing static-credential service keeps working unchanged.

## Key Decisions

| Decision | ADR | Choice |
|----------|-----|--------|
| Engine placement | ADR-012 §A | New `internal/tokenexchange` package: `IdentitySource` → per-provider `ExchangeAdapter` → expiry-aware cache w/ proactive refresh (mirrors `internal/lease`). Cloud `Provider`s branch to it; `proxy.Injector` reuses it. NOT OpenBao cloud engines (not bundled — §6). |
| Identity trust root | ADR-012 §B | **Default: OpenBao identity-token issuer (B1).** SPIRE (B2, fleets) and CI-OIDC (B3) are pluggable alternatives. **Maintainer must confirm — see below.** |
| Session granularity | ADR-012 §C | **Per-deployment (C1) for Wave 1**; interfaces shaped to add per-session (C2) later without call-site changes. |
| Self-rotating tokens | ADR-012 | Per-credential `RefreshGuard` (keyed mutex + single-flight) with atomic write-back to OpenBao (Slack single-use RT, Atlassian rotating RT). |
| GitHub App | ADR-012 | Store **only** the App private key; mint 1-hour installation tokens via the engine; no PAT stored. |
| No-passthrough | ADR-012 | Audience is required; engine has no API to relay an inbound token — structural compliance. |

## Identity-Root Decision the Maintainer Must Confirm

**Recommended:** OpenBao identity-token issuer as trust root, per-deployment
identity (B1 + C1). The load-bearing caveat: clouds must fetch the issuer's JWKS,
but the flagship container binds localhost-only. Confirm one of: (1) a public
JWKS/discovery-only endpoint; (2) pre-registered static JWKS per cloud; or (3)
gate cloud keyless to deployments with a reachable issuer and ship GitHub-App
keyless (no external issuer) on the single container first. Phase 1 (engine) and
the GitHub-App path do not depend on this; cloud keyless (Phase 2/3) does.

## Scope

**In scope (Wave 1)**
- `internal/tokenexchange`: `IdentitySource`, `ExchangeAdapter`, `Engine` (cache +
  proactive refresh), `RefreshGuard`.
- `vault.Client` identity-issuer methods (`ConfigureIdentityIssuer`,
  `CreateIdentityRole`, `GenerateIdentityToken`) + `openbaoSource`.
- AWS `AssumeRoleWithWebIdentity` (extend `STSClient`); GCP WIF; Azure FIC +
  `jwt-bearer` — each branching the existing provider, static path preserved.
- Additive config schema (`web_identity`/`workload_identity`/`federated_identity`
  blocks) + validation; no change to existing static fields.
- `RefreshGuard` for Slack/Atlassian; `github_app` adapter + `FederatedBearerInjector`.
- New audit event `token_minted` (provider/audience/expiry, no token material).

**Out of scope (Wave 1, flagged)**
- Per-session identity (C2); GCP SA impersonation (second hop); generic OIDC-HTTP
  injector + Okta/Auth0 validation; SPIRE `IdentitySource` (B2); factoring the
  shared expiry-cache out of `internal/lease`.

## Phased Plan

1. **Engine + OpenBao issuer** (no provider change; fully faked tests).
2. **AWS flagship** — `AssumeRoleWithWebIdentity`, zero stored admin keys.
3. **GCP WIF + Azure FIC** (static paths preserved).
4. **Refresh-mutex + GitHub App** (atomic write-back; App private key only).

## Design Artifacts

```
docs/design/design-keyless-credentials/
  README.md                                       # This file
  adr/
    ADR-012-keyless-federated-credentials.md      # Engine, providers, trust root, refresh-mutex, GitHub App, phases, tests
```

## Success Metrics

- A keyless AWS service runs `straylight_exec` with **zero static AWS keys in
  vault** (verified at the service's vault path).
- Static-config paths remain byte-identical (golden env-var tests) for all three
  providers.
- Concurrent tool calls on a rotating credential never corrupt it (single-flight +
  atomic write-back, proven under `-race`).
- No engine path relays an inbound/identity token as a downstream credential.
- Issuer discovery + JWKS reachable at startup before keyless is advertised;
  otherwise static path + clear diagnostic.
```
