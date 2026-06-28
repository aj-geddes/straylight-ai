# Design Package: Coverage at Scale (Issue #11, Wave 2)

**Date**: 2026-06-28
**Author**: Architect Agent
**Status**: Proposed
**Builds on**: ADR-009 (injection-strategy dispatch — `Injector` interface + registry)
**Relates to**: PRODUCT-STRATEGY.md §3.1 (universal coverage)

## Summary

Extend the existing declarative `ServiceTemplate` / `AuthMethod` / `InjectionConfig`
+ strategy-injector model (ADR-009) so Straylight covers as many technologies/APIs
as possible with minimal per-service Go. Four additive primitives: a data-driven
`custom_auth` injector (n8n-style `{headers, query, body}` from credential fields —
the bespoke long tail with zero per-service Go); two stateless generic signers
(`aws_sigv4`, parameterized region+service so it also serves R2/MinIO/Spaces and
passes STS session tokens — this implements one of ADR-009's declared-but-missing
strategies; and a new `hmac_signature` covering Stripe/GitHub/Slack-style signing
from data); an OpenAPI 3.1 importer ("paste a spec → draft template", servers→Target,
securitySchemes→AuthMethods, marked "draft, needs review"); and a runtime-loadable
community template registry + data-driven OAuth-provider table (adding a service or
provider becomes a config PR, not Go). Everything is additive — existing templates,
the 5 built-in injectors, `oauth`, and the legacy path are byte-for-byte unchanged.

## Key Decisions

| Decision | ADR | Choice |
|----------|-----|--------|
| Bespoke long-tail auth | ADR-014 §A | One stateless data-driven `custom_auth` injector (`InjectionConfig.Custom` = `{Headers, Query, Body, BodyMode}` rendered via a safe-func text/template over the credential field map). Highest coverage per line of Go; zero per-service code. |
| Generic signers | ADR-014 §B | Stateless `aws_sigv4` (region+service param, STS session token; implements ADR-009 declared strategy) and new `hmac_signature` (algorithm/encoding/header/prefix/timestamp/signed-string template), config nested under `InjectionConfig.Sign` to avoid bloat; injected clock for deterministic test vectors. |
| OpenAPI importer | ADR-014 §C | New pure `internal/openapi` pkg (`FromSpec` map + SSRF-gated `FetchSpec` via egress Guard); exposed as dashboard `POST /api/v1/templates/import`; MCP tool deferred to keep the AI off the fetch path. Output marked "draft, needs review", runs `ValidateTemplate`. |
| Community catalog + OAuth table | ADR-014 §D | `LoadCommunityTemplates(dir)` + `MergeTemplates` (built-in wins on collision, fail-isolated per file, same `ValidateTemplate` parity); `config.templates_dir` (default `<dataDir>/templates/`). OAuth `Provider` gains data fields `PKCE`, `TokenParser`, `DiscoveryURL` + `LoadProviders(dir)`. |
| Phasing | ADR-014 §E | 1 `custom_auth` → 2 `hmac_signature` → 3 `aws_sigv4` → 4 loader → 5 importer → 6 OAuth table. Each independently TDD-able, mergeable, additive, revertible. |
| Explicit defer (Wave-2.5) | ADR-014 §F | Non-HTTP executors (SSH/gRPC/MQ) behind a sketched `ProtocolExecutor` contract; `mutual_tls` (transport-layer, dialer mTLS); `github_app_jwt` (stateful token exchange → §3.2 engine). |

## Recommended Phase-1 (most shippable) subset

**Ship the `custom_auth` injector first, alone.** It is the highest coverage per
line of Go (one stateless injector unlocks the entire bespoke header/query/body long
tail with zero per-service code), the lowest risk (pure, no network, no runtime
change, no untrusted input), it slots into the ADR-009 registry exactly as that ADR
prescribed ("implement interface, register, add to template"), and it makes the
later loader/importer phases materially more valuable (most imported/community
templates that aren't plain bearer/apiKey map to `custom_auth`). Demonstrate it with
one `custom_auth` template driving a dual-key API end-to-end through the proxy with
the credential never appearing — the §3.1 thesis made tangible without the heavier
machinery. Signers (Phases 2–3) are the natural fast-follow; loader/importer/OAuth
table (Phases 4–6) are the catalog-scale multiplier.

## Backward compatibility

Strictly additive: new closed injection-type enum values, new `omitempty`
`InjectionConfig.Custom`/`Sign` fields (nil for every existing config), a new loader
called only when `templates_dir` is set, a new importer package, new `omitempty`
OAuth `Provider` fields. The existing `aws` template keeps `named_strategy` +
`aws_sigv4` (the signer is dual-registered under both the new type name and the
legacy strategy name). No existing behavior changes.

## Flagged for maintainer confirmation

- `templates_dir` default (`<dataDir>/templates/`).
- Importer front door = dashboard endpoint only for Wave 2 (MCP tool deferred).
- In-tree `aws` template gaining `Sign.AWS.Service` as a follow-up edit (TD-1) vs.
  blocking the signer merge.

## Artifacts

```
docs/design/design-coverage-at-scale/
  README.md                              # This file
  adr/
    ADR-014-coverage-at-scale.md         # custom_auth + signers + importer + loader/OAuth table,
                                         # defer list, phased plan, test plan
```
