# Design Package: Wave-0 Egress Guard + Policy Engine

**Date**: 2026-06-25
**Author**: Architect Agent
**Status**: Proposed

## Summary

Two Wave-0 security controls that make Straylight's honest claim
(`PRODUCT-STRATEGY.md` §2: the proxy stops credential *exfiltration*, not
*misuse*) credible by bounding *misuse*. They are independent and composable:
a **network-layer** egress guard and a **request-shape** policy gate, both
default-deny where configured, both evaluated **before any credential is
injected**, both reusing the repo's strategy-registry / consumer-interface
idioms and the existing per-service config + audit conventions.

## Key Decisions

| Decision | ADR | Choice |
|----------|-----|--------|
| Default-deny egress allowlist + SSRF guard | ADR-010 | One `egress.Guard`; proxy enforces on the **resolved IP inside a custom `DialContext`** (defeats DNS rebinding + redirects); exec path gets a best-effort pre-flight host check; container-level egress deferred |
| Per-service policy engine v1 | ADR-011 | `policy.Engine` evaluated at the `dispatchToolCall` seam (uniform per-tool gate) **and** at `HandleAPICall` before injection (authoritative re-check); gate on method / path-prefix / host |

## Scope

**In scope (v1)**
- `internal/egress` package: SSRF denylist (metadata, link-local, RFC1918,
  CGNAT, ULA, loopback, unspecified, IPv4-mapped-IPv6) + per-service allowlist.
- `internal/policy` package: per-service method / path-prefix / host gate.
- Hook points: proxy `http.Transport.DialContext` (IP re-check) + `HandleAPICall`
  (policy pre-injection); `cmdwrap.Wrapper.Execute` (egress pre-flight);
  `mcp.dispatchToolCall` (policy per-tool gate).
- `Service` + `config.yaml` schema additions (`Egress`, `Policy`), validated and
  persisted via the existing metadata path.
- `serve()` wiring (one guard, one engine, injected into both consumers).
- New audit events: `egress_denied`, `policy_denied`.

**Out of scope (v1, tracked)**
- Container/kernel-level egress for child-process sockets (nft/eBPF) — exec
  residual-risk paydown (issue #9).
- Glob/regex path matching, per-identity or per-time policy rules, external
  policy engine (OPA/Rego).

## Residual Risk (ships in docs, per §2)

An egress allowlist does **not** stop exfiltration **through** an approved host
(**CamoLeak**): a broad allowlisted destination (`*.githubusercontent.com`, a
webhook catch-all, a path-echoing endpoint) can still be an exfil channel. The
exec path's socket-level egress is unmediated in v1. Neither control makes a
confused-deputy agent benign — within the allowed surface, misuse is still
possible. Both controls make misuse **scoped, bounded, and auditable**; keep
allowlists narrow, prefer exact hosts over wildcards, and pair with the response
sanitizer (defense-in-depth, never a guarantee) and short-lived least-privilege
credentials.

## Design Artifacts

```
docs/design/design-egress-policy/
  README.md                         # This file
  adr/
    ADR-010-egress-guard-ssrf.md    # Egress guard + SSRF (network layer)
    ADR-011-policy-engine-v1.md     # Per-service tool-call policy (request shape)
```

## Success Metrics

- Every SSRF denylist class is blocked by default on the proxy path, on the IP
  actually dialed (DNS-rebinding + redirect covered).
- A denied tool call reaches neither the injector nor the upstream client.
- Existing services (no `egress`/`policy` config) behave exactly as today.
- SSRF and policy denials are tamper-evidently audited without leaking creds.
