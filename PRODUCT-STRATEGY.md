# Straylight-AI — Product Strategy & Roadmap

*Research-backed strategy for: maximum technology + AI-tool coverage · OIDC passthrough wherever possible · near-zero-touch onboarding (install → quick setup → one running container) · rigorous isolation of security-sensitive info from the AI CLI. Synthesized mid-2026.*

> **Provenance.** This document synthesizes a 7-dimension deep-research workflow (AI-CLI landscape, MCP protocol/auth, OIDC/secretless auth, competitive landscape, threat model/isolation, onboarding UX, coverage strategy), each followed by an adversarial fact-check against primary sources (RFCs, the MCP spec, CVE/NVD, OWASP, SANS, vendor docs). Where verification corrected the research, the corrected fact is used here and the correction is logged in §6. Code-level claims were cross-checked against this repo.

---

## 1. The thesis, in one sentence

**Straylight-AI is the MCP-spec-compliant, zero-knowledge credential broker for AI coding CLIs: one self-hosted container that lets Claude Code, Cursor, Windsurf, Copilot, Codex, Gemini, and every other MCP client do real work against your services — while the raw credential never enters the model's context, and every credential it can, it mints short-lived and federated instead of storing static.**

The market has converged in Straylight's favor on three fronts simultaneously:
- **MCP is now the universal integration substrate** — every major AI coding tool is an MCP client over stdio, so *one* server reaches the whole market.
- **The MCP authorization spec now *mandates* Straylight's exact pattern**: a server "**MUST NOT pass through the token it received from the MCP client**" and must hold its own downstream credentials. Straylight is effectively the reference implementation of that rule.
- **"Keyless/federated over static" went mainstream** (cloud Workload Identity Federation, OAuth 2.1, short-lived tokens), which is exactly the axis Straylight should own.

But the category is **no longer empty**: Infisical **Agent Vault** (launched Apr 2026) is a near-identical credential-injecting proxy. Differentiation must be concrete and earned (see §4).

---

## 2. The honest security claim (this governs everything else)

The single most important strategic discipline is **not overclaiming**, because the threat research is unambiguous: a credential proxy solves **one** of two threat classes.

- **(a) Exfiltration of the secret — genuinely solved.** The secret string never enters the AI's process/context/logs or the model provider's pipeline, so prompt injection cannot steal the credential itself. This is the defensible heart of "zero-knowledge."
- **(b) Misuse of the authority — NOT solved by hiding the secret.** A prompt-injected agent can still call `straylight_api_call` / `straylight_exec` / `straylight_db_query` with attacker-chosen arguments, and the proxy faithfully attaches the real credential. The agent becomes a **confused deputy** wielding the credential's *power* without seeing its *value*. By Simon Willison's "lethal trifecta" logic, hiding the secret removes **none** of the three legs (private-data access, untrusted-content exposure, exfiltration channel) — the proxy even *strengthens* leg 1 by lending authority.

**Use this claim (defensible):**
> *Straylight keeps your raw credentials out of the AI assistant's context, logs, and the model provider's pipeline — so prompt injection cannot exfiltrate the credential itself. When an agent is tricked into misusing the access a credential grants, Straylight bounds the damage with short-lived least-privilege credentials, a default-deny egress allowlist, per-tool scopes, human approval for high-impact actions, and tamper-evident audit. No credential proxy can stop a prompt-injected agent from attempting to use its authorized tools; Straylight makes that misuse scoped, bounded, and auditable.*

**Never say:** "keeps your secrets safe from prompt injection" · "the AI can't misuse your credentials" · "tamper-proof / fully isolated" · or imply response sanitization is a guarantee (real scanners miss 12–48% of secrets; one missed bearer token stays valid for its whole TTL).

This honesty is itself a **competitive asset** — Agent Vault and CyberArk Secretless both scope their claims narrowly; matching that candor (with an explicit "what this does NOT protect against" section) builds trust that overclaiming destroys.

---

## 3. The four outcomes — how we meet each

### 3.1 Universal technology + AI-tool coverage

**Reach every AI tool with one server.** MCP-over-stdio is the lowest common denominator; a single compliant stdio server (the existing host shim → container) reaches Claude Code, Cursor, Windsurf, GitHub Copilot, Codex, Gemini CLI, Amazon Q, Cline, Roo, Continue, Cody/Amp, Zed, and JetBrains AI. **Do not build per-tool integrations — build per-tool *config snippets*** (each tool's `mcp.json`/`config.toml`/`settings.json`) and ship them as copy-paste/auto-registered onboarding. Claude Code is the priority target because it uniquely adds **programmable hooks** (PreToolUse can block/rewrite input; PostToolUse can redact output) — a defense-in-depth surface no competitor matches.

**Reach every *service* with declarative breadth, not hand-coded integrations.** Straylight's `ServiceTemplate`/`AuthMethod`/`InjectionConfig` model + the ADR-009 strategy-injector registry is already the right architecture (the same pattern n8n, Vault, Steampipe, Zapier use for huge catalogs). The work is *extension*, not redesign:
- **Adopt OpenAPI 3.1 Security Scheme vocabulary** (`apiKey`/`http`/`oauth2`/`openIdConnect`/`mutualTLS`) as the canonical template language, so any published API spec imports mechanically. Add `cookie` apiKey location, `openIdConnect` discovery (auto-fill OAuth URLs from `.well-known`), and `mutualTLS`.
- **One generic `custom_auth` injector** (n8n-style `{headers, query, body}` templates rendered from credential fields) covers the entire long tail of bespoke API auth with zero new Go code. This is the highest-leverage coverage primitive after bearer/basic.
- **Two generic signers** absorb most non-token APIs: `aws_sigv4` (parameterized by region+service so it also serves R2/MinIO/Spaces, passes STS `session_token`) and a new `hmac_signature` (algorithm/encoding/header/timestamp/template — covers Stripe/GitHub/Slack/Shopify signing from data alone).
- **OpenAPI importer**: "paste a spec URL → draft a template" (servers→Target, securitySchemes→AuthMethods), marked "draft, needs review." Fastest path from ~16 templates to hundreds.
- **Runtime-loadable community template registry** (YAML/JSON validated through the existing `ValidateTemplate` path) + an OAuth-provider **data table** (authorize/token URLs, scopes, PKCE, token-parser expression) so adding "Notion OAuth" is a config PR, not Go.
- **Protocol executors beyond HTTP** behind one contract (the non-HTTP analog of the `Injector` interface): SQL (already), SSH (OpenBao `ssh` engine short-lived certs), gRPC (bearer in `authorization` metadata), message queues (SASL OAUTHBEARER/SCRAM). Same declarative `AuthMethod` feeds each — "same credential model, different injection site."

### 3.2 OIDC passthrough — keyless by default

The flagship finding, grounded in this repo's code: **all three cloud providers are still backed by long-lived static secrets in the vault**, and every one can be made keyless.
- `internal/cloud/aws.go` uses `AssumeRole` → **requires static admin AWS keys**. Add an **`AssumeRoleWithWebIdentity`** path fed by an OpenBao- or SPIRE-issued OIDC token → **zero stored AWS keys**.
- `internal/cloud/gcp.go` uses a **static service-account JSON key**. Replace with **GCP Workload Identity Federation** (`sts.googleapis.com/v1/token`, which *is* RFC 8693) + optional SA impersonation.
- `internal/cloud/azure.go` stores a **static `client_secret`**. Replace with an Entra **federated identity credential** + `jwt-bearer` client assertion → no secret stored.

All three reduce to one abstract op: *present identity proof → receive short-lived creds → cache to ~5 min pre-expiry → refresh.* Build a **generic token-exchange engine (RFC 8693 shape)** behind the existing `Injector` interface, with an identity-proof source (OpenBao identity token / SPIRE Workload API / GitHub OIDC in CI) → per-provider exchange adapters → expiry-aware cache (extend `internal/lease/`). Where possible, lean on **OpenBao's own secrets engines + plugin WIF** rather than reimplementing each STS — but note the constraint in §6 (OpenBao does **not** bundle the cloud engines).

**Provider migrations off static keys** (highest value first): GitHub PAT → **GitHub App 1-hour installation tokens** (store only the App private key); GitLab → rotation API / OAuth refresh; then validate the generic OIDC-passthrough path against **Okta/Auth0** (cleanest full OIDC providers). Keep **Stripe** on the scoped-restricted-key-in-vault model — it has no OIDC/device flow, and it's the canonical proof the vault-injection model matters *even when federation is impossible* (the AI still never sees the key).

**A mandatory engine detail:** Slack (single-use refresh token) and Atlassian (rotating RT) will **corrupt themselves under concurrent AI tool calls** without a **per-credential refresh mutex** that writes the rotated token back to OpenBao atomically. Required, not optional.

**MCP no-passthrough compliance:** whenever Straylight brokers a delegated/workload token, it must mint a **fresh, audience-scoped (`resource`/RFC 8707), downstream-specific** token — never relay an inbound token. This is exactly the spec mandate and a marketable differentiator.

### 3.3 Near-zero-touch onboarding — one container

North star: `npx straylight-ai` → image pulls → container starts → vault auto-unseals → MCP server auto-registers across every detected AI CLI → dashboard opens → user adds one service → first credential-isolated call. **Everything between `npx` and "add one service" is invisible.** Only two human decisions: telemetry consent, and which service to add first.

The ideal first-run flow:
1. **Preflight** — verify Docker is running; if not, one actionable line and exit.
2. **Pull + start** — stream the one-time image pull; create a named volume (`straylight-vault-data`); bind **localhost only** (`127.0.0.1:9470` + internal API).
3. **Invisible vault unseal** — this is *static auto-unseal*, not dev mode. Init OpenBao on first run; store the unseal key in the **OS keychain or a `0600` host file outside the data volume and outside any path the AI's `read_file`/`exec`/`db_query` tools can reach.** (If the model can read the unseal key, the entire zero-knowledge claim dies.) The OpenBao port is never exposed.
4. **Readiness gate** — *container up AND vault unsealed AND HTTP API answering*, with bounded backoff; surfaced three ways (Docker `HEALTHCHECK`, dashboard badge, the `straylight_check` MCP tool).
5. **Auto-register across detected CLIs** — `claude mcp add --scope user …` for Claude Code; **atomic read-merge-write** of the `straylight` stdio entry for the rest (preserve other servers; temp-file+rename). **Special-case Windsurf**, whose HTTP config uses `serverUrl`, not `url`. Idempotent on re-run; print "Registered with … / Skipped …".
6. **Success block + auto-open dashboard** (Supabase-style: URL, registered CLIs, next step; printed URL fallback).
7. **First-run wizard (2 decisions):** opt-in telemetry (with "show me what you'd send", honor `DO_NOT_TRACK`, off in CI — *do not repeat the GitHub-CLI opt-out backlash*); add first service (template picker ordered by friction: **OAuth button** using the dashboard `:9470` as the fixed redirect → **device flow** (no loopback port) → **paste-key** with a deep link to the service's key page).
8. **The "aha" test call** — immediately run a real `api_call` through Straylight and show the response with *"notice the token never appeared."* This single demonstration is the entire thesis made tangible.

**Container self-update must be transactional, never background auto-replace** (a vault-holding container is the one case the container-update literature says to *exclude* from auto-update): seal → snapshot the volume → pull → recreate same volume → re-unseal → readiness check → **roll back on failure**. Surface updates as a non-blocking dashboard nag.

### 3.4 Rigorous isolation — and the controls its limits demand

Because §2 establishes that hiding the secret only addresses exfiltration, *credible isolation requires controls that touch **misuse***. These are net-new capabilities, in rough priority:
- **A policy engine that gates tool calls on arguments and destinations**, not merely on "does a credential exist." This is the only layer that touches threat class (b).
- **Default-deny egress allowlist with SSRF blocking** (block `169.254.169.254`, link-local, private ranges except where intended). Highest-leverage single control — it attacks the trifecta's exfiltration leg. (Document the CamoLeak caveat: an allowlist trusting a broad domain like `*.githubusercontent.com` can still be abused *through* an approved destination.)
- **Short-lived, least-privilege dynamic credentials by default** (OpenBao dynamic DB engine — which Straylight already uses — + AWS STS session policies). Tight **scope** bounds misuse; TTL only bounds the window.
- **Per-tool scopes & allow/deny lists** (Pomerium-style matching) for the 7 MCP tools.
- **Approval tiers / human-in-the-loop** for high-impact/irreversible actions, with argument previews.
- **Tamper-evident, hash-chained audit** (identity, tool, args, destination, decision) — the proxy, not the AI, is the source of truth for what happened.
- **Response sanitization on every path** (HTTP/stdout/stderr/DB) with base64/hex/URL decoding + entropy fallback — positioned as *defense-in-depth, never a guarantee.*

---

## 4. Competitive positioning

**Direct competitor:** Infisical **Agent Vault** (open-core, launched Apr 22 2026, research preview) — same TLS-intercepting credential-injecting proxy concept, incl. Claude Code. Its own docs call setup "a bit clunky" and it **lacks** OAuth/OIDC passthrough, cloud STS, dynamic DB creds in the broker, and breadth of templates. **Beat it on exactly those:** breadth of built-in templates, OAuth auth-code + device flow + AWS STS/GCP/Azure passthrough, integrated file firewall/response sanitizer, and genuinely zero-touch single-container onboarding.

**The sharpest one-line differentiator** — draw the taxonomy explicitly in docs:
> *Every reference-injection tool (1Password `op://`, Infisical/Doppler `run`, Vault Agent) still places the plaintext secret in the agent's process. Straylight — like CyberArk Secretless and Agent Vault — never does.* (Nuance to keep honest: 1Password's newer Environments/Runlayer integration also claims zero-context-window; the gap is narrowing, so lead with breadth + OIDC + zero-touch, not the isolation concept alone.)

**Adjacent, not competitive (absorb ideas, don't fight):** AI inference gateways (LiteLLM, Portkey — *now acquired by Palo Alto Networks*, Apr 2026) own model-traffic redaction; position Straylight as the **tool-call/egress complement** ("chain Straylight for tool creds + LiteLLM/Portkey for model traffic"). Identity-aware proxies (Teleport/Pomerium/Boundary) validate the short-lived-cert model and offer per-tool policy patterns to copy.

**The cautionary tale (and a positioning weapon):** the **March 2026 LiteLLM/"TeamPCP" supply-chain breach** shows a centralized broker holding long-lived broad-scope creds is a crown-jewel target. This is *double-edged*: it argues **for** short-lived/federated tokens **and** is a direct caution against Straylight's own design (single container + embedded long-lived vault = the same aggregation target). The rebuttal must be substantive: minimize standing secrets (prefer OIDC/STS/dynamic), supply-chain-harden the image (SBOM, signed releases, pinned deps, Trivy), rootless/restricted-network container, and a tamper-evident audit trail.

---

## 5. Consolidated roadmap

Sequenced across all seven dimensions, deduplicated. Each wave is shippable and independently valuable.

**Wave 0 — Make the current claim honest & safe (security correctness).** *Required before any "isolation" marketing.*
- Default-deny **egress allowlist + SSRF block** (`169.254.169.254`, private/link-local ranges).
- Audit that the **unseal key / root token / recovery keys are unreachable** by any MCP tool path; enforce localhost-only binding everywhere; never expose the OpenBao port.
- **Honest threat-model docs** with an explicit "what this does NOT protect against" section; adopt trifecta / Rule-of-Two framing.
- **Policy engine v1**: gate each tool call on method/path/host (per-service allowlist) — the minimal control that touches *misuse*.
- Harden the **response sanitizer** (decode base64/hex/url, entropy fallback) as defense-in-depth.

**Wave 1 — Keyless-by-default (the OIDC flagship).**
- Generic **RFC 8693 token-exchange engine** behind the `Injector` interface, with expiry-aware caching in `internal/lease/`.
- **AWS `AssumeRoleWithWebIdentity`**, **GCP WIF**, **Azure FIC** — eliminate the three static cloud secrets in `internal/cloud/*.go`.
- Stand up **OpenBao identity-token issuer** as the trust root (`.well-known/openid-configuration` + JWKS); add SPIRE-consumer support for fleets.
- **Per-credential refresh mutex** (Slack/Atlassian rotation safety) with atomic write-back.
- **GitHub App 1-hour installation tokens**; validate the OIDC-passthrough path on **Okta/Auth0**.

**Wave 2 — Coverage at scale.**
- Generic **`custom_auth`** injector (n8n-style headers/qs/body).
- Implement the declared-but-missing **`aws_sigv4`** and **`github_app_jwt`** strategies (ADR-009 Phase 2); add **`hmac_signature`** and **`mutual_tls`** (OpenBao `pki` client certs).
- **OpenAPI 3.1 importer** → draft templates; adopt OpenAPI security-scheme vocabulary.
- **Runtime-loadable community template registry** + OAuth-provider data table.
- **Protocol executors**: SSH (OpenBao `ssh` certs), gRPC (bearer metadata), message queues.
- Code hygiene: **de-duplicate the two `aws` templates**; **wire the unwired executors** (`db_query`/`read_file`/`exec`) so the advertised tools actually run (see §7).

**Wave 3 — Multi-client & team (remote MCP).**
- Spec-compliant **Streamable HTTP MCP mode**: publish RFC 9728 Protected Resource Metadata, require RFC 8707 `resource` + PKCE, **validate token audience**, never pass tokens through. Unlocks per-user OIDC identity + multi-client (Claude Code, Claude API connector, Cursor, VS Code) that stdio can't give.
- **URL-mode elicitation** (MCP 2025-11-25) for credential onboarding — server drives the OAuth/key-entry flow out-of-band so the secret never reaches the LLM.
- **Confused-deputy mitigations**: per-client consent for dynamically registered clients, exact `redirect_uri` matching, hardened state/cookies.
- **Approval tiers** + **hash-chained audit**.

**Wave 0.5 — Onboarding polish (parallelizable with Wave 0–1).**
- One-command `npx` flow (preflight → pull → unseal → auto-register → dashboard → "aha" test call).
- **Idempotent multi-CLI auto-registration** (Windsurf `serverUrl` special-case; `register`/`unregister` subcommands).
- **Opt-in telemetry** with payload preview + `DO_NOT_TRACK`.
- **Transactional, rollback-capable container update** (no background auto-replace).

---

## 6. Accuracy guardrails (verification corrections to not get wrong)

These are the things the raw research got wrong and the adversarial pass corrected — **do not** propagate the originals:
- **OpenBao does NOT bundle the AWS/GCP/Azure secrets engines** (they were removed at the fork; OpenBao core ships ~11 engines: kv, database, pki, transit, ssh, totp, ldap, kubernetes, rabbitmq, cubbyhole, identity — cloud engines are *external plugins* in `openbao/openbao-plugins`). So Straylight's cloud creds are **its own code** (`internal/cloud`), **not** "free from OpenBao." The "Vault-grade for free" framing holds only for DB/transit/identity/PKI/SSH/OIDC. (Confirmed in this repo: dynamic DB creds *do* use OpenBao's database engine; cloud is self-implemented.)
- **Isolation ≠ prompt-injection immunity.** Keep §2's exfiltration-vs-misuse distinction front and center; the "credential proxy" concept is **not novel** (Agent Vault, Secretless, 1Password+Runlayer, MintMCP) — differentiate on single-container self-hosted + breadth + OIDC + honesty, not the concept.
- **OIDC passthrough is not universal.** Stripe, Slack, and Atlassian have **no device flow**; Stripe has no OIDC at all. Frame passthrough as "where the provider supports it."
- **The MCP RFC stack is version-mixed.** The *stable* 2025-06-18 spec mandates OAuth 2.1 + PKCE + RFC 9728 + RFC 8414 + RFC 8707; **DCR (RFC 7591) is still "SHOULD," not deprecated**, and Client ID Metadata Documents + RFC 9207 appear only in the *draft*. Implement to 2025-06-18 (latest published is 2025-11-25; a 2026-07-28 RC exists). **OAuth 2.1 is itself still an IETF draft** — pin to the rev the MCP spec references.
- **"Auto-revoked" creds have caveats:** revocation depends on correctly configured OpenBao `revocation_statements`; STS tokens stay valid bearer creds for their full 15 min–12 h TTL — these shrink blast radius, they don't remove the need for sanitization.
- **Sourcing flags:** the GitHub-MCP/Claude-Code adoption "most-loved" percentages were mis-attributed (Pragmatic Engineer, not JetBrains); CamoLeak→CVE-2025-59145 is reported by all security sources but one NVD fetch returned an unrelated record — re-confirm before formal citation. Aider's MCP support is via community bridges, not native.

---

## 7. Quick wins already visible in the codebase

- **Native (non-container) execution** — *fixed this session* (bao path resolution + OpenBao config auto-generation; merged in PR #6). Native dev now works on Apple Silicon.
- **Duplicate `aws` template** in `internal/services/auth_methods.go` (two entries with `id:"aws"`) — independently flagged by two research agents; de-duplicate.
- **Declared-but-unimplemented strategies:** `aws_sigv4` and `github_app_jwt` are referenced in templates but listed as ADR-009 Phase-2 / unimplemented.
- **Partial MCP wiring (from CLAUDE.md):** in the shipped binary, `straylight_db_query` / `straylight_read_file` / `straylight_exec` run with nil executors (stub/error) and `/api/v1/databases/*` + `/api/v1/audit/*` return 501. These advertised capabilities are implemented and tested but **not wired into `serve`** — wiring them is a prerequisite for the coverage and isolation stories above.

---

## 8. Open questions for you

1. **Identity root model.** Does Straylight issue its own OIDC identity (embedded OpenBao as trust root, must be network-reachable for clouds to federate) or consume SPIRE in fleet deployments? This decides the Wave-1 token-exchange identity source.
2. **Per-AI-session vs per-deployment identity.** Per-session scoped JWTs enable per-session audit + revocation (aligns with zero-knowledge) but multiply token-exchange volume. Which?
3. **Remote MCP mode timing.** It unlocks multi-client + per-user OIDC but adds the full RFC 9728/8707/consent surface and confused-deputy obligations. Wave 3, or sooner for a team SKU?
4. **How far into "agent firewall."** Egress allowlist + policy engine are required for an honest isolation claim; full DLP/anomaly-detection/signed-receipts is a larger bet. Where's the line for v1?
5. **Telemetry & hosting posture** for a zero-knowledge product (opt-in only is assumed here).

---

### Appendix — primary sources by dimension
- **MCP spec & auth:** modelcontextprotocol.io (basic/authorization, security_best_practices, transports); RFCs 9728, 8707, 8414, 8693, 8628; OAuth 2.1 draft.
- **OIDC/keyless:** AWS STS `AssumeRoleWithWebIdentity` & Roles Anywhere, GCP Workload Identity Federation, Microsoft Entra WIF/OBO, GitHub/GitLab/Google/Okta/Auth0/Slack/Atlassian/Stripe developer docs, SPIFFE/SPIRE, OpenBao identity-token + Vault secrets-engine docs.
- **Threat model:** Simon Willison (lethal trifecta; Nov-2025 prompt-injection papers), Meta "Agents Rule of Two", OWASP (LLM Top-10, MCP Tool Poisoning, AI Agent Security Cheat Sheet), SANS (credential broker), CSA (confused deputy), Invariant Labs, Check Point, Legit Security (CamoLeak), Formal.ai (proxy pattern), ESEM-2023 secret-scanner study; CVE-2025-59536, CVE-2026-21852, CVE-2025-54135/54136, CVE-2025-59145.
- **Competitive:** Infisical Agent Vault, CyberArk Secretless Broker, HashiCorp Vault/OpenBao/Boundary, 1Password, Doppler, Teleport, Pomerium, Docker MCP Gateway, LiteLLM, Portkey, Pipelock.
- **Onboarding:** Tailscale, ngrok, Stripe CLI, Doppler, Ollama, 1Password CLI, Supabase CLI, OpenBao seal/unseal + static auto-unseal, Watchtower (container-update caveats), CLI-telemetry best-practice writeups, Claude Code MCP docs.
- **Coverage:** OpenAPI 3.1 Security Scheme Object, n8n custom auth, AWS SigV4, HMAC signing, HashiCorp Vault plugin engines, Steampipe plugin model, Raycast/Zapier provider tables, OpenAPI→MCP generators.
