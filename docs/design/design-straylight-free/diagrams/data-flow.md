# Data Flow Diagrams -- Straylight-AI Personal (Free)

## Flow 1: Agent Makes an Authenticated API Call

This is the primary use case. An AI agent (Claude Code) calls a service
(e.g., Stripe) through Straylight-AI without ever seeing the API key.

```
Claude Code          straylight-mcp      Straylight Core      OpenBao         Stripe API
(MCP Client)         (host binary)       (container:9470)     (internal:9443) (external)
    |                     |                    |                   |               |
    |  tool/call          |                    |                   |               |
    |  straylight_api_call|                    |                   |               |
    |  service: stripe    |                    |                   |               |
    |  method: GET        |                    |                   |               |
    |  path: /v1/balance  |                    |                   |               |
    |-------------------->|                    |                   |               |
    |     (stdin)         |                    |                   |               |
    |                     |  POST /api/v1/mcp/ |                   |               |
    |                     |  tool-call         |                   |               |
    |                     |------------------->|                   |               |
    |                     |   (HTTP)           |                   |               |
    |                     |                    |  GET secret/data/ |               |
    |                     |                    |  services/stripe/ |               |
    |                     |                    |  credential       |               |
    |                     |                    |------------------>|               |
    |                     |                    |                   |               |
    |                     |                    |<------------------|               |
    |                     |                    |  { api_key: sk_.. }               |
    |                     |                    |                   |               |
    |                     |                    |  GET /v1/balance  |               |
    |                     |                    |  Authorization:   |               |
    |                     |                    |  Bearer sk_...    |               |
    |                     |                    |---------------------------------->|
    |                     |                    |                   |               |
    |                     |                    |<----------------------------------|
    |                     |                    |  { balance: ... } |               |
    |                     |                    |                   |               |
    |                     |                    |  [sanitize output]|               |
    |                     |                    |  (strip any       |               |
    |                     |                    |   credential      |               |
    |                     |                    |   patterns)       |               |
    |                     |                    |                   |               |
    |                     |<-------------------|                   |               |
    |                     |  { sanitized JSON }|                   |               |
    |                     |                    |                   |               |
    |<--------------------|                    |                   |               |
    |  MCP tool result    |                    |                   |               |
    |  (clean JSON)       |                    |                   |               |
```

**Key security properties:**
- The API key (`sk_...`) exists only in container memory during the request
- The key travels: OpenBao -> Go process memory -> HTTP request to Stripe
- The key NEVER appears in: MCP stdio, agent context, logs, or tool responses
- Output sanitizer catches any credential patterns in the Stripe response

## Flow 2: Agent Runs a Credentialed Command

```
Claude Code          straylight-mcp      Straylight Core      OpenBao
(MCP Client)         (host binary)       (container:9470)     (internal:9443)
    |                     |                    |                   |
    |  tool/call          |                    |                   |
    |  straylight_exec    |                    |                   |
    |  service: github    |                    |                   |
    |  command: gh repo   |                    |                   |
    |    list --json name |                    |                   |
    |-------------------->|                    |                   |
    |                     |  POST /api/v1/mcp/ |                   |
    |                     |  tool-call         |                   |
    |                     |------------------->|                   |
    |                     |                    |  GET secret/data/ |
    |                     |                    |  services/github/ |
    |                     |                    |  credential       |
    |                     |                    |------------------>|
    |                     |                    |<------------------|
    |                     |                    |  { token: ghp_... }
    |                     |                    |                   |
    |                     |                    |  [spawn subprocess]
    |                     |                    |  env: GH_TOKEN=ghp_...
    |                     |                    |  cmd: gh repo list
    |                     |                    |       --json name
    |                     |                    |                   |
    |                     |                    |  [capture stdout/stderr]
    |                     |                    |  [sanitize output]
    |                     |                    |  (replace ghp_... patterns
    |                     |                    |   with [REDACTED:github])
    |                     |                    |                   |
    |                     |<-------------------|                   |
    |                     |  { scrubbed output }                   |
    |<--------------------|                    |                   |
    |  MCP tool result    |                    |                   |
```

**Key security properties:**
- Token injected via environment variable (not command-line argument)
- Subprocess stdout/stderr captured and sanitized before return
- Token patterns replaced with `[REDACTED:github]`

## Flow 3: User Stores a Credential via Web UI

```
Browser              Straylight Core      OpenBao
(Web UI)             (container:9470)     (internal:9443)
    |                     |                   |
    |  POST /api/v1/      |                   |
    |  services/stripe/   |                   |
    |  credential         |                   |
    |  { key: "sk_..." }  |                   |
    |-------------------->|                   |
    |   (HTTPS/localhost) |                   |
    |                     |  [validate format]|
    |                     |                   |
    |                     |  PUT secret/data/ |
    |                     |  services/stripe/ |
    |                     |  credential       |
    |                     |  { api_key: sk_.. }
    |                     |------------------>|
    |                     |                   |
    |                     |<------------------|
    |                     |  { version: 1 }   |
    |                     |                   |
    |<--------------------|                   |
    |  { status: "stored" }                   |
    |                     |                   |
```

**Key security properties:**
- Credential travels: browser -> Go process -> OpenBao (encrypted at rest)
- Credential is NEVER logged (audit log records access, not values)
- Web UI clears the input field after submission
- Go process does not cache the credential in memory

## Flow 4: OAuth Authorization Flow

```
Browser              Straylight Core      GitHub OAuth     OpenBao
(Web UI)             (container:9470)     (external)       (internal:9443)
    |                     |                   |                |
    |  GET /api/v1/       |                   |                |
    |  oauth/github/start |                   |                |
    |-------------------->|                   |                |
    |                     |  [generate state] |                |
    |                     |  [store state in  |                |
    |                     |   memory/session] |                |
    |                     |                   |                |
    |<--------------------|                   |                |
    |  302 Redirect to    |                   |                |
    |  github.com/login/  |                   |                |
    |  oauth/authorize?   |                   |                |
    |  client_id=...&     |                   |                |
    |  state=...&         |                   |                |
    |  scope=repo,read:org|                   |                |
    |                     |                   |                |
    |  [user authorizes in browser]           |                |
    |                     |                   |                |
    |  GET /api/v1/oauth/ |                   |                |
    |  callback?code=...& |                   |                |
    |  state=...          |                   |                |
    |-------------------->|                   |                |
    |                     |  [verify state]   |                |
    |                     |                   |                |
    |                     |  POST /login/     |                |
    |                     |  oauth/access_token                |
    |                     |  code=...         |                |
    |                     |------------------>|                |
    |                     |<------------------|                |
    |                     |  { access_token,  |                |
    |                     |    refresh_token,  |                |
    |                     |    expires_in }    |                |
    |                     |                   |                |
    |                     |  PUT secret/data/services/         |
    |                     |  github/oauth     |                |
    |                     |  { access_token, refresh_token,    |
    |                     |    expires_at }    |                |
    |                     |------------------------------------>|
    |                     |<------------------------------------|
    |                     |                   |                |
    |<--------------------|                   |                |
    |  200 { status:      |                   |                |
    |    "connected" }    |                   |                |
```

## Flow 5: Output Sanitization Pipeline

```
Raw Response / Command Output
         |
         v
+--------+----------+
| Pattern Matcher    |  Known credential patterns:
|                    |  - sk_live_[a-zA-Z0-9]{24,}    (Stripe)
|                    |  - ghp_[a-zA-Z0-9]{36}          (GitHub PAT)
|                    |  - gho_[a-zA-Z0-9]{36}          (GitHub OAuth)
|                    |  - sk-[a-zA-Z0-9]{48,}           (OpenAI)
|                    |  - Bearer [a-zA-Z0-9._-]{20,}   (Generic bearer)
|                    |  - [A-Z0-9]{20}:[a-zA-Z0-9/+]{40} (AWS keys)
|                    |  - [custom patterns per service]
+--------+----------+
         |
         v
+--------+----------+
| Known Value Check  |  Compare against all currently-stored
|                    |  secret values from OpenBao
+--------+----------+
         |
         v
+--------+----------+
| Replacement        |  Replace matches with:
|                    |  [REDACTED:service-name]
|                    |  or [REDACTED:credential-pattern]
+--------+----------+
         |
         v
Sanitized Output
(safe for agent context)
```

**Sanitization is two-layered:**
1. **Pattern matching**: Regex-based detection of known credential formats
2. **Value matching**: Direct comparison against stored secret values

This ensures that even if a credential format is not recognized by pattern,
it will be caught by value comparison if it was stored through Straylight-AI.

## Flow 6: Container Startup Sequence

```
Container Start
     |
     v
[1] Go process starts (straylight serve)
     |
     v
[2] Load config from /data/config.yaml
     |
     v
[3] Start OpenBao supervisor
     |
     +---> Fork: bao server -config=/etc/straylight/openbao.hcl
     |
     v
[4] Wait for OpenBao health (poll /v1/sys/health, max 3s)
     |
     v
[5] Check initialization status
     |
     +--[not initialized]---> Initialize OpenBao
     |                         |
     |                         +---> POST /v1/sys/init
     |                         +---> Save unseal key to /data/openbao/init.json
     |                         +---> POST /v1/sys/unseal
     |                         +---> Enable KV v2 at secret/
     |                         +---> Create AppRole + policy
     |                         |
     +--[initialized]--------->+
     |                         |
     v                         v
[6] Unseal OpenBao (read key from init.json)
     |
     v
[7] Authenticate to OpenBao (AppRole)
     |
     v
[8] Load service credentials from OpenBao
     |
     v
[9] Build sanitizer patterns from stored credentials
     |
     v
[10] Start HTTP server on :9470
     |
     v
[11] Ready (health check returns 200)
```
