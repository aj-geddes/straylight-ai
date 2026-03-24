# Sequence Diagrams -- Straylight-AI Personal (Free)

## Diagram 1: First-Time Setup (npx straylight-ai setup)

```
Developer            npx CLI              Docker             Container          Browser
    |                   |                    |                   |                  |
    | npx straylight-ai |                    |                   |                  |
    | setup             |                    |                   |                  |
    |------------------>|                    |                   |                  |
    |                   |                    |                   |                  |
    |                   | Check Docker       |                   |                  |
    |                   | installed          |                   |                  |
    |                   |------------------->|                   |                  |
    |                   |<-------------------|                   |                  |
    |                   | Docker v27.x       |                   |                  |
    |                   |                    |                   |                  |
    |                   | Check existing     |                   |                  |
    |                   | container          |                   |                  |
    |                   |------------------->|                   |                  |
    |                   |<-------------------|                   |                  |
    |                   | Not found          |                   |                  |
    |                   |                    |                   |                  |
    |   Pulling image...|                    |                   |                  |
    |<------------------|                    |                   |                  |
    |                   | docker pull        |                   |                  |
    |                   | ghcr.io/straylight |                   |                  |
    |                   |------------------->|                   |                  |
    |                   |<-------------------|                   |                  |
    |                   |                    |                   |                  |
    |                   | mkdir ~/.straylight-ai/data/           |                  |
    |                   |                    |                   |                  |
    |                   | docker run -d      |                   |                  |
    |                   | --name straylight  |                   |                  |
    |                   | -p 9470:9470       |                   |                  |
    |                   | -v data:/data      |                   |                  |
    |                   |------------------->|                   |                  |
    |                   |                    | Start container   |                  |
    |                   |                    |------------------>|                  |
    |                   |                    |                   |                  |
    |                   | Poll health        |                   |                  |
    |                   | GET :9470/health   |                   |                  |
    |                   |----------------------------------->|                  |
    |                   |<-----------------------------------|                  |
    |                   | { status: "ok" }   |                   |                  |
    |                   |                    |                   |                  |
    |                   | Detect claude CLI  |                   |                  |
    |                   | (which claude)     |                   |                  |
    |                   |                    |                   |                  |
    |                   | claude mcp add     |                   |                  |
    |                   | --transport stdio  |                   |                  |
    |                   | straylight --      |                   |                  |
    |                   | straylight-mcp     |                   |                  |
    |                   |                    |                   |                  |
    |                   | open browser       |                   |                  |
    |                   |----------------------------------------------------->|
    |                   |                    |                   |          localhost:9470
    |                   |                    |                   |                  |
    |   Setup complete! |                    |                   |                  |
    |   Open localhost:  |                    |                   |                  |
    |   9470 to add      |                    |                   |                  |
    |   services.        |                    |                   |                  |
    |<------------------|                    |                   |                  |
```

## Diagram 2: Service Configuration via Web UI (Paste Key)

```
Developer          Browser/React         Go Core API          OpenBao
    |                   |                    |                    |
    | Click "Add        |                    |                    |
    | Service" tile     |                    |                    |
    |------------------>|                    |                    |
    |                   |                    |                    |
    | [Select "Stripe"] |                    |                    |
    |------------------>|                    |                    |
    |                   |                    |                    |
    | [Paste API key    |                    |                    |
    |  into input]      |                    |                    |
    |------------------>|                    |                    |
    |                   |                    |                    |
    | [Click "Save"]    |                    |                    |
    |------------------>|                    |                    |
    |                   | POST /api/v1/      |                    |
    |                   | services           |                    |
    |                   | { name: "stripe",  |                    |
    |                   |   type: "http_proxy",                   |
    |                   |   target: "https://|                    |
    |                   |   api.stripe.com", |                    |
    |                   |   credential: {    |                    |
    |                   |     key: "sk_..." } }                   |
    |                   |------------------->|                    |
    |                   |                    |                    |
    |                   |                    | [validate config]  |
    |                   |                    |                    |
    |                   |                    | PUT secret/data/   |
    |                   |                    | services/stripe/   |
    |                   |                    | credential         |
    |                   |                    |------------------->|
    |                   |                    |<-------------------|
    |                   |                    |                    |
    |                   |                    | [update service    |
    |                   |                    |  registry in       |
    |                   |                    |  config.yaml]      |
    |                   |                    |                    |
    |                   |                    | [rebuild sanitizer |
    |                   |                    |  patterns]         |
    |                   |                    |                    |
    |                   |<-------------------|                    |
    |                   | { status: "ok",    |                    |
    |                   |   service: "stripe",                    |
    |                   |   connected: true } |                    |
    |                   |                    |                    |
    | [Tile shows       |                    |                    |
    |  "Connected"]     |                    |                    |
    |<------------------|                    |                    |
```

## Diagram 3: Claude Code Uses straylight_api_call

```
Claude Code           straylight-mcp       Go Core             OpenBao          Stripe
(agent)               (host, stdio)        (:9470)             (:9443)          (ext.)
    |                     |                    |                   |               |
    | "Check my Stripe    |                    |                   |               |
    |  balance"           |                    |                   |               |
    |                     |                    |                   |               |
    | [Agent decides to   |                    |                   |               |
    |  call MCP tool]     |                    |                   |               |
    |                     |                    |                   |               |
    | {"jsonrpc":"2.0",   |                    |                   |               |
    |  "method":"tools/   |                    |                   |               |
    |  call",             |                    |                   |               |
    |  "params":{         |                    |                   |               |
    |    "name":          |                    |                   |               |
    |    "straylight_     |                    |                   |               |
    |     api_call",      |                    |                   |               |
    |    "arguments":{    |                    |                   |               |
    |      "service":     |                    |                   |               |
    |      "stripe",      |                    |                   |               |
    |      "method":"GET",|                    |                   |               |
    |      "path":        |                    |                   |               |
    |      "/v1/balance"  |                    |                   |               |
    |    }}}              |                    |                   |               |
    |-------------------->|                    |                   |               |
    |   (stdin pipe)      |                    |                   |               |
    |                     | POST /api/v1/mcp/  |                   |               |
    |                     | tool-call          |                   |               |
    |                     | {tool, arguments}  |                   |               |
    |                     |------------------->|                   |               |
    |                     |                    |                   |               |
    |                     |                    | [resolve service  |               |
    |                     |                    |  "stripe" from    |               |
    |                     |                    |  config registry] |               |
    |                     |                    |                   |               |
    |                     |                    | GET secret/data/  |               |
    |                     |                    | services/stripe/  |               |
    |                     |                    | credential        |               |
    |                     |                    |------------------>|               |
    |                     |                    |<------------------|               |
    |                     |                    | {api_key:"sk_..."} |               |
    |                     |                    |                   |               |
    |                     |                    | GET https://api.  |               |
    |                     |                    | stripe.com        |               |
    |                     |                    | /v1/balance       |               |
    |                     |                    | Authorization:    |               |
    |                     |                    | Bearer sk_...     |               |
    |                     |                    |---------------------------------->|
    |                     |                    |                   |               |
    |                     |                    |<----------------------------------|
    |                     |                    | {"available":[    |               |
    |                     |                    |   {"amount":12345,|               |
    |                     |                    |    "currency":"usd"}]}            |
    |                     |                    |                   |               |
    |                     |                    | [sanitize: scan   |               |
    |                     |                    |  for sk_live_*,   |               |
    |                     |                    |  Bearer tokens,   |               |
    |                     |                    |  stored values]   |               |
    |                     |                    |                   |               |
    |                     |<-------------------|                   |               |
    |                     | {content:[{type:   |                   |               |
    |                     |  "text", text:     |                   |               |
    |                     |  "{...balance...}" |                   |               |
    |                     | }]}                |                   |               |
    |                     |                    |                   |               |
    |<--------------------|                    |                   |               |
    | {"jsonrpc":"2.0",   |                    |                   |               |
    |  "result":{         |                    |                   |               |
    |    "content":[{     |                    |                   |               |
    |      "type":"text", |                    |                   |               |
    |      "text":        |                    |                   |               |
    |      "{balance...}" |                    |                   |               |
    |    }]}}             |                    |                   |               |
    |                     |                    |                   |               |
    | [Agent interprets   |                    |                   |               |
    |  balance data and   |                    |                   |               |
    |  responds to user]  |                    |                   |               |
```

## Diagram 4: Claude Code Hooks Integration (Phase 2)

```
Claude Code           PreToolUse Hook     PostToolUse Hook
(agent)               (straylight)        (straylight)
    |                     |                    |
    | [Agent wants to     |                    |
    |  run: echo $STRIPE_ |                   |
    |  API_KEY]           |                    |
    |                     |                    |
    | PreToolUse event    |                    |
    | {tool: "Bash",      |                    |
    |  input: "echo       |                    |
    |  $STRIPE_API_KEY"}  |                    |
    |-------------------->|                    |
    |                     |                    |
    |                     | [pattern match:    |
    |                     |  detects env var   |
    |                     |  reference to      |
    |                     |  known credential] |
    |                     |                    |
    |<--------------------|                    |
    | exit code 2         |                    |
    | (BLOCK)             |                    |
    | stderr: "Blocked:   |                    |
    |  command would      |                    |
    |  expose STRIPE_     |                    |
    |  API_KEY. Use       |                    |
    |  straylight_exec    |                    |
    |  instead."          |                    |
    |                     |                    |
    | [Agent adjusts:     |                    |
    |  uses straylight_   |                    |
    |  exec tool instead] |                    |
    |                     |                    |
    | ...later...         |                    |
    |                     |                    |
    | [Tool execution     |                    |
    |  completes]         |                    |
    |                     |                    |
    | PostToolUse event   |                    |
    | {tool: "Bash",      |                    |
    |  output: "...text   |                    |
    |  containing sk_live |                    |
    |  _abc123..."}       |                    |
    |--------------------------------------------->|
    |                     |                    |
    |                     |                    | [scan output for
    |                     |                    |  credential patterns]
    |                     |                    |
    |                     |                    | [replace matches with
    |                     |                    |  [REDACTED:stripe]]
    |                     |                    |
    |<---------------------------------------------|
    | exit code 0         |                    |
    | stdout: sanitized   |                    |
    | output              |                    |
```

## Diagram 5: OpenBao Crash Recovery

```
Go Supervisor         OpenBao Process      MCP/Proxy Requests
    |                     |                    |
    | [monitoring via     |                    |
    |  process.Wait()]    |                    |
    |                     |                    |
    |                     | CRASH / EXIT       |
    |                     X                    |
    |                     |                    |
    | [process.Wait()     |                    |
    |  returns error]     |                    |
    |                     |                    |
    | [log error]         |                    |
    | [set status =       |                    | Request arrives
    |  "recovering"]      |                    |----->
    |                     |                    |
    |                     |                    | [vault client
    |                     |                    |  returns error:
    |                     |                    |  "vault unavailable,
    |                     |                    |  retrying..."]
    |                     |                    |
    | [restart OpenBao]   |                    |
    | fork: bao server    |                    |
    |-------------------->| (new process)      |
    |                     |                    |
    | [poll health]       |                    |
    |-------------------->|                    |
    |<--------------------|                    |
    | [503 sealed]        |                    |
    |                     |                    |
    | [unseal]            |                    |
    | POST /v1/sys/unseal |                    |
    |-------------------->|                    |
    |<--------------------|                    |
    | [200 OK]            |                    |
    |                     |                    |
    | [re-authenticate]   |                    |
    | AppRole login       |                    |
    |-------------------->|                    |
    |<--------------------|                    |
    | [token received]    |                    |
    |                     |                    |
    | [set status = "ok"] |                    |
    |                     |                    | Retry succeeds
    |                     |                    |<----
```
