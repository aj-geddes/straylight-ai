# Component Diagram -- Straylight-AI Personal (Free)

## System Context

```
+------------------+
|  Developer       |
|  Workstation     |
+--------+---------+
         |
         |  uses
         v
+--------+---------+     stdio       +---------------------+
|  Claude Code /   |<--------------->|  straylight-mcp     |
|  Cursor / MCP    |  (JSON-RPC 2.0) |  (host binary)      |
|  Client          |                 +----------+----------+
+------------------+                            |
                                                | HTTP localhost:9470
         +--------------------------------------+
         |
         |  browser
         v
+--------+---------+     HTTP        +------------------------------+
|  Web Browser     |<--------------->|  Docker Container            |
|  localhost:9470  |  localhost:9470  |  (straylight-ai)             |
+------------------+                 +------------------------------+
```

## Container Internals

```
+===================================================================+
|                    Docker Container: straylight-ai                  |
|                                                                     |
|  +-----------------------+                                          |
|  |   Go Process          |                                          |
|  |   (straylight serve)  |                                          |
|  |                       |                                          |
|  |  +----------------+   |                                          |
|  |  | HTTP Router    |   |                                          |
|  |  | :9470          |   |                                          |
|  |  +---+----+---+---+   |                                          |
|  |      |    |   |       |                                          |
|  |      v    |   v       |                                          |
|  |  +------+ | +-------+ |     +----------------------------------+ |
|  |  | Web  | | | MCP   | |     |                                  | |
|  |  | UI   | | | API   | |     |  External Services               | |
|  |  |Handler| | |Handler| |     |  (Stripe, GitHub, OpenAI, etc.) | |
|  |  +------+ | +---+---+ |     |                                  | |
|  |           |     |      |     +------------------^---------------+ |
|  |           v     v      |                        |                 |
|  |  +--------+----+---+  |                        |                 |
|  |  | Service Router  |  |                        |                 |
|  |  | (resolves creds |  |                        |                 |
|  |  |  + routes reqs) |  |                        |                 |
|  |  +---+----+----+---+  |                        |                 |
|  |      |    |    |       |                        |                 |
|  |      v    |    v       |                        |                 |
|  |  +------+ | +-------+  |  +---+  credential    |                 |
|  |  |Vault | | | HTTP   |--+--|-->|  injection  ---+                 |
|  |  |Client| | | Proxy  |  |  +---+                                  |
|  |  +--+---+ | +--------+  |                                        |
|  |     |     |              |                                        |
|  |     |     v              |                                        |
|  |     |  +----------+     |                                        |
|  |     |  | Output   |     |                                        |
|  |     |  | Sanitizer|     |                                        |
|  |     |  +----------+     |                                        |
|  |     |                    |                                        |
|  |     |  +-----------+    |                                        |
|  |     |  | OAuth     |    |                                        |
|  |     |  | Handler   |    |                                        |
|  |     |  +-----+-----+    |                                        |
|  |     |        |           |                                        |
|  |     |  +-----+-----+    |                                        |
|  |     |  | Cmd       |    |                                        |
|  |     |  | Wrapper   |    |                                        |
|  |     |  +-----------+    |                                        |
|  |     |                    |                                        |
|  +-----------------------+  |                                        |
|        |                    |                                        |
|        v  localhost:9443    |                                        |
|  +-----+---------------+   |                                        |
|  |   OpenBao Process    |   |                                        |
|  |   (bao server)       |   |                                        |
|  |                      |   |                                        |
|  |   KV v2 Engine       |   |                                        |
|  |   File Storage       |   |                                        |
|  |   Audit Backend      |   |                                        |
|  +----------+-----------+   |                                        |
|             |               |                                        |
+===================================================================+
              |
              v
     ~/.straylight-ai/data/
        openbao/          (encrypted secrets)
        config.yaml       (service definitions)
```

## Component Responsibilities

### Go Process Components

| Component | Responsibility | Dependencies |
|-----------|---------------|--------------|
| HTTP Router | Route requests to correct handler by path | None |
| Web UI Handler | Serve React SPA (embedded), handle SPA fallback | embed.FS |
| MCP API Handler | Handle tool-call and tool-list from MCP host binary | Service Router |
| Service Router | Resolve service config, dispatch to proxy or cmd wrapper | Vault Client, Config |
| HTTP Proxy | Forward HTTP requests to external services with injected credentials | Vault Client |
| Output Sanitizer | Strip credential patterns from responses and command output | Sanitizer Rules |
| Vault Client | Read/write secrets from OpenBao KV v2 engine | OpenBao (HTTP) |
| OAuth Handler | Manage OAuth authorization code flow, token refresh | Vault Client |
| Command Wrapper | Execute commands with credentials in environment, scrub output | Vault Client, Sanitizer |
| OpenBao Supervisor | Start, unseal, health check, restart OpenBao process | os/exec |
| Config Manager | Load and validate service configuration from /data/config.yaml | None |

### OpenBao Process

| Component | Responsibility |
|-----------|---------------|
| KV v2 Secret Engine | Store API keys, OAuth tokens, service credentials |
| File Storage Backend | Persist encrypted data to /data/openbao/ |
| Audit Backend | Log all secret access (file-based) |
| TCP Listener | Accept connections on 127.0.0.1:9443 only |

### Host Components (outside container)

| Component | Responsibility |
|-----------|---------------|
| straylight-mcp binary | stdio MCP server; translates JSON-RPC to HTTP calls to container |
| straylight-ai npm CLI | Docker lifecycle management, MCP registration, bootstrap |

## Interface Boundaries

```
                      Interface Map
  +-----------+
  | External  |
  | Services  |    HTTPS (public internet)
  +-----------+
       ^
       |
  -----+----- Container Boundary ------------------------------------------
       |
  +----+------+
  | HTTP Proxy |    HTTP with injected auth headers/tokens
  +-----------+
       ^
       |  in-process function call
  +----+------+
  | Service   |
  | Router    |
  +-----------+
    ^       ^
    |       |  in-process function calls
    |    +--+--------+
    |    | MCP API   |    HTTP localhost:9470/api/v1/mcp/*
    |    | Handler   |    (called by host MCP binary)
    |    +-----------+
    |
  +-+---------+
  | Web UI    |    HTTP localhost:9470/api/v1/*
  | API       |    (called by React SPA in browser)
  | Handler   |
  +-----------+
       ^
       |  localhost:9443 HTTP
  +----+------+
  | OpenBao   |    Internal only, no external exposure
  +-----------+
       ^
       |  filesystem
  +----+------+
  | /data     |    Volume mount to host
  +-----------+
```

## Port and Protocol Summary

| Port | Protocol | Listener | Consumer | Exposed to Host |
|------|----------|----------|----------|----------------|
| 9470 | HTTP | Go process | Browser, MCP binary | Yes (localhost) |
| 9443 | HTTP | OpenBao | Go process (Vault client) | No |
