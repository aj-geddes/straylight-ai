# Implementation Guide -- Straylight-AI Personal (Free)

**For**: Developer Agent
**From**: Architect Agent
**Date**: 2026-03-22

## Overview

This guide breaks the Straylight-AI Personal (Free) build into three phases with
concrete work packages. Each work package has clear inputs, outputs, complexity,
and test criteria. Follow the dependency ordering within each phase.

**Key design documents to reference:**
- `adr/ADR-001-language-choice.md` -- Go as primary language
- `adr/ADR-002-openbao-integration.md` -- OpenBao sidecar strategy
- `adr/ADR-003-mcp-transport.md` -- stdio MCP with host binary
- `adr/ADR-004-web-ui-strategy.md` -- React embedded in Go binary
- `adr/ADR-005-bootstrap-experience.md` -- npx bootstrap package
- `adr/ADR-006-container-packaging.md` -- Multi-stage Docker build
- `contracts/mcp-tools.json` -- MCP tool schemas
- `contracts/internal-api.yaml` -- Internal HTTP API spec
- `schemas/config-schema.yaml` -- Configuration file schema
- `schemas/service-registry.md` -- Data model and OpenBao paths

---

## Repository Structure

Create this Go module structure at the project root:

```
straylight-ai/
  go.mod                           -- module github.com/aj-geddes/straylight-ai
  go.sum
  cmd/
    straylight/                    -- Main server binary
      main.go
    straylight-mcp/                -- MCP host binary (thin stdio adapter)
      main.go
  internal/
    server/                        -- HTTP server setup and routing
      server.go
      routes.go
    proxy/                         -- HTTP reverse proxy with credential injection
      proxy.go
      proxy_test.go
    vault/                         -- OpenBao client wrapper
      client.go
      client_test.go
      supervisor.go                -- Process lifecycle management
      supervisor_test.go
    mcp/                           -- MCP tool implementations
      handler.go                   -- HTTP handler for /api/v1/mcp/*
      tools.go                     -- Tool definitions and dispatch
      tools_test.go
    sanitizer/                     -- Output sanitization engine
      sanitizer.go
      sanitizer_test.go
      patterns.go                  -- Built-in credential patterns
    oauth/                         -- OAuth flow handler
      handler.go
      providers.go                 -- Provider-specific config (GitHub, Google, etc.)
      state.go                     -- CSRF state management
    services/                      -- Service registry management
      registry.go
      registry_test.go
      templates.go                 -- Built-in service templates
    config/                        -- Configuration loading and validation
      config.go
      config_test.go
    cmdwrap/                       -- Command wrapping and execution
      wrapper.go
      wrapper_test.go
    hooks/                         -- Claude Code hooks scripts
      pretooluse.go
      posttooluse.go
    web/                           -- Embedded web UI
      embed.go
      handler.go
  web/                             -- React SPA source
    package.json
    vite.config.ts
    tsconfig.json
    src/
      main.tsx
      App.tsx
      api/
        client.ts
      components/
        ServiceTile.tsx
        PasteKeyDialog.tsx
        OAuthButton.tsx
        StatusIndicator.tsx
        HealthBanner.tsx
        Layout.tsx
      pages/
        Dashboard.tsx
        ServiceConfig.tsx
        OAuthCallback.tsx
      types/
        service.ts
        health.ts
    dist/                          -- Build output (gitignored)
  deploy/
    openbao.hcl                    -- OpenBao server configuration
    Dockerfile                     -- Multi-stage Docker build
    docker-compose.yml             -- Development convenience
  npm/
    straylight-ai/                 -- npm CLI package
      package.json
      bin/
        cli.js
        mcp-shim.js
      src/
        commands/
          setup.ts
          start.ts
          stop.ts
          status.ts
        docker.ts
        health.ts
        mcp-register.ts
  docs/                            -- Design documents (this directory)
  .github/
    workflows/
      build.yml                    -- CI: build + test + Docker image
  .gitignore
```

---

## Phase 0: Foundation

**Goal**: A running container with OpenBao, a health endpoint, and a Web UI shell.
The agent cannot do anything useful yet, but the infrastructure is in place.

**Exit criteria**: `docker run` starts the container, OpenBao auto-initializes and
auto-unseals, the health endpoint returns 200, and the Web UI loads in a browser.

### WP-0.1: Go Module and Project Skeleton

**Complexity**: S (Small)
**Dependencies**: None
**Deliverables**:
- `go.mod` with module path `github.com/aj-geddes/straylight-ai`
- `cmd/straylight/main.go` with cobra or plain flag-based CLI
  - Subcommands: `serve`, `health`, `version`
- `internal/config/config.go` with config struct and YAML loading
- `internal/server/server.go` with basic HTTP server on :9470
- Health endpoint at `GET /api/v1/health` returning `{"status":"starting"}`

**Test strategy**:
- Unit test for config loading (valid YAML, invalid YAML, missing file)
- Unit test for health endpoint (returns 200 with correct JSON)
- `go vet` and `go test ./...` pass

**Done when**: `go run ./cmd/straylight/ serve` starts an HTTP server and
`curl localhost:9470/api/v1/health` returns a JSON response.

---

### WP-0.2: OpenBao Supervisor

**Complexity**: M (Medium)
**Dependencies**: WP-0.1
**Deliverables**:
- `internal/vault/supervisor.go` -- Start, monitor, restart OpenBao process
- `internal/vault/client.go` -- OpenBao API client wrapper (init, unseal, auth, KV operations)
- `deploy/openbao.hcl` -- Server configuration (file storage, localhost listener, no TLS)
- Auto-initialization flow (see ADR-002 for details):
  1. Start `bao server -config=/etc/straylight/openbao.hcl`
  2. Poll health until ready
  3. Initialize if needed (1 share, 1 threshold)
  4. Save unseal key + root token to `/data/openbao/init.json`
  5. Unseal
  6. Enable KV v2 at `secret/`
  7. Create policy and AppRole
  8. Authenticate via AppRole
- Crash recovery: restart OpenBao and re-unseal on process exit

**Test strategy**:
- Unit tests with mock OpenBao HTTP server (init, unseal, auth sequences)
- Integration test: start real OpenBao binary, verify init + unseal + KV write/read
- Test crash recovery: kill OpenBao process, verify supervisor restarts it
- Test persistence: stop/start supervisor, verify existing init.json is reused

**Anti-patterns to avoid**:
- Do NOT store root token in memory long-term; use AppRole token after init
- Do NOT retry indefinitely; fail after 30 seconds with clear error
- Do NOT log unseal key or root token values

**Done when**: Go process starts OpenBao, auto-initializes, auto-unseals, and
can write/read a KV v2 secret. Health endpoint shows `"openbao":"unsealed"`.

---

### WP-0.3: React Web UI Shell

**Complexity**: S (Small)
**Dependencies**: WP-0.1
**Deliverables**:
- `web/` directory with Vite + React + TypeScript + Tailwind CSS
- Basic layout component with header ("Straylight-AI"), sidebar navigation
- Dashboard page showing health status (fetched from /api/v1/health)
- Health banner: green/yellow/red based on API response
- API client module (`web/src/api/client.ts`) with typed fetch wrapper
- Vite config with proxy to localhost:9470 for development

**Test strategy**:
- React component tests with Vitest + React Testing Library
- Health banner renders correct state for each status
- API client handles fetch errors gracefully

**Done when**: `cd web && npm run dev` shows a dashboard page that displays
the health status from the Go backend. The page is styled and responsive.

---

### WP-0.4: Web UI Embedding and Docker Image

**Complexity**: M (Medium)
**Dependencies**: WP-0.2, WP-0.3
**Deliverables**:
- `internal/web/embed.go` with `go:embed` directive for `web/dist/*`
- `internal/web/handler.go` with SPA-aware file server (fallback to index.html)
- `deploy/Dockerfile` multi-stage build (see ADR-006):
  - Stage 1: Build React SPA
  - Stage 2: Build Go binary (with embedded SPA)
  - Stage 3: Alpine runtime with OpenBao binary
- `.dockerignore` to keep build context small
- Basic `docker-compose.yml` for development

**Test strategy**:
- Build Docker image; verify size < 80 MB (budget 60 MB, allow 20 MB headroom)
- Start container; verify health endpoint responds within 10 seconds
- Verify Web UI loads in browser at localhost:9470
- Verify OpenBao is not accessible from host (port 9443 not mapped)
- Verify container runs as non-root user
- Stop and restart container; verify OpenBao data persists

**Done when**: `docker build -t straylight . && docker run -p 9470:9470 -v ~/.straylight-ai/data:/data straylight`
starts a working container with health endpoint and Web UI.

---

### WP-0.5: Volume and Data Directory Setup

**Complexity**: S (Small)
**Dependencies**: WP-0.2
**Deliverables**:
- On first start, create `/data/openbao/` directory structure
- Generate default `config.yaml` at `/data/config.yaml` if not exists
- Set correct file permissions (0700 for directories, 0600 for init.json)
- Validate volume mount exists; log clear error if /data is not mounted

**Test strategy**:
- Test first-start creates expected directory structure
- Test restart with existing data preserves everything
- Test missing volume mount produces clear error message

**Done when**: Container handles first-run and subsequent runs correctly with
proper file permissions on all data files.

---

## Phase 1: MVP

**Goal**: An AI agent can configure a service and make an authenticated API call
through Straylight-AI. This is the minimum useful product.

**Exit criteria**: A developer can `npx straylight-ai setup`, add a Stripe API key
in the Web UI, run `claude mcp add`, and then have Claude Code check their Stripe
balance via `straylight_api_call` -- with the API key never appearing in context.

### WP-1.1: Service Registry and Configuration API

**Complexity**: M (Medium)
**Dependencies**: WP-0.2 (OpenBao client)
**Deliverables**:
- `internal/services/registry.go` -- In-memory service registry, synced with config.yaml
- `internal/services/templates.go` -- Built-in service templates (Stripe, GitHub, OpenAI)
- HTTP API endpoints (per `contracts/internal-api.yaml`):
  - `POST /api/v1/services` -- Create service + store credential in OpenBao
  - `GET /api/v1/services` -- List services (no credentials in response)
  - `GET /api/v1/services/{name}` -- Get service detail
  - `PUT /api/v1/services/{name}` -- Update service config/credential
  - `DELETE /api/v1/services/{name}` -- Delete service + OpenBao secrets
  - `GET /api/v1/services/{name}/check` -- Credential status
  - `GET /api/v1/templates` -- List available templates

**Test strategy**:
- Unit tests for registry CRUD operations
- Integration tests: create service via API, verify credential in OpenBao, verify
  credential NOT in API response, verify deletion removes OpenBao secret
- Test input validation (bad names, missing fields, duplicate names)
- Test template listing

**Anti-patterns to avoid**:
- NEVER return credential values from GET endpoints
- NEVER log credential values
- Always delete OpenBao secrets when deleting a service (no orphans)

**Done when**: All CRUD endpoints work correctly. Credentials are stored in OpenBao
and never appear in API responses.

---

### WP-1.2: HTTP Proxy with Credential Injection

**Complexity**: L (Large)
**Dependencies**: WP-1.1 (service registry)
**Deliverables**:
- `internal/proxy/proxy.go` -- HTTP reverse proxy using `httputil.ReverseProxy`
- Credential injection based on service config:
  - Header injection (most common): set Authorization header from template
  - Query parameter injection (for services that use API keys in URLs)
- Request routing: resolve service name -> target URL -> inject credential -> forward
- Response passthrough with sanitization (see WP-1.3)
- Timeout handling per service configuration
- Error responses for: unknown service, missing credential, upstream error, timeout

**Implementation notes**:
- Use `httputil.ReverseProxy` with custom `Director` function
- The `Director` function:
  1. Looks up service config by name
  2. Fetches credential from OpenBao (with short TTL cache -- see below)
  3. Sets the target URL (service.target + request path)
  4. Injects credential per injection config
  5. Copies additional default_headers
- Credential caching: cache OpenBao lookups for 60 seconds to reduce vault calls.
  Use `sync.Map` with TTL. Invalidate on service update/delete.
- The `ModifyResponse` function runs the output sanitizer

**Test strategy**:
- Unit test with httptest.Server as mock external service
- Test header injection (Bearer token, Basic auth, custom header)
- Test query parameter injection
- Test credential caching (second request does not hit OpenBao)
- Test cache invalidation on service update
- Test timeout behavior
- Test error cases: unknown service, vault unavailable, upstream 500
- Benchmark: proxy overhead < 20ms (measured without network latency)

**Done when**: `POST /api/v1/mcp/tool-call` with `straylight_api_call` tool
successfully proxies a request to a mock external service with the correct
Authorization header injected, and the credential does not appear in the response.

---

### WP-1.3: Output Sanitizer

**Complexity**: M (Medium)
**Dependencies**: WP-1.1 (service registry for stored credential values)
**Deliverables**:
- `internal/sanitizer/sanitizer.go` -- Core sanitization engine
- `internal/sanitizer/patterns.go` -- Built-in credential regex patterns
- Two-layer sanitization:
  1. **Pattern matching**: Regex-based detection of known credential formats
     (see `schemas/service-registry.md` for pattern list)
  2. **Value matching**: Direct comparison against all stored credential values
     fetched from OpenBao
- Replacement with `[REDACTED:service-name]` or `[REDACTED:credential-pattern]`
- Thread-safe pattern registry (add/remove patterns as services change)
- Performance: sanitize 1 MB of text in < 10ms

**Implementation notes**:
- Compile regex patterns once and reuse (sync.RWMutex for updates)
- For value matching, normalize the credential and search as literal substring
- Order matters: value matching catches service-specific leaks; pattern matching
  catches similar-looking credentials from unknown sources
- Be careful with regex performance: avoid catastrophic backtracking
- The sanitizer is called from two places: proxy response body and command output

**Test strategy**:
- Unit tests for each built-in pattern (Stripe, GitHub, OpenAI, AWS, etc.)
- Test that known credential values are always caught by value matching
- Test that regex patterns catch credentials not in the value store
- Test replacement format is correct
- Test performance benchmark: 1 MB text with 10 patterns in < 10ms
- Test that non-credential text is NOT modified
- Test multi-line text with credentials scattered throughout

**Done when**: Sanitizer catches all credential patterns listed in the service
templates, catches stored credential values, and runs within performance budget.

---

### WP-1.4: MCP Internal API Handler

**Complexity**: M (Medium)
**Dependencies**: WP-1.2 (proxy), WP-1.3 (sanitizer)
**Deliverables**:
- `internal/mcp/handler.go` -- HTTP handler for `/api/v1/mcp/tool-call` and `/api/v1/mcp/tool-list`
- `internal/mcp/tools.go` -- Tool definitions matching `contracts/mcp-tools.json`
- Tool dispatch:
  - `straylight_api_call` -> proxy.HandleAPICall()
  - `straylight_check` -> services.CheckCredential()
  - `straylight_services` -> services.ListServices()
  - `straylight_exec` -> (stub returning "not available in Phase 1")
- Response format matches MCP CallToolResult schema (content array with text items)

**Test strategy**:
- Unit test each tool handler with mock dependencies
- Integration test: full tool-call request -> response cycle
- Test tool-list returns correct schemas matching contracts/mcp-tools.json
- Test error handling: unknown tool, missing arguments, validation failures
- Test that responses never contain credential values

**Done when**: `POST /api/v1/mcp/tool-call` dispatches to correct handler and
returns properly formatted MCP results. `GET /api/v1/mcp/tool-list` returns
all four tool definitions with correct input schemas.

---

### WP-1.5: MCP Host Binary (straylight-mcp)

**Complexity**: M (Medium)
**Dependencies**: WP-1.4 (internal MCP API)
**Deliverables**:
- `cmd/straylight-mcp/main.go` -- Thin stdio MCP server
- Uses official Go MCP SDK (`github.com/modelcontextprotocol/go-sdk`)
- Reads JSON-RPC 2.0 from stdin, forwards tool calls to container API, writes results to stdout
- On startup: check container health; emit MCP error notification if unavailable
- Tool registration: register all 4 tools with schemas from the container's tool-list endpoint
- Graceful shutdown on SIGTERM/SIGINT

**Implementation notes**:
- The binary should be stateless -- all state lives in the container
- Use the Go MCP SDK's `mcp.NewServer()` and `mcp.StdioTransport()`
- For each registered tool, the handler function makes an HTTP POST to
  `http://localhost:9470/api/v1/mcp/tool-call` and returns the result
- Container URL should be configurable via `STRAYLIGHT_URL` env var (default: http://localhost:9470)
- Binary must compile for all 5 target platforms (see ADR-003)

**Test strategy**:
- Unit test: mock HTTP server, verify stdin/stdout JSON-RPC round-trip
- Integration test: start container + MCP binary, send tool/list via stdin,
  verify response on stdout
- Test container-unavailable error handling
- Test binary size < 10 MB per platform
- Cross-compile test for all 5 platforms

**Done when**: `echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | straylight-mcp`
returns a valid tools/list response. Tool calls via stdin produce correct results
from the container.

---

### WP-1.6: Web UI Service Management

**Complexity**: M (Medium)
**Dependencies**: WP-1.1 (service API), WP-0.3 (UI shell)
**Deliverables**:
- Dashboard page with service tiles (grid layout)
- Service tile component:
  - Service icon and name
  - Status indicator (green=available, yellow=expired, gray=not configured)
  - Click to configure
- "Add Service" button -> template picker (shows built-in templates + custom option)
- Paste-key dialog:
  - Template-driven form (fields from service template)
  - Password input for credential fields (masked, paste-friendly)
  - "Save" stores service + credential via API
  - Input cleared after successful save
- Service detail view:
  - Configuration display (no credential values)
  - "Update Credential" action
  - "Delete Service" action with confirmation
  - Status and last-used timestamp

**Test strategy**:
- Component tests for ServiceTile, PasteKeyDialog, template picker
- Integration test: create service via UI, verify tile appears with correct status
- Test credential input is masked and cleared after submission
- Test deletion removes tile from dashboard
- Test empty state (no services configured)

**Done when**: User can add a Stripe service via the Web UI by selecting the
Stripe template and pasting an API key. The tile shows "available" status.
User can update and delete services.

---

### WP-1.7: OAuth Flow (GitHub)

**Complexity**: L (Large)
**Dependencies**: WP-1.1 (service registry), WP-0.2 (vault client)
**Deliverables**:
- `internal/oauth/handler.go` -- OAuth HTTP handlers
  - `GET /api/v1/oauth/{provider}/start` -- Generate state, redirect to provider
  - `GET /api/v1/oauth/callback` -- Exchange code for tokens, store in OpenBao
- `internal/oauth/providers.go` -- GitHub-specific OAuth config
  - Authorization URL: `https://github.com/login/oauth/authorize`
  - Token URL: `https://github.com/login/oauth/access_token`
  - Default scopes: `repo`, `read:org`
- `internal/oauth/state.go` -- CSRF state token management (in-memory with expiry)
- Token refresh logic: when access token is expired and refresh token is available,
  automatically refresh before credential injection
- Web UI "Connect with GitHub" button that initiates the OAuth flow

**Implementation notes**:
- The user must provide a GitHub OAuth App client_id and client_secret
- Client ID goes in config.yaml; client_secret goes in OpenBao
- The callback URL must match what is configured in the GitHub OAuth App
- State tokens expire after 10 minutes
- Token refresh runs lazily (on credential access) not proactively

**Test strategy**:
- Unit test with mock OAuth provider (httptest.Server)
- Test full flow: start -> redirect -> callback -> token stored
- Test CSRF: invalid state parameter returns error
- Test state expiry: expired state returns error
- Test token refresh: expired access token triggers refresh
- Test refresh failure: returns clear error, sets status to "expired"

**Done when**: User can click "Connect with GitHub" in the Web UI, authorize
in GitHub, and have the OAuth token stored in OpenBao. Subsequent
`straylight_api_call` calls to github service use the OAuth token.

---

### WP-1.8: npx Bootstrap Package

**Complexity**: M (Medium)
**Dependencies**: WP-0.4 (Docker image), WP-1.5 (MCP binary)
**Deliverables**:
- `npm/straylight-ai/` -- npm package source
- CLI commands (see ADR-005):
  - `npx straylight-ai` / `npx straylight-ai setup` -- Full bootstrap
  - `npx straylight-ai start` -- Start container
  - `npx straylight-ai stop` -- Stop container
  - `npx straylight-ai status` -- Health check
- Docker detection (docker / podman)
- Container lifecycle management (create, start, stop, remove)
- Health check polling
- Claude Code MCP registration (`claude mcp add`)
- Browser auto-open
- `bin/mcp-shim.js` -- MCP binary launcher (finds platform-specific binary)
- Platform-specific binary packages (5 packages for optionalDependencies)

**Test strategy**:
- Test Docker detection on systems with/without Docker
- Test idempotent setup (run twice, no duplicate containers)
- Test MCP registration command generation
- Test mcp-shim finds correct platform binary
- Manual end-to-end test: `npx straylight-ai setup` on macOS and Linux

**Done when**: `npx straylight-ai setup` on a machine with Docker installed pulls
the image, starts the container, registers the MCP server with Claude Code (if
installed), opens the browser to localhost:9470, and prints a success message.

---

### WP-1.9: Claude Code Integration Test

**Complexity**: S (Small)
**Dependencies**: WP-1.5 (MCP binary), WP-1.2 (proxy), WP-1.6 (Web UI)
**Deliverables**:
- End-to-end integration test script
- Test scenario:
  1. Start container
  2. Add Stripe test key via API
  3. Start straylight-mcp binary
  4. Send `tools/list` via stdin -> verify 4 tools returned
  5. Send `straylight_check` for stripe -> verify "available"
  6. Send `straylight_api_call` for stripe GET /v1/balance -> verify response
  7. Verify API key does NOT appear in any stdout output
  8. Send `straylight_services` -> verify stripe listed
- Documentation: step-by-step guide for manually testing with Claude Code

**Test strategy**: This IS the test. It is the integration smoke test.

**Done when**: The integration test passes end-to-end. A developer can follow
the manual test guide and have Claude Code make authenticated API calls.

---

## Phase 2: Hardening

**Goal**: Full feature set for the free tier. Command wrapping, Claude Code hooks,
additional OAuth providers, and the `straylight_services` discovery tool are all
working. The product is ready for public release.

**Exit criteria**: All four MCP tools work correctly. Claude Code hooks prevent
credential leakage. Multiple OAuth providers are supported. The system handles
error cases gracefully.

### WP-2.1: Command Wrapper (straylight_exec)

**Complexity**: L (Large)
**Dependencies**: WP-1.3 (sanitizer), WP-1.1 (service registry)
**Deliverables**:
- `internal/cmdwrap/wrapper.go` -- Subprocess execution with credential injection
- Credential injection via environment variables (per service exec_config.env_var)
- Subprocess timeout enforcement (kill after timeout_seconds)
- stdout and stderr capture
- Output sanitization (run both through sanitizer before returning)
- Response format: exit code + sanitized stdout + sanitized stderr
- Command allowlist enforcement (if exec_config.allowed_commands is set)
- Security: commands run as the container's non-root user

**Implementation notes**:
- Use `os/exec.CommandContext` with context timeout
- Set env vars on the `Cmd.Env` field (start from empty env, add only service env vars
  plus essential PATH, HOME, etc.)
- Capture stdout and stderr separately via pipes
- Run sanitizer on both stdout and stderr before building response
- The command runs INSIDE the container, so available commands are limited to what
  is installed in the container image (need to document this limitation)

**Test strategy**:
- Unit test: mock command execution, verify env var injection
- Test timeout: command that sleeps forever is killed at timeout
- Test output sanitization: command that echoes a credential gets it redacted
- Test allowlist: blocked command returns clear error
- Test exit code propagation
- Test large output handling (> 1 MB)
- Security test: verify command cannot read /data/openbao/init.json

**Done when**: `straylight_exec` runs commands with injected credentials, sanitizes
output, enforces timeouts, and respects command allowlists.

---

### WP-2.2: Claude Code Hooks

**Complexity**: M (Medium)
**Dependencies**: WP-1.3 (sanitizer)
**Deliverables**:
- `internal/hooks/pretooluse.go` -- PreToolUse hook script/binary
- `internal/hooks/posttooluse.go` -- PostToolUse hook script/binary
- PreToolUse behavior:
  - Receives tool name and input via stdin (JSON)
  - Checks if the tool input contains known credential env var references
    (e.g., `$STRIPE_API_KEY`, `$GH_TOKEN`)
  - If detected: exit code 2 (block) with stderr message suggesting straylight_exec
  - If clean: exit code 0 (allow)
- PostToolUse behavior:
  - Receives tool output via stdin (JSON)
  - Runs output through sanitizer
  - Outputs sanitized version to stdout
  - Exit code 0
- Hook registration config for `.claude/settings.json`:
  ```json
  {
    "hooks": {
      "PreToolUse": [{
        "matcher": "Bash|Write|Edit",
        "hooks": [{
          "type": "command",
          "command": "straylight-mcp hook pretooluse"
        }]
      }],
      "PostToolUse": [{
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "straylight-mcp hook posttooluse"
        }]
      }]
    }
  }
  ```

**Implementation notes**:
- Hooks run on the HOST, so they use the straylight-mcp binary
- Add `hook` subcommand to straylight-mcp: `straylight-mcp hook pretooluse`
- The hook subcommand reads the JSON event from stdin, applies rules, and exits
- PreToolUse rules need the list of known credential env var names (fetched from
  container's service registry API)
- Cache the credential env var list (refresh every 60 seconds)

**Test strategy**:
- Unit test: PreToolUse blocks `echo $STRIPE_API_KEY` with exit code 2
- Unit test: PreToolUse allows `ls -la` with exit code 0
- Unit test: PostToolUse sanitizes credential patterns in output
- Integration test: hook receives Claude Code hook JSON format and responds correctly
- Test that hooks do not add significant latency (< 50ms per invocation)

**Done when**: PreToolUse blocks commands that would leak credentials and
suggests using straylight_exec. PostToolUse sanitizes credential patterns from
tool output. Both hooks integrate with Claude Code's settings.json format.

---

### WP-2.3: Additional OAuth Providers (Google, Stripe)

**Complexity**: M (Medium)
**Dependencies**: WP-1.7 (OAuth flow)
**Deliverables**:
- Google OAuth provider configuration
  - Authorization URL: `https://accounts.google.com/o/oauth2/v2/auth`
  - Token URL: `https://oauth2.googleapis.com/token`
  - Default scopes: configurable per use case
- Stripe OAuth (Stripe Connect) provider configuration
  - Authorization URL: `https://connect.stripe.com/oauth/authorize`
  - Token URL: `https://connect.stripe.com/oauth/token`
- Web UI "Connect with Google" and "Connect with Stripe" buttons
- Provider-specific token refresh implementations
- Updated service templates for Google and Stripe OAuth

**Test strategy**:
- Unit tests with mock OAuth providers for each new provider
- Test token refresh for each provider (different refresh flows)
- Test error handling for each provider's specific error responses

**Done when**: Users can connect Google and Stripe accounts via OAuth in the
Web UI, and the tokens are automatically refreshed when expired.

---

### WP-2.4: straylight_services Tool Enhancement

**Complexity**: S (Small)
**Dependencies**: WP-2.1 (command wrapper adds exec capability)
**Deliverables**:
- Update `straylight_services` response to include:
  - Credential status (available, expired, not_configured)
  - Capabilities per service (api_call, exec)
  - Base URL per service
  - OAuth scopes (if applicable)
- Add capability discovery: which tools can be used with each service
- Ensure the response format matches `contracts/mcp-tools.json`

**Test strategy**:
- Test with services of various types and statuses
- Test that response matches contract schema exactly
- Test empty state (no services) returns helpful message

**Done when**: `straylight_services` returns a complete, accurate capability
map that helps agents understand what they can do with each service.

---

### WP-2.5: Error Handling and Resilience

**Complexity**: M (Medium)
**Dependencies**: WP-2.1
**Deliverables**:
- Consistent error format across all endpoints (per `contracts/internal-api.yaml` ErrorResponse)
- OpenBao unavailable handling:
  - MCP tools return clear error: "Credential storage is temporarily unavailable"
  - Health endpoint shows degraded status
  - Web UI shows warning banner
- Proxy timeout handling: clear error with service name and timeout value
- OAuth token refresh failure: clear error suggesting re-authorization
- Request validation: reject malformed requests with specific field-level errors
- Structured logging: all errors logged with request ID, service name, error type
- Audit trail: log all credential access events (service, timestamp, tool used)

**Test strategy**:
- Test each error path produces correct error format
- Test OpenBao unavailability is handled gracefully (not a panic/crash)
- Test structured log output contains required fields
- Test audit log entries for credential access

**Done when**: Every error case returns a structured, helpful error message.
The system degrades gracefully when OpenBao is unavailable. All credential
access is audit-logged.

---

### WP-2.6: Security Hardening

**Complexity**: M (Medium)
**Dependencies**: WP-2.1, WP-2.2
**Deliverables**:
- Request rate limiting on API endpoints (prevent brute-force)
- CORS configuration (localhost only)
- Input sanitization on all API endpoints (prevent injection attacks)
- OpenBao policy review: minimum required permissions only
- Container security review:
  - Verify non-root execution
  - Verify no unnecessary capabilities
  - Verify port 9443 is not exposed
- Credential rotation support: update credential without service downtime
- Secrets in Docker logs: verify docker logs never contain credential values
- Add `--read-only` rootfs support (only /data is writable)

**Test strategy**:
- Security-focused test suite:
  - Attempt to read credentials via API (should never succeed)
  - Attempt to access OpenBao from host (should fail)
  - Send malformed JSON/headers (should not crash)
  - Send oversized requests (should be rejected)
  - Check Docker logs for credential values (should find none)
- Run a container security scanner (trivy/grype) on the image
- Verify CORS headers are set correctly

**Done when**: Security test suite passes. Container scan shows no critical
CVEs. No credential values appear in any logs or API responses.

---

### WP-2.7: Documentation and Release Preparation

**Complexity**: S (Small)
**Dependencies**: All other WPs
**Deliverables**:
- User-facing README.md with:
  - One-command install instructions
  - Service configuration guide
  - MCP integration guide for Claude Code
  - FAQ and troubleshooting
- `npx straylight-ai --help` output for all commands
- In-app help text for Web UI (tooltips, empty states)
- License file (MIT or Apache-2.0)
- GitHub Actions CI workflow:
  - Run tests on PR
  - Build Docker image on main
  - Push to GHCR on tag
  - Build and publish npm packages on tag
- CHANGELOG.md for v1.0.0

**Test strategy**:
- README instructions are verified end-to-end on a clean machine
- CI pipeline builds and tests successfully

**Done when**: A new user can follow the README, run `npx straylight-ai setup`,
and be making authenticated API calls through Claude Code within 5 minutes.

---

## Dependency Graph

```
Phase 0:
  WP-0.1 (Go skeleton)
    |
    +---> WP-0.2 (OpenBao supervisor)
    |       |
    |       +---> WP-0.4 (Docker image) --------+
    |       |                                     |
    |       +---> WP-0.5 (Volume setup)          |
    |                                             |
    +---> WP-0.3 (React shell) ---> WP-0.4 -----+
                                                  |
Phase 1:                                          |
  WP-0.2 -------> WP-1.1 (Service registry)      |
                    |                             |
                    +---> WP-1.2 (HTTP proxy) ----+-----> WP-1.4 (MCP handler)
                    |       |                     |         |
                    |       v                     |         v
                    |     WP-1.3 (Sanitizer) -----+       WP-1.5 (MCP binary)
                    |                             |         |
                    +---> WP-1.7 (OAuth/GitHub)   |         |
                    |                             |         |
  WP-0.3 -------> WP-1.6 (Web UI services) -----+         |
                                                  |         |
  WP-0.4 -------> WP-1.8 (npx package) ---------+---------+
                                                  |
                                                  v
                                          WP-1.9 (Integration test)

Phase 2:
  WP-1.3 + WP-1.1 -----> WP-2.1 (Command wrapper)
                            |
  WP-1.3 -------> WP-2.2 (Hooks)
                            |
  WP-1.7 -------> WP-2.3 (More OAuth)
                            |
  WP-2.1 -------> WP-2.4 (Services tool)
                            |
  WP-2.1 -------> WP-2.5 (Error handling)
                            |
  WP-2.1 + WP-2.2 -> WP-2.6 (Security hardening)
                            |
  All WPs -------> WP-2.7 (Docs + release)
```

## Complexity Summary

| Phase | Work Package | Complexity | Est. Effort |
|-------|-------------|------------|-------------|
| 0 | WP-0.1: Go skeleton | S | 1 day |
| 0 | WP-0.2: OpenBao supervisor | M | 3 days |
| 0 | WP-0.3: React shell | S | 1 day |
| 0 | WP-0.4: Docker image | M | 2 days |
| 0 | WP-0.5: Volume setup | S | 0.5 day |
| 1 | WP-1.1: Service registry | M | 3 days |
| 1 | WP-1.2: HTTP proxy | L | 4 days |
| 1 | WP-1.3: Output sanitizer | M | 2 days |
| 1 | WP-1.4: MCP internal handler | M | 2 days |
| 1 | WP-1.5: MCP host binary | M | 2 days |
| 1 | WP-1.6: Web UI services | M | 3 days |
| 1 | WP-1.7: OAuth (GitHub) | L | 4 days |
| 1 | WP-1.8: npx package | M | 3 days |
| 1 | WP-1.9: Integration test | S | 1 day |
| 2 | WP-2.1: Command wrapper | L | 3 days |
| 2 | WP-2.2: Claude Code hooks | M | 2 days |
| 2 | WP-2.3: More OAuth providers | M | 2 days |
| 2 | WP-2.4: Services tool | S | 0.5 day |
| 2 | WP-2.5: Error handling | M | 2 days |
| 2 | WP-2.6: Security hardening | M | 3 days |
| 2 | WP-2.7: Docs + release | S | 2 days |
| | | **Total** | **~44 days** |

## Cross-Cutting Concerns

### Testing Strategy (All Phases)

| Level | Scope | Tools | Coverage Target |
|-------|-------|-------|-----------------|
| Unit | Individual functions/methods | Go testing, Vitest | 80% |
| Integration | Component interactions | testcontainers-go | Key flows |
| E2E | Full system via MCP | Custom test harness | Happy path + errors |
| Security | Credential leakage | Custom assertions | 100% of credential paths |
| Performance | Proxy latency, sanitizer speed | Go benchmarks | < 20ms proxy, < 10ms sanitizer |

### Observability (All Phases)

- **Logging**: Structured JSON logs via `slog` package (Go 1.21+)
- **Health**: `/api/v1/health` endpoint with component-level status
- **Metrics**: (Phase 2) Basic counters: requests served, credentials accessed, errors
- **Audit**: OpenBao audit backend logs all secret access

### Security Invariants (Must Hold at All Times)

1. Credential values NEVER appear in MCP tool responses
2. Credential values NEVER appear in API GET responses
3. Credential values NEVER appear in logs (Docker logs, application logs, audit logs)
4. Credential values NEVER appear in config files
5. OpenBao is NEVER accessible from outside the container
6. The straylight-mcp host binary NEVER handles credential values
7. Output sanitizer runs on ALL text returned to agents (proxy responses + command output)

### Development Workflow

```bash
# Start OpenBao and Go backend (with hot reload)
docker-compose up openbao
air  # or: go run ./cmd/straylight/ serve

# Start React dev server (separate terminal)
cd web && npm run dev

# Run tests
go test ./...
cd web && npm test

# Build Docker image
docker build -t straylight .

# Full integration test
./scripts/integration-test.sh
```
