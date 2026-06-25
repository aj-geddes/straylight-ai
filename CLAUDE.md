# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Straylight-AI is a **zero-knowledge credential proxy for AI coding assistants**. The AI calls
tools via MCP; Straylight injects the real credential into outbound HTTP requests / commands /
DB queries inside the proxy and sanitizes responses, so secrets never enter the AI's context.

One repo ships four artifacts:
- **`cmd/straylight`** — the core HTTP server (`straylight serve`), listens on `:9470`. Owns all
  credentials, the service registry, the OpenBao vault, the proxy, and the MCP tool logic.
- **`cmd/straylight-mcp`** — a thin **stdio↔HTTP shim** the AI assistant launches. Speaks MCP
  JSON-RPC over stdio and forwards every tool call to the core over `localhost:9470`. Also
  implements the Claude Code `hook pretooluse|posttooluse` subcommands. Contains **no** tool logic.
- **`web/`** — a React/Vite SPA dashboard, **compiled into the Go binary** via `go:embed`.
- **`npm/straylight-ai`** — the `npx straylight-ai` wrapper that orchestrates the Docker container.

Module path: `github.com/straylight-ai/straylight`. Go 1.25.8, Node 22 (CI), React 18 + Vite 5.

## Local setup (macOS / Homebrew)

```bash
brew install go            # 1.26.x is fine — it satisfies the `go 1.25.8` directive
brew install node@22       # REQUIRED for web tests (keg-only; see gotcha below). Your default Node can stay newer.
brew install openbao       # provides the `bao` binary; only needed to run the server natively
# Docker image builds also need Colima running on macOS: `colima start`
```

- **`go` / `bao`** land on `/opt/homebrew/bin` (already on PATH via `brew shellenv` in `~/.zprofile`) — no profile edits needed.
- The server resolves the OpenBao binary as `STRAYLIGHT_BAO_BIN` → `bao` on `PATH` → `/usr/local/bin/bao` (the container path), so a host-installed `bao` works natively (see `internal/vault/supervisor.go` `resolveBinaryPath`).
- **Web tests must run on Node 22.** Node 23+ ships an experimental built-in `localStorage` global that shadows jsdom's, so `npm test` in `web/` fails with `localStorage` `undefined` errors on a newer default Node. Run web tests with Node 22 on PATH, e.g. `PATH="/opt/homebrew/opt/node@22/bin:$PATH" npm test`. Go tests, `npm run build`, and the `npm/straylight-ai` wrapper tests are unaffected by Node version.

## Commands

There is **no Makefile** and **no golangci-lint config**. Go linting is `go vet`; web linting is `tsc --noEmit`.

```bash
# --- Go (run from repo root) ---
go build -o /tmp/straylight ./cmd/straylight/ && go build -o /tmp/straylight-mcp ./cmd/straylight-mcp/
go test ./...                                   # all unit tests (what CI runs)
go test ./internal/server/                      # one package
go test -run TestHealthEndpoint_ReturnsJSON ./internal/server/  # one test (add -v for verbose)
go test -tags=integration ./internal/integration/...   # integration tests (see gotcha #4)
go vet ./...                                     # the only Go linter wired into CI

# --- Web (run from web/) ---
cd web && npm ci
npm run build        # tsc && vite build -> web/dist
npm test             # vitest run (all)
npx vitest run api.client.test.ts   # one test file
npm run lint         # tsc --noEmit (type-check only)
npm run dev          # Vite dev server on :5173, proxies /api -> localhost:9470

# --- npm wrapper (run from npm/straylight-ai/) ---
cd npm/straylight-ai && npm ci && npm run build && npm test   # vitest 3.x (NOT the same vitest as web/)

# --- Docker / run (context MUST be repo root, not deploy/) ---
docker compose -f deploy/docker-compose.yml up --build   # hardened local run on :9470
docker buildx build --platform linux/amd64,linux/arm64 -f deploy/Dockerfile -t straylight-ai:local .

# --- Full integration suite (Go tests + live HTTP smoke + MCP stdio smoke) ---
./scripts/integration-test.sh        # env: STRAYLIGHT_PORT (default 19470), SKIP_GO_TESTS=1
```

**Local dev without Docker:** the server supervises a real OpenBao process. Run it with a writable data dir
(the default `/data` requires root); `bao` must be resolvable (on `PATH`, or via `STRAYLIGHT_BAO_BIN`):

```bash
STRAYLIGHT_DATA_DIR=/tmp/sl-data STRAYLIGHT_PORT=29470 go run ./cmd/straylight serve
cd web && npm run dev      # in another terminal: Vite on :5173, proxies /api -> :9470 (set the proxy port if not 9470)
```

The supervisor auto-generates its OpenBao config + storage under `$STRAYLIGHT_DATA_DIR/openbao/` when the
container's baked-in `/etc/straylight/openbao.hcl` is absent, so native boot needs no manual config. Verify with
`curl localhost:29470/api/v1/health` → `{"status":"ok","openbao":"unsealed",...}`.

## Architecture

### Two-binary split (the core mental model)
The AI process only ever sees stdio + the **shim** (`cmd/straylight-mcp`). All secrets, the service
registry, vault leases, and tool execution live behind the **core's** localhost API. The 7 MCP tools
are defined **once** in `internal/mcp/tools.go` (`toolDefinitions`) and served at `GET /api/v1/mcp/tool-list`;
the shim fetches that list at runtime and re-emits it, so **adding a tool needs no shim change**. Tool calls
go `POST /api/v1/mcp/tool-call` with body `{"tool": name, "arguments": {...}}`. Tool-level failures return
HTTP 200 with `isError: true` (only malformed/unknown-tool requests are 4xx).

### Boot order & dependency wiring (`cmd/straylight/main.go` `serve`)
`datadir.Initialize` → resolve port (flag `-p` > `STRAYLIGHT_PORT` env > 9470) → optional `config.yaml`
→ start **OpenBao** via `vault.Supervisor` (init/unseal/AppRole + background token renewal) → build
`services.Registry` (vault-backed) and `registry.LoadFromVault()` → `sanitizer` → `proxy` → `mcp.Handler`
→ `oauth.Handler` → `server.New(server.Config{...})` → `srv.Run()`. **The HTTP listener only starts after
the vault is unsealed.**

`server.Config` (`internal/server/server.go`) is the **dependency-injection seam** — every subsystem is a
field, and `registerRoutes` (`internal/server/routes.go`) is **nil-gated**: a nil dependency makes its routes
return `501`. This is what makes the server testable with `httptest` by passing only the deps a test needs —
**and** the source of gotcha #3.

### Credential-injection data flow (the zero-knowledge core)
`AI → POST /api/v1/mcp/tool-call → mcp.Handler → proxy.HandleAPICall` (`internal/proxy/proxy.go`):
resolve service → read credential from `services.Registry` (which reads OpenBao) → `resolveInjectionConfig`
maps the service's `auth_method` to an injector → one of 5 transport-layer injectors
(`internal/proxy/injectors.go`: bearer header, custom header, multi-header, query param, basic auth) mutates
the outbound `*http.Request` → call the real API → `sanitizer.Sanitize` scrubs the response → return to AI.
The credential never reaches the AI.

The **sanitizer** (`internal/sanitizer/`) is two-layer: exact value-matching (single `strings.Replacer`,
ignores values <8 chars) runs **before** regex pattern-matching, so a known secret is labeled
`[REDACTED:<service>]` rather than a generic type. Patterns (`patterns.go`) are also reused by `internal/scanner`
and `internal/firewall`. **The sanitizer is optional on the proxy (`NewProxy` accepts nil) — without it,
bodies pass through unredacted.**

### Vault / OpenBao
Single-node OpenBao bundled **into the same image** (not a sidecar), supervised from `main.go`, listening
only on `127.0.0.1:8200` (TLS disabled, never network-exposed). `secret_shares=1/threshold=1`. The unseal
key, root token, **and** AppRole RoleID/SecretID are all persisted together in plaintext at
`<data>/openbao/init.json` (0600) — **the security boundary is filesystem perms on that file, not the vault seal.**
The AppRole token (TTL 1h) is renewed every 30m by a background goroutine (added in 1.0.3 to fix a ~1h 403 bug).

### Dynamic credentials — three *different* models (`internal/{database,cloud,lease,oauth}`)
- **Database** creds are **true Vault dynamic secrets**: OpenBao runs `creation_statements` against the live
  DB to make a real temporary user, returns a lease, and **auto-revokes** it on expiry. Default creation SQL is
  **read-only** (`SELECT`). Default TTL 15m / max 1h. `internal/lease/` is the only component with active
  timer-based renewal/revocation. **Postgres/MySQL work; Redis is effectively a no-op** (empty creation
  statements, no DSN driver).
- **Cloud** creds are **not** Vault-managed: `internal/cloud/` calls the provider's own token API
  (AWS STS AssumeRole, GCP SA token, Azure client-credentials) and just caches by expiry — "revocation" is
  only provider-side expiry. Note: GCP/Azure are simplified HTTP POSTs, **not** Workload Identity Federation /
  token exchange despite the README framing; the GCP path is explicitly stubbed (won't auth against real Google).
- **OAuth** (`internal/oauth/`) is a separate concern: user-delegated OAuth 2.0 (auth-code + RFC 8628 device
  flow) for HTTP-proxy services. Tokens stored in OpenBao KV at `services/{name}/oauth_tokens`. No background
  refresh — `RefreshToken` is called on demand.

### Security feature packages (back the MCP tools)
- `internal/scanner/` → `straylight_scan`: walks a dir (skips `.git`, `node_modules`, vendor, binaries, files
  >1MiB), reuses `sanitizer.Patterns()` + scanner-only patterns, redacts matches in findings, optionally emits
  `.claudeignore`/`.cursorignore` rules.
- `internal/firewall/` → `straylight_read_file`: **blocks** fully-sensitive files (`.env`, `*.pem`, `id_rsa`,
  `credentials.json`, `init.json`, …) with a "use the vault" message; **redacts** structured config
  (YAML/JSON/TOML) by replacing sensitive key values with `[STRAYLIGHT:structured-key:<key>]`. Enforces a
  ProjectRoot boundary against symlink traversal.
- `internal/hooks/` → the `straylight-mcp hook` subcommands. **PreToolUse** blocks `$CRED_VAR` references and
  reads of sensitive files (exit 0=allow / 2=block) and **depends on the core being up** (calls
  `GET /api/v1/services`). **PostToolUse** sanitizes tool output and is **self-contained** (local sanitizer).
- `internal/cmdwrap/` → `straylight_exec`: runs a command with creds as env vars via **direct `exec` (no shell,
  no metachar evaluation)**, a minimal env (won't inherit parent env), `reservedEnvVars` protection (can't
  override `PATH`/`LD_PRELOAD`/…), 30s timeout, 1MiB output cap, sanitized stdout/stderr.
- `internal/audit/` → audit trail (in-memory ring buffer + daily `audit-YYYY-MM-DD.jsonl`). **Events log
  metadata only — never credential values.**

### Web dashboard (`web/`)
React 18 + react-router 7 + Tailwind 3 + Vite 5, tested with vitest 2 + jsdom + testing-library. Routes
(`web/src/App.tsx`): `/` Dashboard, `/services` Services, `/services/:name` ServiceConfig, `/help` Help — each
wrapped in `<Layout currentPath=…>`. All backend calls go through `web/src/api/client.ts` (plain `fetch`, no
Redux/Context/React-Query); pages poll independently (15s/30s) and degrade gracefully to defaults on error.
Built output is `go:embed`'d (`internal/web/embed.go`) and served by the Go binary at `/` with SPA fallback;
in dev, Vite proxies `/api` → `:9470`. Tests live in `web/src/__tests__/`. The UI shows the version it reads
from `/api/v1/health` at runtime, not from `web/package.json`.

## Critical gotchas

1. **Version sync — the #1 recurring pain (see git history).** There is no single source of truth for the
   release version. Bumping it requires editing the **same literal** in lockstep:
   `cmd/straylight/main.go:33` (`version`), `cmd/straylight-mcp/server.go:28` (`serverVersion`, a *separate*
   constant in a *separate* binary), `web/package.json`, `npm/straylight-ai/package.json`, `CHANGELOG.md`, and
   the **GitHub release tag** (CI uses it as the Docker image tag). **Plus** every test that hardcodes it, or
   `go test`/`npm test` fail: Go — `internal/server/{server_test.go(×11),security_test.go(×6),routes_mcp_test.go,
   routes_errors_test.go,routes_services_test.go,routes_cloud_test.go,routes_oauth_config_test.go}` and
   `cmd/straylight-mcp/mcp_test.go`; Web — `web/src/__tests__/{HealthBanner,api.client,Dashboard,Dashboard.stats}.test.tsx`.
   (The npm-wrapper tests use unrelated fixture versions and are *not* coupled.)

2. **Web build must precede the Go build.** `internal/web/embed.go` does `//go:embed all:dist` over
   `internal/web/dist/`, which holds a committed **placeholder** `index.html` for local dev. The Dockerfile
   builds `web/` first and overlays the real Vite output into `internal/web/dist` **before** `go build`. For a
   production-correct local binary, mirror that: `cd web && npm run build`, copy `web/dist` → `internal/web/dist`,
   then build Go.

3. **Several advertised features are implemented + tested but inert in the shipped binary.** `main.go:160` wires
   only `VaultStatus, Registry, OAuthHandler, MCPHandler` into `server.Config`, and `mcp.NewHandler(p, registry)`
   gets **no** `Set*` executors. Consequence at runtime: `straylight_api_call`, `straylight_check`,
   `straylight_services` fully work; `straylight_scan` works via a `scanner.New()` fallback; **`straylight_exec`,
   `straylight_db_query`, `straylight_read_file` return stub/"not configured" responses**; `/api/v1/audit/*` and
   `/api/v1/databases/*` return **501**; `/api/v1/stats` activity counters stay **0**. The handlers/executors all
   exist and are tested — they're just not wired in `serve`. Don't assume a feature is live just because the
   README, the route, or the tests describe it.

4. **`go test ./...` skips the integration tests.** `internal/integration/integration_test.go` has
   `//go:build integration`; run it with `-tags=integration` (the integration script does this).

5. **No authentication anywhere.** The trust boundary is localhost binding + a CORS allowlist
   (`localhost:9470`, `localhost:5173`, `127.0.0.1:9470`) in `internal/server/middleware.go`. There is no API
   token / auth middleware by design (personal-tier, plain HTTP on localhost — HSTS is only set when `r.TLS != nil`).

6. **Proxy credential cache is 60s.** On any service update/delete/rotate you must call
   `proxy.InvalidateCache(name)` or stale credentials are used for up to a minute (`RotateCredential`'s doc says so).

7. **Injector coverage gap.** The proxy's `DefaultInjectorRegistry` registers only 5 injection types; `oauth`
   and `named_strategy` auth methods (AWS SigV4, connection strings, SSH keys, GitHub App JWT, Google SA) are
   **not** HTTP-proxiable — they're storage/exec/DB-engine features, handled outside the proxy path.

8. **Stale value:** `cmd/straylight/main.go:253` reports `"go": "go1.24"` in the `version` subcommand even though
   the module/Dockerfile build with Go 1.25.8. Cosmetic, but update it when touching that area.
