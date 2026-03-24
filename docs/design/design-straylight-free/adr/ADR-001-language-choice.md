# ADR-001: Primary Language Choice

**Date**: 2026-03-22
**Status**: Proposed

## Context

Straylight-AI Personal requires a backend that handles:
- HTTP reverse proxy with credential injection
- MCP server over stdio transport (JSON-RPC 2.0)
- Process spawning and output sanitization for command wrapping
- Communication with OpenBao for secret retrieval
- Serving a React SPA for the Web UI
- OAuth flow handling

The chosen language must produce a single deployable artifact, handle concurrent
connections efficiently, and interoperate with OpenBao (itself written in Go). The
container image should be small and start fast.

## Decision Drivers

- **Interoperability with OpenBao**: OpenBao is Go; its client libraries are Go-native
- **Performance**: Proxy adds latency to every agent API call; must be minimal
- **Single binary**: Simplifies container image and reduces attack surface
- **MCP SDK availability**: Official Go SDK exists (github.com/modelcontextprotocol/go-sdk)
- **Developer velocity**: Team familiarity, ecosystem maturity
- **Container size**: Smaller image = faster bootstrap

## Options Considered

### Option 1: Go (single binary for all backend components)

**Pros**:
- Native OpenBao client library (github.com/openbao/openbao/api/v2)
- Official MCP Go SDK (github.com/modelcontextprotocol/go-sdk) with stdio support
- Single statically-linked binary, no runtime dependencies
- Excellent HTTP reverse proxy support (net/http/httputil.ReverseProxy)
- Built-in concurrency (goroutines) for handling multiple agent requests
- Go embed for bundling React SPA assets
- Container image can use scratch/distroless base (< 30 MB)
- Sub-second startup time
- Strong subprocess management (os/exec)

**Cons**:
- Slower iteration cycle than Node.js for rapid prototyping
- Less ergonomic for complex JSON transformation
- Go error handling is verbose

### Option 2: Node.js (TypeScript) for all backend components

**Pros**:
- Same language as React frontend (shared types)
- Fastest iteration speed
- Rich npm ecosystem for OAuth, HTTP proxy libraries
- TypeScript MCP SDK is the reference implementation (most mature)
- Natural fit for the npx bootstrap package

**Cons**:
- Requires Node.js runtime in container (larger image, ~150 MB vs ~30 MB)
- OpenBao client library is less mature in Node.js (HTTP API wrapper only)
- Single-threaded event loop; CPU-bound sanitization blocks other requests
- No static binary; dependency management in container is more complex
- Slower cold start than Go binary

### Option 3: Hybrid (Go backend + Node.js MCP server)

**Pros**:
- Go handles proxy, OpenBao, OAuth (plays to Go strengths)
- Node.js handles MCP stdio (uses reference TypeScript SDK)
- Each component uses its best-fit language

**Cons**:
- Two runtimes in container (Go binary + Node.js)
- Inter-process communication needed between MCP server and proxy
- More complex build pipeline and Dockerfile
- Harder to debug; two process trees to monitor
- Larger container image
- Configuration duplication between components

## Decision

Chose **Option 1: Go** because:

1. **OpenBao interoperability is critical**. The Go client library is first-party, well-maintained, and avoids HTTP API translation overhead. Since OpenBao communication is on the hot path (every credential lookup), native Go integration reduces latency.

2. **The MCP Go SDK is official and stable**. The modelcontextprotocol/go-sdk is maintained by Anthropic in collaboration with Google, supports stdio transport natively, and generates JSON schema from Go structs -- reducing boilerplate.

3. **Single binary simplifies everything**. One binary in a scratch container means: smaller image, faster pulls, no dependency CVEs from runtime, trivial Dockerfile, and predictable startup behavior.

4. **Proxy performance matters**. Every agent API call transits the proxy. Go's net/http and httputil.ReverseProxy are production-proven (used by Caddy, Traefik, etc.) and add negligible latency.

5. **Go embed bundles the React SPA**. The `embed` package compiles the built React assets into the Go binary itself, eliminating the need for a separate static file server or Node.js runtime for the UI.

## Consequences

**Positive**:
- Container image under 50 MB including OpenBao binary
- Sub-second startup time
- Single process to monitor and debug
- Native OpenBao integration with full feature access
- Statically linked binary eliminates shared library issues

**Negative**:
- Go has a steeper learning curve than Node.js for frontend developers
- JSON handling is more verbose than JavaScript
- Test iteration is slower than Node.js (compile step required)

**Risks**:
- Go MCP SDK may lag behind TypeScript SDK in feature releases. Mitigation: the spec is stable; stdio transport is frozen; we only need tool registration which is well-supported.
- OpenBao Go client API is technically "unsupported for embedding." Mitigation: we use it as a client library (api/v2), not embedding the server; client API is stable and widely used.

**Tech Debt**: None anticipated. Go is the natural choice for this problem domain.

## Implementation Notes

- Use Go 1.22+ for improved routing (net/http.ServeMux pattern matching)
- Use `go:embed` directive to bundle React build output
- Structure as a Go module at `github.com/aj-geddes/straylight-ai`
- Key packages:
  - `cmd/straylight/` -- main entry point
  - `internal/proxy/` -- HTTP reverse proxy with credential injection
  - `internal/mcp/` -- MCP server tool implementations
  - `internal/vault/` -- OpenBao client wrapper
  - `internal/sanitizer/` -- Output sanitization engine
  - `internal/oauth/` -- OAuth flow handler
  - `internal/config/` -- Configuration management
  - `web/` -- React SPA source; `web/dist/` embedded at build time

## Validation Criteria

- Go binary compiles and runs on linux/amd64 and linux/arm64
- MCP server responds to tool/list and tool/call over stdio
- Proxy adds < 20ms latency to forwarded requests (measured by benchmark test)
- Container image size < 50 MB (excluding OpenBao)
