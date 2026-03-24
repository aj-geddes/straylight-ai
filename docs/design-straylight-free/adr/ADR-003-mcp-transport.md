# ADR-003: MCP Server Transport Choice

**Date**: 2026-03-22
**Status**: Proposed

## Context

Straylight-AI exposes four MCP tools to AI agents: `straylight_api_call`,
`straylight_exec`, `straylight_check`, and `straylight_services`. The MCP server must
be accessible from Claude Code, Cursor, and any other MCP-compatible client.

The MCP specification (2025-11-25) supports two official transports: stdio and Streamable
HTTP. The choice affects how the MCP server is registered, how it communicates with the
host process, and what deployment constraints apply.

## Decision Drivers

- **Client compatibility**: Must work with Claude Code's `claude mcp add` command
- **Simplicity**: Fewer moving parts for localhost use
- **Latency**: Agent tool calls should be fast
- **Security**: No network exposure for credential operations
- **Container interaction**: MCP server runs inside Docker; agent runs on host

## Options Considered

### Option 1: stdio transport (MCP server binary runs on host, communicates with container)

The MCP server binary runs directly on the host machine as a child process of Claude Code.
It communicates with the Straylight-AI container via localhost HTTP (the internal API).
Claude Code launches the binary via `claude mcp add --transport stdio straylight -- straylight-mcp`.

**Pros**:
- Standard pattern for Claude Code MCP servers
- Simple registration: `claude mcp add --transport stdio straylight -- straylight-mcp`
- No port exposure needed for MCP protocol
- Lowest latency (direct stdin/stdout pipe to Claude Code)
- Works with all MCP clients that support stdio

**Cons**:
- Requires a binary on the host (not just in the container)
- Binary must be installed/distributed separately from the container
- Two components: container + host binary

### Option 2: stdio transport via `docker exec`

Claude Code launches `docker exec straylight-ai straylight-mcp` as the stdio command.
The MCP server runs inside the container.

**Pros**:
- No separate host binary needed
- MCP server has direct access to OpenBao (same container)
- Single deployable unit

**Cons**:
- Requires Docker socket access from Claude Code
- `docker exec` adds 200-500ms startup latency per invocation
- Container name must be deterministic and known
- Some MCP clients may not support complex exec commands
- Process lifecycle is awkward (exec'd process vs container lifecycle)

### Option 3: Streamable HTTP transport

The MCP server listens on a localhost HTTP port (e.g., :9471) and Claude Code connects
via HTTP. Registration: `claude mcp add --transport http straylight http://localhost:9471/mcp`.

**Pros**:
- MCP server runs entirely inside the container
- No host binary needed
- Single port for both MCP and Web UI

**Cons**:
- HTTP transport adds overhead vs direct stdio pipe
- Exposes another port (or must multiplex on existing port)
- Not all MCP clients support HTTP transport yet
- Claude Code historically favors stdio for local servers
- More complex protocol (HTTP + SSE for server-initiated messages)

## Decision

Chose **Option 1: stdio transport with host binary** because:

1. **Best MCP client compatibility**. stdio is the universal transport. Every MCP client
   supports it. Claude Code, Cursor, and future clients all treat stdio as the default.

2. **Lowest latency**. The host binary communicates with Claude Code via direct pipe
   (zero network overhead for the MCP protocol) and with the container via localhost
   HTTP (negligible overhead for credential operations).

3. **Clean separation of concerns**. The thin host binary handles only MCP protocol
   translation. It calls the container's internal API for actual credential operations.
   This means the host binary has zero secrets -- it is a pure protocol adapter.

4. **Natural distribution via npm**. The `npx straylight-ai` bootstrap command already
   ships an npm package. Including the MCP binary (or a Node.js shim that invokes it)
   in the same package provides a single install path. The npm package can bundle
   platform-specific Go binaries using the standard optionalDependencies pattern.

### Architecture

```
Claude Code                                  Docker Container
+-------------+     stdio      +---------+     HTTP      +------------------+
|  MCP Client |<-------------->| MCP     |<------------>|  Straylight-AI   |
|             |  (stdin/stdout)| Binary  | localhost:9470|  Core Server     |
+-------------+                +---------+               +------------------+
                               (host)                     (container)
```

The host binary is ~5 MB, statically linked, and performs no credential handling.

## Consequences

**Positive**:
- Works with every MCP client out of the box
- Host binary is stateless and credential-free (zero-knowledge design preserved)
- Can be distributed as part of the npm package
- Fastest possible MCP communication path

**Negative**:
- Requires distributing a platform-specific binary to the host
- Two components to version (host binary + container) -- though they share the same
  version and the binary is thin enough that compatibility is trivial
- Extra HTTP hop for credential operations (host -> container)

**Risks**:
- Platform compatibility for the host binary. Mitigation: build for linux/amd64,
  linux/arm64, darwin/amd64, darwin/arm64, windows/amd64. Distribute via npm
  optionalDependencies pattern (same as esbuild, turbo, etc.).
- Container not running when MCP binary starts. Mitigation: MCP binary checks
  container health at startup and returns clear MCP error responses if unavailable.

**Tech Debt**: None. This is the standard, well-understood pattern for MCP servers.

## Implementation Notes

### Host Binary (`straylight-mcp`)

Responsibilities:
- Read JSON-RPC 2.0 messages from stdin
- For tool/call and tool/list, forward to container's internal API at localhost:9470
- Write JSON-RPC 2.0 responses to stdout
- Health check the container on startup; emit MCP error if unavailable

Registration command:
```bash
claude mcp add --transport stdio straylight -- straylight-mcp
```

Or via the bootstrap script:
```bash
npx straylight-ai setup  # Starts container AND registers MCP server
```

### Internal API (Container, port 9470)

The container exposes an HTTP API that the MCP host binary calls:

```
POST /api/v1/mcp/tool-call
  Request:  { "tool": "straylight_api_call", "arguments": { ... } }
  Response: { "content": [ { "type": "text", "text": "..." } ] }

GET /api/v1/mcp/tool-list
  Response: { "tools": [ ... ] }

GET /api/v1/health
  Response: { "status": "ok", "openbao": "unsealed", "services": 3 }
```

### npm Distribution

```json
{
  "name": "straylight-ai",
  "bin": {
    "straylight-ai": "./bin/cli.js",
    "straylight-mcp": "./bin/mcp-shim.js"
  },
  "optionalDependencies": {
    "@straylight-ai/binary-linux-x64": "1.0.0",
    "@straylight-ai/binary-linux-arm64": "1.0.0",
    "@straylight-ai/binary-darwin-x64": "1.0.0",
    "@straylight-ai/binary-darwin-arm64": "1.0.0",
    "@straylight-ai/binary-win32-x64": "1.0.0"
  }
}
```

The `straylight-mcp` shim locates the platform-specific binary and execs it.

## Validation Criteria

- `claude mcp add --transport stdio straylight -- straylight-mcp` succeeds
- Claude Code can call `straylight_services` and receive a valid response
- MCP binary starts in < 100ms
- MCP binary returns clear error if container is not running
- Tool calls complete within 200ms (including container round-trip)
- Zero secrets pass through the host binary (verified by logging all stdio traffic)
