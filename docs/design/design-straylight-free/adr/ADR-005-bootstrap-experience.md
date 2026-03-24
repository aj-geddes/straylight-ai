# ADR-005: Bootstrap Experience Strategy

**Date**: 2026-03-22
**Status**: Proposed

## Context

The architecture specifies `npx straylight-ai` as the bootstrap command. This must:
1. Pull and start the Docker container
2. Wait for health check to pass
3. Open the Web UI in the browser
4. Optionally register the MCP server with Claude Code

The bootstrap must work on macOS (Docker Desktop), Linux (Docker/Podman), and Windows
(Docker Desktop/WSL2). The user should go from zero to working in under 5 minutes with
a single command.

## Decision Drivers

- **One-command setup**: `npx straylight-ai` does everything
- **Cross-platform**: macOS, Linux, Windows
- **Idempotent**: Running again should not break existing setup
- **No runtime dependency leak**: npm package should not require Go, Rust, etc.
- **MCP registration**: Should handle `claude mcp add` automatically if Claude Code is detected

## Options Considered

### Option 1: npm package with Node.js CLI that orchestrates Docker

A lightweight Node.js CLI published to npm. It shells out to `docker` (or `podman`) to
pull the image, create the container, and manage lifecycle. The same npm package also
ships platform-specific Go binaries for the MCP server (via optionalDependencies).

**Pros**:
- `npx straylight-ai` works immediately (npm is ubiquitous)
- Node.js CLI can detect Docker/Podman, check versions, provide helpful errors
- Can bundle MCP binary via optionalDependencies (proven pattern: esbuild, turbo)
- Interactive prompts for configuration if needed
- Can detect Claude Code and auto-register MCP server
- Idempotent: checks for existing container before creating

**Cons**:
- Requires Node.js 18+ on the host (but any developer using Claude Code has this)
- npm package must handle 5 platform variants for MCP binary
- Docker image pull on first run adds 30-60 seconds

### Option 2: Shell script (curl | bash pattern)

A single shell script that the user downloads and runs. Handles Docker setup directly.

**Pros**:
- No Node.js dependency
- Simple, transparent, auditable
- Works on any Unix-like system

**Cons**:
- No Windows support without WSL
- No interactive prompts (or requires fzf/dialog)
- `curl | bash` has security stigma
- Cannot bundle MCP binary (must download separately)
- No version management or update mechanism
- Error handling in shell is fragile

### Option 3: Standalone Go CLI distributed via Homebrew/apt/scoop

A Go binary that handles everything: Docker management, MCP server, and bootstrap.

**Pros**:
- Single binary, no runtime dependencies
- Cross-platform with native binaries
- MCP server is built into the same binary

**Cons**:
- Requires installing via brew/apt/scoop (extra step vs npx)
- Package manager coverage is uneven (no single universal installer)
- More friction than `npx` (users must add a tap or PPA)
- Cannot leverage npm ecosystem for distribution

## Decision

Chose **Option 1: npm package with Docker orchestration** because:

1. **npx is the lowest-friction install path**. Every developer with Claude Code already
   has Node.js. `npx straylight-ai` requires zero pre-installation.

2. **The optionalDependencies pattern is proven**. esbuild, turbo, and SWC all distribute
   platform-specific binaries via npm. The MCP host binary fits this pattern perfectly.

3. **Interactive CLI improves DX**. The npm package can use `inquirer` or `prompts` for
   guided setup, detect the environment, and provide clear error messages when Docker is
   not available.

4. **Idempotent lifecycle management**. The CLI can detect existing containers, check
   versions, and handle upgrades gracefully -- something shell scripts struggle with.

## Consequences

**Positive**:
- One-command bootstrap: `npx straylight-ai`
- MCP binary distributed alongside CLI (no separate install)
- Interactive setup with environment detection
- Version management via npm

**Negative**:
- Requires Node.js 18+ (acceptable for the target audience)
- npm optionalDependencies adds build/publish complexity
- Must maintain 5 platform-specific binary packages

**Risks**:
- npm registry downtime blocks installation. Mitigation: Docker image is independent;
  manual setup is documented as fallback.
- optionalDependencies fail to install on exotic platforms. Mitigation: detect failure
  and provide manual binary download instructions.

**Tech Debt**: None. This is standard practice for CLI tools targeting developers.

## Implementation Notes

### npm Package Structure

```
straylight-ai/
  package.json
  bin/
    cli.js                    -- Main CLI entry point
    mcp-shim.js               -- MCP binary launcher
  src/
    commands/
      start.ts                -- Pull image, create/start container
      stop.ts                 -- Stop container
      setup.ts                -- Full bootstrap (start + register MCP)
      status.ts               -- Check container and service health
      logs.ts                 -- Stream container logs
    docker.ts                 -- Docker/Podman detection and management
    mcp-register.ts           -- Claude Code MCP registration
    health.ts                 -- Health check polling
    config.ts                 -- User configuration management
  README.md
```

### CLI Commands

```bash
npx straylight-ai              # Interactive setup wizard
npx straylight-ai start        # Start container (pull if needed)
npx straylight-ai stop         # Stop container
npx straylight-ai status       # Show health and service status
npx straylight-ai setup        # Full bootstrap: start + register MCP + open UI
npx straylight-ai logs         # Stream container logs
npx straylight-ai mcp-register # Register MCP server with Claude Code
npx straylight-ai update       # Pull latest image, restart container
```

### Bootstrap Flow (`npx straylight-ai setup`)

```
1. Detect Docker or Podman (error with install instructions if missing)
2. Check for existing straylight-ai container
   a. If exists and running: skip to step 5
   b. If exists and stopped: start it
   c. If not exists: continue to step 3
3. Create data directory: ~/.straylight-ai/data/
4. Pull and start container:
   docker run -d \
     --name straylight-ai \
     -p 9470:9470 \
     -v ~/.straylight-ai/data:/data \
     --restart unless-stopped \
     ghcr.io/aj-geddes/straylight-ai:latest
5. Poll health endpoint until ready (max 30s)
6. Detect Claude Code installation
   a. If found: run `claude mcp add --transport stdio straylight -- straylight-mcp`
   b. If not found: print manual registration instructions
7. Open http://localhost:9470 in default browser
8. Print success message with next steps
```

### MCP Binary Distribution

```json
{
  "name": "straylight-ai",
  "version": "1.0.0",
  "bin": {
    "straylight-ai": "./bin/cli.js",
    "straylight-mcp": "./bin/mcp-shim.js"
  },
  "optionalDependencies": {
    "@straylight-ai/bin-linux-x64": "1.0.0",
    "@straylight-ai/bin-linux-arm64": "1.0.0",
    "@straylight-ai/bin-darwin-x64": "1.0.0",
    "@straylight-ai/bin-darwin-arm64": "1.0.0",
    "@straylight-ai/bin-win32-x64": "1.0.0"
  }
}
```

Each platform package contains a single Go binary:
```json
{
  "name": "@straylight-ai/bin-darwin-arm64",
  "os": ["darwin"],
  "cpu": ["arm64"],
  "files": ["straylight-mcp"]
}
```

### mcp-shim.js

```javascript
#!/usr/bin/env node
const { execFileSync } = require('child_process');
const path = require('path');
const os = require('os');

const platform = os.platform();
const arch = os.arch();
const binName = platform === 'win32' ? 'straylight-mcp.exe' : 'straylight-mcp';

try {
  const binPkg = `@straylight-ai/bin-${platform}-${arch}`;
  const binPath = path.join(require.resolve(binPkg + '/package.json'), '..', binName);
  const child = require('child_process').spawn(binPath, [], {
    stdio: 'inherit'
  });
  child.on('exit', (code) => process.exit(code));
} catch (err) {
  console.error(`Straylight-AI MCP binary not available for ${platform}-${arch}`);
  console.error('Please see https://straylight.dev/install for manual installation.');
  process.exit(1);
}
```

## Validation Criteria

- `npx straylight-ai setup` completes in < 60 seconds (excluding Docker image pull)
- Running `npx straylight-ai setup` twice is idempotent (does not create duplicate containers)
- CLI detects missing Docker and prints actionable error message
- MCP binary is found and executable on all 5 target platforms
- Claude Code MCP registration succeeds when Claude Code is installed
- Container starts with correct port mapping and volume mount
- Health check passes within 10 seconds of container start
