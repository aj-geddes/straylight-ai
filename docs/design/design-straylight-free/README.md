# Straylight-AI Personal (Free) -- Design Package

**Date**: 2026-03-22
**Status**: Proposed
**Author**: Architect Agent

## Summary

Straylight-AI Personal is a zero-knowledge credential proxy for AI agents. It runs
as a single Docker container on localhost, providing an MCP server interface that lets
AI coding assistants (Claude Code, Cursor, etc.) make authenticated API calls and run
credentialed commands without ever seeing the secrets.

## Key Decisions

| Decision | Choice | ADR |
|----------|--------|-----|
| Primary language | Go (single binary) | ADR-001 |
| OpenBao integration | Sidecar process in same container | ADR-002 |
| MCP server transport | stdio via Go official SDK | ADR-003 |
| Web UI build strategy | React SPA embedded in Go binary via `embed` | ADR-004 |
| Bootstrap experience | npm package wrapping Docker CLI | ADR-005 |
| Container packaging | Single multi-stage Dockerfile | ADR-006 |

## Architecture Overview

```
+------------------------------------------------------------------+
|                    Docker Container (localhost)                     |
|                                                                    |
|  +------------------+    +------------------+    +--------------+  |
|  |  Straylight-AI   |    |  Straylight-AI   |    | Straylight   |  |
|  |  Web UI (React)  |<-->|  Core (Go)       |<-->| MCP Server   |  |
|  |  :9470           |    |  API + Proxy     |    | (stdio)      |  |
|  +------------------+    +------------------+    +--------------+  |
|                               |       |                            |
|                               v       v                            |
|                          +-----------------+                       |
|                          |   OpenBao       |                       |
|                          |   (sidecar)     |                       |
|                          |   :9443         |                       |
|                          +-----------------+                       |
|                               |                                    |
|                               v                                    |
|                     ~/.straylight-ai/data/                         |
+------------------------------------------------------------------+
```

## Success Metrics

| Metric | Target |
|--------|--------|
| Bootstrap to first API call | < 5 minutes |
| Container startup time | < 3 seconds |
| API call latency overhead | < 50ms |
| Memory footprint (idle) | < 100 MB |
| Zero secret exposure in agent context | 100% (verified by integration tests) |

## Package Contents

```
docs/design-straylight-free/
  README.md                          -- This file
  adr/
    ADR-001-language-choice.md       -- Go as primary language
    ADR-002-openbao-integration.md   -- OpenBao sidecar strategy
    ADR-003-mcp-transport.md         -- stdio transport with Go SDK
    ADR-004-web-ui-strategy.md       -- React embedded in Go binary
    ADR-005-bootstrap-experience.md  -- npx package wrapping Docker
    ADR-006-container-packaging.md   -- Single multi-stage Dockerfile
  diagrams/
    component-diagram.md             -- Component boundaries and interfaces
    data-flow.md                     -- Request lifecycle diagrams
    sequence-diagrams.md             -- Key interaction sequences
  contracts/
    mcp-tools.json                   -- JSON Schema for all 4 MCP tools
    internal-api.yaml                -- Internal HTTP API (Web UI <-> Core)
  schemas/
    config-schema.yaml               -- Configuration file schema
    service-registry.md              -- Service definition data model
  implementation-guide.md            -- Phased build plan for Developer agent
```
