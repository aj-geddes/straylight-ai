# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-22

### Added

- Zero-knowledge credential proxy for AI agents — credentials stored in
  encrypted vault, injected at the HTTP transport layer, never passed to the
  agent context window
- MCP server with four tools:
  - `straylight_api_call` — authenticated HTTP requests with credential injection
  - `straylight_exec` — command execution with credentials injected as environment variables
  - `straylight_check` — credential availability and validity check
  - `straylight_services` — service discovery with capability and status listing
- Web UI dashboard (React + Tailwind) for service management:
  - Template-driven service configuration (Stripe, GitHub, OpenAI, and custom)
  - Paste-key dialog with masked input, cleared after save
  - Service tiles with live credential status indicators
  - OAuth connect buttons with browser-based authorization flow
- OAuth support for GitHub, Google, and Stripe Connect with automatic token
  refresh
- Output sanitization engine — two-layer detection (regex pattern matching and
  stored-value matching) replaces credential patterns with `[REDACTED:service-name]`
- Claude Code hooks integration:
  - `PreToolUse` hook blocks Bash/Write/Edit tools that reference credential
    environment variables
  - `PostToolUse` hook sanitizes tool output for credential patterns
- Docker container with OpenBao (encrypted-at-rest credential storage):
  - Multi-stage build: React SPA, Go binary, Alpine runtime
  - Auto-initialization and auto-unseal of OpenBao on first start
  - Non-root execution (UID 10001)
  - Health endpoint at `GET /api/v1/health`
  - Persistent volume at `/data` for credentials and configuration
- `npx straylight-ai` bootstrap CLI:
  - Detects Docker or Podman automatically
  - Pulls image, creates container, mounts data volume
  - Polls health endpoint until ready
  - Auto-registers MCP server with Claude Code if installed
  - Opens dashboard in default browser
  - Idempotent: safe to run multiple times
- GitHub Actions CI pipeline:
  - Go tests and vet on every PR and push to main
  - React web UI build and tests
  - npm package build and tests
  - Docker multi-arch image (linux/amd64, linux/arm64) published to GHCR on release
  - npm package published on release
