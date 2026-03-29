# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-03-29

### Changed
- Split Dashboard and Services into separate pages: Dashboard shows live metrics, audit breakdown, and activity feed; Services is dedicated to credential management
- Redesigned Help page with searchable content, quick nav, Key Concepts section, MCP tools reference, and collapsible FAQ
- Updated npm README with v1.0.0 features, dashboard documentation, and corrected volume info

### Added
- Dashboard metrics: 8 live metric cards (system health, vault status, uptime, service count, API calls, exec calls, audit events, credential access)
- Dashboard service status sidebar with direct links
- Dashboard audit breakdown with per-event-type bar charts
- Dashboard activity feed with event type badges and timestamps
- API client functions for `/api/v1/audit/stats` and `/api/v1/audit/events`
- Help page search filtering across all sections
- Help page Key Concepts section (zero-knowledge proxy, MCP, OpenBao vault, templates, audit trail, dynamic credentials)
- Help page MCP tools reference documenting all 7 tools
- GitHub Actions updated to Node.js 24 runtime (checkout v6, setup-node v6, setup-go v6, buildx v4, login v4, build-push v7)

## [0.5.0] - 2026-03-28

### Added
- Dynamic database credentials: temporary PostgreSQL, MySQL, and Redis users via OpenBao database secrets engine
- Cloud provider temporary credentials: AWS STS, GCP, and Azure ephemeral credential injection
- Project secret scanner: detect exposed secrets across 14 pattern categories via `straylight_scan` MCP tool
- Sensitive file firewall: redacted file reading via `straylight_read_file` MCP tool
- Credential audit trail: JSON Lines append-only logging of all credential access
- New MCP tools: `straylight_db_query`, `straylight_scan`, `straylight_read_file`
- Lease-aware credential cache for dynamic secrets with automatic renewal and revocation
- Enhanced Claude Code hooks: additional sensitive file patterns, connection string redaction
- Database and cloud service templates (PostgreSQL, MySQL, Redis, AWS, GCP, Azure)

### Fixed
- Vault ACL policy: `*` wildcard only matched one path segment, blocking credential writes to nested `services/{name}/credential` paths; added explicit `+` glob rules for sub-paths
- npm setup: replaced bind mount with named Docker volume (`straylight-ai-data`) so container UID 10001 can write to `/data` without host-side `mkdir`/`chown`

### Security
- Upgraded Go from 1.25.0 to 1.25.8 — fixes 14 stdlib CVEs across `net/url`, `crypto/tls`, `crypto/x509`, `net/http`, `encoding/asn1`, `encoding/pem`, and `os`
- Upgraded OpenBao from 2.5.1 to 2.5.2 — fixes CVE-2026-33757 (9.6 critical, session fixation) and CVE-2026-33758 (9.4 critical, XSS), plus 4 high-severity CVEs
- Upgraded Alpine base image from 3.21 to 3.23
- Upgraded `filippo.io/edwards25519` from v1.1.0 to v1.2.0 (CVE-2026-26958)
- Pinned Go builder image to `golang:1.25.8-alpine`
- Fixed npm dependency vulnerabilities in `brace-expansion` and `picomatch`

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
