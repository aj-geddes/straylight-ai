---
layout: doc
title: "Documentation"
description: "Straylight-AI documentation: quickstart, user guide, MCP tool reference, service templates, database credentials, cloud credentials, secret scanner, file firewall, audit trail, configuration, troubleshooting, and FAQ."
permalink: /docs/
toc: false
---

Welcome to the Straylight-AI documentation. Straylight-AI is a self-hosted Docker container
that keeps your API keys out of AI coding assistant context windows using zero-knowledge credential injection.

## Getting Started

The fastest path from zero to working setup:

| Step | Page | Time |
|------|------|------|
| 1. Install and start | [Quickstart](/straylight/docs/quickstart/) | ~2 min |
| 2. Add your services | [User Guide — Adding Services](/straylight/docs/user-guide/#adding-services) | ~5 min |
| 3. Connect Claude Code | [Quickstart — Connect Claude Code](/straylight/docs/quickstart/#connect-claude-code) | ~1 min |

## Documentation Sections

### [Quickstart](/straylight/docs/quickstart/)

Install Straylight-AI with a single command, add your first service, and make your first
zero-knowledge API call. Includes verification steps to confirm credentials never appear in output.

### [User Guide](/straylight/docs/user-guide/)

Complete reference for the dashboard UI, all 16 service templates, MCP tool parameters,
configuration options, and troubleshooting common issues.

**New in v0.2.0:**

- [Database Credentials](/straylight/docs/user-guide/#database-credentials) — Connect PostgreSQL, MySQL, or Redis. Straylight provisions temporary, scoped database users per query and revokes them automatically.
- [Cloud Provider Credentials](/straylight/docs/user-guide/#cloud-provider-credentials) — Configure AWS, GCP, or Azure for temporary credential injection. The AI runs CLI commands without seeing access keys or service account credentials.
- [Secret Scanner](/straylight/docs/user-guide/#secret-scanner) — Scan a project directory for exposed secrets across 14 pattern categories. Generate ignore rules for `.claudeignore`, `.cursorignore`, and similar files.
- [Sensitive File Firewall](/straylight/docs/user-guide/#sensitive-file-firewall) — Use `straylight_read_file` to read configuration files with secrets automatically redacted. Blocked files return a helpful message instead of credential values.
- [Credential Audit Trail](/straylight/docs/user-guide/#credential-audit-trail) — Every MCP tool call is logged in an append-only JSON Lines file. Query events via the REST API or read log files directly.

### [FAQ](/straylight/docs/faq/)

Answers to questions about security guarantees, compatibility, database credential safety,
what the scanner detects, file firewall behavior, what happens on container restart, and how to add custom services.

## Reference

- [Features](/straylight/features/) — Detailed breakdown of each feature with diagrams
- [Architecture](/straylight/architecture/) — Container internals, data flow, security layers, tech stack

## Quick Links

- [GitHub Repository](https://github.com/aj-geddes/straylight-ai)
- [Report a Bug](https://github.com/aj-geddes/straylight-ai/issues)
- [Releases](https://github.com/aj-geddes/straylight-ai/releases)

## Prerequisites

- Docker Desktop or Docker Engine installed and running
- Node.js 18+ (for `npx straylight-ai`)
- Claude Code, Cursor, or any MCP-compatible client
