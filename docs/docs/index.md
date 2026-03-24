---
layout: doc
title: "Documentation"
description: "Straylight-AI documentation: quickstart, user guide, MCP tool reference, service templates, configuration, troubleshooting, and FAQ."
permalink: /docs/
toc: false
---

Welcome to the Straylight-AI documentation. Straylight-AI is a self-hosted Docker container
that keeps your API keys out of AI agent context windows using zero-knowledge credential injection.

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

### [FAQ](/straylight/docs/faq/)

Answers to questions about security guarantees, compatibility, what happens on container restart,
how it compares to alternatives, and how to add custom services.

## Reference

- [Features](/straylight/features/) — Detailed breakdown of each feature with diagrams
- [Architecture](/straylight/architecture/) — Container internals, data flow, security layers, tech stack

## Quick Links

- [GitHub Repository](https://github.com/straylight-ai/straylight)
- [Report a Bug](https://github.com/straylight-ai/straylight/issues)
- [Releases](https://github.com/straylight-ai/straylight/releases)

## Prerequisites

- Docker Desktop or Docker Engine installed and running
- Node.js 18+ (for `npx straylight-ai`)
- Claude Code, Cursor, or any MCP-compatible client
