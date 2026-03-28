# Straylight-AI

**Keep your API keys safe when using Claude Code, Cursor, and Windsurf.**

Straylight-AI is a self-hosted credential proxy that sits between your AI coding assistant and external APIs. Your keys are stored in an encrypted vault and injected at the HTTP transport layer — they never appear in the AI's context window, prompts, logs, or responses.

## Quick Start

```bash
npx straylight-ai
```

This will:
1. Pull and start the Straylight-AI container (Docker or Podman)
2. Open the dashboard at http://localhost:9470
3. Register the MCP server with Claude Code (if installed)

### Prerequisites

- Docker or Podman
- Node.js 18+

## Add a Service

1. Open http://localhost:9470
2. Click "Add Service"
3. Select a template (GitHub, Stripe, OpenAI, AWS, and more) or create a custom service
4. Paste your API key — it goes straight into the encrypted vault

## Connect to Your AI Coding Assistant

### Claude Code

If not auto-registered during setup:

```bash
claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp
```

### Cursor / Windsurf

Any MCP-compatible AI coding assistant works. The MCP server speaks the standard protocol over stdio.

## CLI Commands

| Command | Description |
|---------|-------------|
| `npx straylight-ai` | Full setup (pull, start, register) |
| `npx straylight-ai start` | Start the container |
| `npx straylight-ai stop` | Stop the container |
| `npx straylight-ai status` | Check health and service status |
| `npx straylight-ai logs` | View container logs |

## MCP Tools

Once registered, your AI coding assistant has access to:

| Tool | What It Does |
|------|-------------|
| `straylight_api_call` | Make an authenticated HTTP request. Credentials injected automatically. |
| `straylight_exec` | Run a command with credentials as environment variables. Output sanitized. |
| `straylight_db_query` | Query a database with dynamic temporary credentials. |
| `straylight_scan` | Scan project files for exposed secrets. |
| `straylight_read_file` | Read a file with secrets automatically redacted. |
| `straylight_check` | Check whether a credential is available for a service. |
| `straylight_services` | List all configured services and their status. |

## How It Works

```
AI Coding Assistant  -->  straylight-mcp (stdio)  -->  Straylight Container
                                                          |
                                                    OpenBao Vault (encrypted)
                                                          |
                                                    HTTP Proxy (injects credentials)
                                                          |
                                                    External API (Stripe, GitHub, ...)
```

Your AI assistant calls a Straylight MCP tool. The container fetches the credential from the vault, injects it into the outbound HTTP request, and returns the sanitized API response. The AI gets the data it needs without ever seeing the key.

## Database Credentials

Configure a database once in the dashboard. When your AI coding assistant needs data, it calls `straylight_db_query` — Straylight provisions a temporary database user, runs the query, and returns the results. The AI never sees the password.

```
// AI calls:
straylight_db_query(service="my-postgres", query="SELECT id, name FROM users LIMIT 10")
```

- Credentials are read-only by default and auto-expire (5–15 min TTL)
- Supported: PostgreSQL, MySQL/MariaDB, Redis
- [Full documentation](https://aj-geddes.github.io/straylight-ai/docs/database-credentials)

## Cloud Credentials

Configure an AWS, GCP, or Azure account in the dashboard. When the AI needs to run a cloud CLI command, it calls `straylight_exec` with a named service — Straylight generates short-lived temporary credentials, injects them as environment variables, and returns the sanitized output.

```
// AI calls:
straylight_exec(service="aws-prod", command="aws s3 ls s3://my-bucket")
```

- AWS: STS AssumeRole with inline session policies
- GCP: Workload Identity Federation tokens
- Azure: short-lived access tokens
- [Full documentation](https://aj-geddes.github.io/straylight-ai/docs/cloud-credentials)

## Secret Scanner

Scan your project for exposed secrets before the AI reads them. Straylight checks files against 14 pattern categories and reports findings by file, line, and type.

```
// AI calls:
straylight_scan(path="/home/user/my-project")
```

- Detects AWS keys, GitHub PATs, Stripe keys, connection strings, private keys, and more
- Returns file paths, line numbers, secret types, and severity
- [Full documentation](https://aj-geddes.github.io/straylight-ai/docs/secret-scanner)

## File Firewall

Let the AI read files it needs without exposing secrets. `straylight_read_file` serves file contents with credentials redacted. Blocked files (`.env`, `.pem`, `credentials.json`) return guidance to use the vault instead.

```
// AI calls:
straylight_read_file(path="docker-compose.yml")
// Returns: file structure with passwords replaced by [STRAYLIGHT:service-name]
```

- Blocked file patterns: `.env*`, `*credentials*`, `*secret*`, `*.pem`, SSH keys
- Legitimate files served clean — structure intact, secrets masked
- [Full documentation](https://aj-geddes.github.io/straylight-ai/docs/file-firewall)

## Audit Trail

Every credential access, API call, and command execution is logged with a timestamp, service name, tool used, and session ID. No credentials appear in the log.

View the audit log in the dashboard at http://localhost:9470 or query it via the API.

- Append-only local log, no retention cap on the free tier
- [Full documentation](https://aj-geddes.github.io/straylight-ai/docs/audit-trail)

## Supported Services

16+ pre-configured templates including GitHub, Stripe, OpenAI, Anthropic, AWS, Google Cloud, Azure, PostgreSQL, MySQL, Redis, Slack, GitLab, and more. Custom services supported via base URL and auth method configuration.

## Security

- **Encrypted at rest** — OpenBao (open-source HashiCorp Vault fork)
- **Transport-layer injection** — credentials never exposed to the AI
- **Output sanitization** — credential patterns stripped from all responses
- **Dynamic database credentials** — temporary users with automatic revocation
- **Non-root container** — UID 10001, minimal Alpine image

## Optional: Claude Code Hooks

For extra protection, add hooks that block credential-accessing commands and sanitize output:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Write|Edit",
      "hooks": [{ "type": "command", "command": "straylight-mcp hook pretooluse" }]
    }],
    "PostToolUse": [{
      "matcher": "Bash",
      "hooks": [{ "type": "command", "command": "straylight-mcp hook posttooluse" }]
    }]
  }
}
```

## Links

- [Documentation](https://aj-geddes.github.io/straylight-ai/docs/quickstart)
- [GitHub](https://github.com/aj-geddes/straylight-ai)
- [Issues](https://github.com/aj-geddes/straylight-ai/issues)

## License

Apache-2.0

---

Built by [High Velocity Solutions LLC](https://highvelocitysolutions.com)
