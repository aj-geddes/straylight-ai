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

1. Open http://localhost:9470 and go to **Services**
2. Click **Add Service**
3. Select a template (GitHub, Stripe, OpenAI, AWS, and more) or create a custom service
4. Paste your API key — it goes straight into the encrypted vault

## Web Dashboard

The dashboard at http://localhost:9470 has three pages:

- **Dashboard** — Live system metrics: health status, vault state, uptime, API call counts, credential access stats, audit event breakdown, service status overview, and recent activity feed. Polls every 15 seconds.
- **Services** — Add, configure, and manage your service credentials. Supports 16+ templates with multiple auth methods per service.
- **Help** — Searchable user guide with getting started steps, key concepts, MCP tools reference, supported services directory, FAQ, and troubleshooting.

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
| `npx straylight-ai` | Full setup (pull latest, start, register) |
| `npx straylight-ai upgrade` | Pull latest image and replace container (data preserved) |
| `npx straylight-ai start` | Start the container |
| `npx straylight-ai stop` | Stop the container |
| `npx straylight-ai status` | Check health and service status |

## MCP Tools

Once registered, your AI coding assistant has access to:

| Tool | What It Does |
|------|-------------|
| `straylight_api_call` | Make an authenticated HTTP request. Credentials injected automatically. |
| `straylight_exec` | Run a command with credentials as environment variables. Output sanitized. |
| `straylight_db_query` | Query a database with dynamic temporary credentials that auto-expire. |
| `straylight_scan` | Scan project files for exposed secrets across 14 pattern categories. |
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

Configure a database once on the Services page. When your AI coding assistant needs data, it calls `straylight_db_query` — Straylight provisions a temporary database user, runs the query, and returns the results. The AI never sees the password.

```
// AI calls:
straylight_db_query(service="my-postgres", query="SELECT id, name FROM users LIMIT 10")
```

- Credentials are read-only by default and auto-expire (5-15 min TTL)
- Supported: PostgreSQL, MySQL/MariaDB, Redis

## Cloud Credentials

Configure an AWS, GCP, or Azure account on the Services page. When the AI needs to run a cloud CLI command, it calls `straylight_exec` with a named service — Straylight generates short-lived temporary credentials, injects them as environment variables, and returns the sanitized output.

```
// AI calls:
straylight_exec(service="aws-prod", command="aws s3 ls s3://my-bucket")
```

- AWS: STS AssumeRole with inline session policies
- GCP: Workload Identity Federation tokens
- Azure: short-lived access tokens

## Secret Scanner

Scan your project for exposed secrets before the AI reads them. Straylight checks files against 14 pattern categories and reports findings by file, line, and type.

```
// AI calls:
straylight_scan(path="/home/user/my-project")
```

- Detects AWS keys, GitHub PATs, Stripe keys, connection strings, private keys, and more
- Returns file paths, line numbers, secret types, and severity

## File Firewall

Let the AI read files it needs without exposing secrets. `straylight_read_file` serves file contents with credentials redacted. Blocked files (`.env`, `.pem`, `credentials.json`) return guidance to use the vault instead.

```
// AI calls:
straylight_read_file(path="docker-compose.yml")
// Returns: file structure with passwords replaced by [STRAYLIGHT:service-name]
```

- Blocked file patterns: `.env*`, `*credentials*`, `*secret*`, `*.pem`, SSH keys
- Legitimate files served clean — structure intact, secrets masked

## Audit Trail

Every credential access, API call, and command execution is logged with a timestamp, service name, tool used, and session ID. No credentials appear in the log.

View the audit feed on the Dashboard page at http://localhost:9470, including:
- Event counts by type and by service
- Credential access frequency
- Recent activity with tool and request details

## Supported Services

16+ pre-configured templates including GitHub, Stripe, OpenAI, Anthropic, AWS, Google Cloud, Azure, PostgreSQL, MySQL, Redis, Slack, GitLab, and more. Custom services supported via base URL and auth method configuration.

## Security

- **Encrypted at rest** — OpenBao (open-source HashiCorp Vault fork)
- **Transport-layer injection** — credentials never exposed to the AI
- **Output sanitization** — credential patterns stripped from all responses
- **Dynamic database credentials** — temporary users with automatic revocation
- **Temporary cloud credentials** — AWS STS, GCP, Azure tokens generated per invocation
- **Non-root container** — UID 10001, minimal Alpine 3.23 image
- **Go 1.25.8** — all stdlib CVEs patched
- **OpenBao 2.5.2** — all known CVEs patched

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

## FAQ

**Does my AI coding assistant ever see my credentials?**
No. Credentials stay inside the vault. The proxy injects them into HTTP requests. The AI only receives the API response, which is also sanitized for credential patterns.

**What happens if I restart the container?**
Credentials persist in the named Docker volume `straylight-ai-data`. The container re-unseals the vault and is operational within seconds.

**Can I use services not on the template list?**
Yes. Select "Custom Service" and provide the base URL and auth method.

**Does this work offline?**
Yes. Straylight runs entirely on your machine. You only need network access to reach the target APIs themselves.

**Is there a cloud/hosted version?**
No. Straylight is local-only by design. Your credentials never leave your machine.

## Links

- [Documentation](https://aj-geddes.github.io/straylight-ai/docs/quickstart)
- [GitHub](https://github.com/aj-geddes/straylight-ai)
- [Changelog](https://github.com/aj-geddes/straylight-ai/blob/main/CHANGELOG.md)
- [Issues](https://github.com/aj-geddes/straylight-ai/issues)

## License

Apache-2.0

---

Built by [High Velocity Solutions LLC](https://highvelocitysolutions-llc.com)
