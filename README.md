<p align="center">
  <img src="assets/logo.png" alt="Straylight-AI — Zero-knowledge credential proxy for AI agents" width="600">
</p>

<h1 align="center">Straylight-AI</h1>

<p align="center"><strong>Zero-knowledge credential proxy for AI agents.</strong></p>
<p align="center"><em>Use AI, with Zero trust.</em></p>

<p align="center">
  <a href="https://github.com/straylight-ai/straylight/actions"><img src="https://img.shields.io/github/actions/workflow/status/straylight-ai/straylight/build.yml?branch=main&style=flat-square&label=build" alt="Build Status"></a>
  <a href="https://github.com/straylight-ai/straylight/releases"><img src="https://img.shields.io/github/v/release/straylight-ai/straylight?style=flat-square&label=version" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/straylight-ai/straylight?style=flat-square" alt="License: MIT"></a>
  <a href="https://straylight-ai.github.io/straylight/docs/quickstart"><img src="https://img.shields.io/badge/docs-quickstart-4f46e5?style=flat-square" alt="Documentation"></a>
</p>

## The Problem

AI coding assistants need credentials to interact with external services. Today,
those credentials are exposed directly into the agent's context window. Prompt
injection, log capture, and conversation exports can all leak your secrets.

## The Solution

Straylight-AI lets AI agents use authenticated services without ever seeing the
credentials. The agent says "call the Stripe API" — Straylight handles credential
injection at the transport layer. The raw token never enters the agent's context
window.

## Quick Start

### Prerequisites

- Docker or Podman
- Node.js 18+

### Install (One Command)

```bash
npx straylight-ai
```

This will:
1. Pull and start the Straylight-AI container
2. Open the dashboard at http://localhost:9470
3. Register the MCP server with Claude Code (if installed)

### Add a Service

1. Open http://localhost:9470
2. Click "Add Service"
3. Select a template (Stripe, GitHub, OpenAI, etc.) or create a custom service
4. Paste your API key — it goes straight into the encrypted vault
5. Done. The key is stored and will never be shown again.

### Connect to Claude Code

If not auto-registered during setup:

```bash
claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp
```

### Use It

Just work normally with Claude Code:

- "Check my GitHub issues"
- "What's my Stripe balance?"
- "Create an OpenAI completion"

Claude sees the Straylight-AI tools and uses them automatically. Your credentials
never enter the conversation.

## How It Works

```
+--------------------------+         +----------------------------------+
|  Claude Code / Agent     |         |  Docker Container (localhost)    |
|                          |  stdio  |                                  |
|  straylight-mcp (shim)  +-------->+  Straylight-AI Core (Go :9470)  |
|                          |         |           |                      |
+--------------------------+         |           v                      |
                                     |    OpenBao (encrypted vault)    |
                                     |           |                      |
                                     |           v                      |
                                     |    HTTP Proxy (credential       |
                                     |    injected at transport layer) |
                                     +----------------------------------+
                                                 |
                                                 v
                                      External API (Stripe, GitHub, ...)
                                      (sees authenticated request,
                                       agent never sees the token)
```

The `straylight-mcp` shim runs on your host and communicates with Claude Code via
stdio. It forwards tool calls to the container over localhost HTTP. The container
fetches credentials from the encrypted vault and injects them into outbound
requests — the agent only ever sees the API response.

## CLI Reference

| Command | Description |
|---------|-------------|
| `npx straylight-ai` | Full setup (pull, start, register) |
| `npx straylight-ai start` | Start the container |
| `npx straylight-ai stop` | Stop the container |
| `npx straylight-ai status` | Check health and service status |
| `npx straylight-ai logs` | Stream container logs |
| `npx straylight-ai update` | Pull latest image and restart |

## MCP Tools

Once registered, Claude Code has access to these tools:

| Tool | What It Does |
|------|-------------|
| `straylight_api_call` | Make an authenticated HTTP request to a configured service. Credentials are injected automatically — you never include them. |
| `straylight_exec` | Run a command inside the container with credentials injected as environment variables. Output is sanitized before being returned. |
| `straylight_check` | Check whether a credential is available and valid for a given service. |
| `straylight_services` | List all configured services, their capabilities, and credential status. |

### Example: straylight_api_call

```json
{
  "service": "stripe",
  "method": "GET",
  "path": "/v1/balance"
}
```

The `Authorization: Bearer sk_live_...` header is injected by Straylight. The
agent never sees or handles the key.

### Example: straylight_exec

```json
{
  "service": "github",
  "command": "gh repo list --json name,url --limit 10"
}
```

`GH_TOKEN` is set in the subprocess environment. The token does not appear in
the command string or in the returned output.

## OAuth Services

For OAuth services (GitHub, Google, Stripe Connect):

1. Click "Connect with [Provider]" in the dashboard
2. Authorize in your browser
3. Tokens are stored in the vault and auto-refreshed

OAuth tokens expire automatically. When a token expires, the service tile shows
a yellow "expired" badge. Click it to re-authorize.

## Claude Code Hooks (Optional)

For an extra layer of protection, add PreToolUse and PostToolUse hooks. These
run on your host and block commands that would leak credentials, then sanitize
any tool output that slips through.

Add this to your `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "straylight-mcp hook pretooluse"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "straylight-mcp hook posttooluse"
          }
        ]
      }
    ]
  }
}
```

With hooks enabled:
- `echo $STRIPE_API_KEY` in a Bash tool call is blocked before execution
- Any credential pattern that appears in tool output is replaced with `[REDACTED:service-name]`

## Security

Straylight-AI is built around the principle that credentials should never enter
the agent context window:

- **Encrypted at rest**: All credentials stored in OpenBao (open-source HashiCorp Vault fork)
- **Injected at the transport layer**: Credentials added to HTTP requests inside the container; the agent sees only the API response
- **Output sanitized**: Responses are scanned for known credential patterns before being returned
- **Non-root container**: Runs as UID 10001 with no unnecessary capabilities
- **No host exposure**: OpenBao port 9443 is not mapped to the host
- **Rate limiting**: API endpoints are rate-limited to prevent brute-force
- **CORS locked**: Dashboard only accessible from localhost

## FAQ

**Does the agent ever see my credentials?**
No. Credentials are stored in OpenBao inside the container. The proxy injects
them into outbound HTTP requests. The agent only receives the API response body,
which is also sanitized for credential patterns before delivery.

**What if OpenBao crashes?**
The Straylight-AI process supervises OpenBao and restarts it automatically. If
it cannot restart, the health endpoint shows a degraded status and MCP tools
return a clear error rather than crashing.

**Can I use this with services not on the template list?**
Yes. Select "Custom service" when adding a service and provide the base URL,
credential injection method (header or query param), and header template.

**What happens if I restart the container?**
Credentials are persisted to the Docker volume at `~/.straylight-ai/data/`. The
container re-reads the volume on start, re-unseals OpenBao, and is operational
within seconds.

**Does this work with Podman?**
Yes. The CLI auto-detects `podman` if `docker` is not available.

**What Node.js version is required?**
Node.js 18 or later. Check with `node --version`.

## Troubleshooting

**`npx straylight-ai` says Docker is not found**

Install Docker Desktop (macOS/Windows) or Docker Engine (Linux):
- macOS/Windows: https://docs.docker.com/get-docker/
- Linux: `curl -fsSL https://get.docker.com | sh`

**Dashboard shows "connecting..." and never loads**

The container may still be starting. Wait 10–15 seconds and refresh. If it
persists:

```bash
npx straylight-ai status
npx straylight-ai logs
```

**MCP tools are not visible in Claude Code**

Re-run the registration step:

```bash
claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp
```

Then restart Claude Code.

**A service shows "expired" status**

The OAuth token has expired. Click the service tile in the dashboard and click
"Re-authorize". For static API keys, click "Update Credential" and paste a
fresh key.

**Container starts but health check fails**

Check the logs for OpenBao errors:

```bash
npx straylight-ai logs
```

The most common cause is a permission error on the data volume. Verify:

```bash
ls -la ~/.straylight-ai/data/
```

The directory should be owned by your user. If not:

```bash
sudo chown -R $USER ~/.straylight-ai/data/
npx straylight-ai stop && npx straylight-ai start
```

## Manual Setup (Without npx)

If you prefer to manage the container directly:

```bash
# Create data directory
mkdir -p ~/.straylight-ai/data

# Pull and start
docker run -d \
  --name straylight-ai \
  -p 9470:9470 \
  -v ~/.straylight-ai/data:/data \
  --restart unless-stopped \
  ghcr.io/straylight-ai/straylight:latest

# Register MCP server (requires straylight-mcp binary on PATH)
claude mcp add straylight-ai --transport stdio -- straylight-mcp
```

Pre-built `straylight-mcp` binaries for each platform are available on the
[Releases](https://github.com/straylight-ai/straylight/releases) page.

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](https://straylight-ai.github.io/straylight/docs/quickstart) | 5-minute setup guide |
| [User Guide](https://straylight-ai.github.io/straylight/docs/user-guide) | Complete reference |
| [Features](https://straylight-ai.github.io/straylight/features/) | Detailed feature breakdown |
| [Architecture](https://straylight-ai.github.io/straylight/architecture/) | Technical deep dive |
| [FAQ](https://straylight-ai.github.io/straylight/docs/faq) | Common questions |

## License

MIT — see [LICENSE](LICENSE)

---

<p align="center">
  Built by <a href="https://highvelocitysolutions.com">High Velocity Solutions LLC</a><br>
  <a href="https://straylight-ai.github.io/straylight/">Website</a> · <a href="https://straylight-ai.github.io/straylight/docs/quickstart">Docs</a> · <a href="https://github.com/straylight-ai/straylight/issues">Issues</a>
</p>
