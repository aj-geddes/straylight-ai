---
layout: doc
title: "User Guide"
description: "Complete Straylight-AI user guide: dashboard overview, adding services, all 16 service templates, MCP tool reference (api_call, exec, check, services), configuration, and troubleshooting."
permalink: /docs/user-guide/
prev_page:
  title: "Quickstart"
  url: "/docs/quickstart/"
next_page:
  title: "FAQ"
  url: "/docs/faq/"
---

This guide covers everything you need to use Straylight-AI effectively: the dashboard,
adding services, using MCP tools in Claude Code, configuration, and troubleshooting.

## Dashboard Overview

The dashboard is available at `http://localhost:9470` while Straylight-AI is running.

### Services Page (Home)

The default view shows all configured services as cards. Each card displays:

- **Service name and icon**
- **Connection status** — Green (connected), Yellow (not verified), Red (error)
- **Account info** — Username, avatar, and service-specific stats for connected services
- **Last verified** — Timestamp of the most recent successful connection check
- **Actions** — Edit, re-verify, or delete the service

### Service Detail

Click a service card to see full details:

- Auth method and masked credential (last 4 characters visible)
- All stored fields for that service
- Audit log of recent API calls made through Straylight for this service
- Re-verify and edit buttons

### Settings

Accessible from the nav. Configuration options include:

- **Port** — Dashboard and API port (default 9470)
- **MCP port** — MCP server port (default 4243)
- **Log level** — debug, info, warn, error
- **Vault address** — If running OpenBao separately (default: built-in)
- **Auto-start** — Configure the container to start with Docker restart policy

## Adding Services

### Using the Service Wizard

1. Click **Add Service** (plus button or "Add Service" in the nav)
2. Search or scroll to select a service template
3. Fill in the credential fields — each template shows only the relevant fields
4. Click **Verify Connection** to test the credential
5. Click **Save** to encrypt and store in the vault

If verification fails, a specific error message is shown. Common causes:

- Invalid credential format (wrong prefix, wrong length)
- Insufficient permissions (PAT missing required scope)
- Network connectivity issue (the external API is unreachable from Docker)

### Supported Auth Methods

Straylight handles six authentication methods automatically:

| Method | Example Services | What Straylight Does |
|--------|-----------------|----------------------|
| Bearer token | GitHub, Stripe, Slack, Linear | Adds `Authorization: Bearer <token>` header |
| API key header | OpenAI, Anthropic | Adds service-specific header (`x-api-key`, etc.) |
| Basic auth | Jira | Encodes `user:password` in Base64, adds `Authorization: Basic <encoded>` |
| AWS SigV4 | AWS | Signs requests with HMAC-SHA256 using access key and secret key |
| OAuth2 (service account) | GCP | Exchanges service account JSON for short-lived OAuth2 tokens |
| Connection string | Databases, SSH | Injects credentials into CLI invocations via the `exec` tool |

## Service Templates Reference

### GitHub

- **Auth method**: Personal Access Token (PAT)
- **Fields**: Token
- **Required scopes**: `read:user` (minimum); `repo` for repository access
- **Account enrichment**: Login, name, avatar URL, public repos, followers, following
- **Base URL**: `https://api.github.com`

### Stripe

- **Auth method**: Bearer token (secret key)
- **Fields**: Secret Key (sk_live_... or sk_test_...)
- **Account enrichment**: Business name, email, account ID, country
- **Base URL**: `https://api.stripe.com`

### OpenAI

- **Auth method**: API key header (`Authorization: Bearer sk-...`)
- **Fields**: API Key
- **Account enrichment**: Organization name, available models list
- **Base URL**: `https://api.openai.com`

### Anthropic

- **Auth method**: API key header (`x-api-key`)
- **Fields**: API Key
- **Account enrichment**: Organization name
- **Base URL**: `https://api.anthropic.com`

### AWS

- **Auth method**: SigV4 signing
- **Fields**: Access Key ID, Secret Access Key, Region, Session Token (optional for assume-role)
- **Account enrichment**: Account ID, IAM user/role ARN (via STS GetCallerIdentity)
- **Base URL**: Region-specific AWS endpoints

### GCP

- **Auth method**: Service account OAuth2
- **Fields**: Service Account JSON (paste full JSON content)
- **Account enrichment**: Project ID, service account email
- **Base URL**: `https://www.googleapis.com`

### Azure

- **Auth method**: Service principal
- **Fields**: Tenant ID, Client ID, Client Secret, Subscription ID
- **Account enrichment**: Subscription name, tenant name
- **Base URL**: `https://management.azure.com`

### Slack

- **Auth method**: Bearer token
- **Fields**: Bot Token (xoxb-...) or App Token (xapp-...)
- **Account enrichment**: Workspace name, bot user name
- **Base URL**: `https://slack.com/api`

### Linear

- **Auth method**: API key
- **Fields**: API Key
- **Account enrichment**: User name, organization name
- **Base URL**: `https://api.linear.app`

### Jira

- **Auth method**: Basic auth (email + API token)
- **Fields**: Email, API Token, Domain (e.g., `yourcompany.atlassian.net`)
- **Account enrichment**: Display name, account type
- **Base URL**: `https://<domain>.atlassian.net`

### PostgreSQL

- **Auth method**: Connection string injection
- **Fields**: Host, Port, Database, Username, Password, SSL mode
- **Usage**: Use with `exec` tool to run psql commands
- **Example**: `exec({ "service": "postgres", "command": "psql -c '\\dt'" })`

### MySQL

- **Auth method**: Connection string injection
- **Fields**: Host, Port, Database, Username, Password
- **Usage**: Use with `exec` tool to run MySQL CLI commands

### MongoDB

- **Auth method**: Connection URI
- **Fields**: Connection URI (mongodb://... or mongodb+srv://...)
- **Usage**: Use with `exec` tool to run mongosh commands

### Redis

- **Auth method**: URL with password
- **Fields**: Host, Port, Password, TLS (boolean)
- **Usage**: Use with `exec` tool to run redis-cli commands

### SSH

- **Auth method**: Private key injection via ssh-agent
- **Fields**: Private Key (PEM format), Host, Username, Port
- **Usage**: Straylight starts a temporary ssh-agent, adds the key, and injects `SSH_AUTH_SOCK` into exec commands

### Generic REST API

- **Auth method**: Configurable
- **Fields**: Base URL, Auth Method (Bearer/Basic/API Key header/Query param), Auth value, Header name (if API key)
- **Usage**: Works with any HTTP API that uses standard auth patterns

## MCP Tool Reference

These four tools are available to Claude Code and any MCP client after connecting to Straylight.

### `api_call`

Make an authenticated HTTP request to a configured service.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Service name as configured in dashboard |
| `method` | string | Yes | HTTP method: GET, POST, PUT, PATCH, DELETE |
| `path` | string | Yes | Path relative to service base URL |
| `body` | object or string | No | Request body for POST/PUT/PATCH |
| `headers` | object | No | Additional request headers (do not include auth — injected automatically) |
| `query` | object | No | Query string parameters |

**Example — GitHub: List repositories:**

```json
{
  "service": "github",
  "method": "GET",
  "path": "/user/repos",
  "query": { "sort": "updated", "per_page": "10" }
}
```

**Example — Stripe: Create a customer:**

```json
{
  "service": "stripe",
  "method": "POST",
  "path": "/v1/customers",
  "body": {
    "email": "new@example.com",
    "name": "New Customer"
  }
}
```

**Example — OpenAI: Chat completion:**

```json
{
  "service": "openai",
  "method": "POST",
  "path": "/v1/chat/completions",
  "body": {
    "model": "gpt-4o",
    "messages": [{ "role": "user", "content": "Hello" }]
  }
}
```

**Returns:** The parsed JSON response body, with any credential values redacted.

---

### `exec`

Execute a CLI command with service credentials injected as environment variables in an isolated subprocess.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Service name |
| `command` | string | Yes | Shell command to execute |
| `args` | array | No | Command arguments as array (preferred over inline) |
| `cwd` | string | No | Working directory for the command |
| `timeout` | number | No | Timeout in seconds (default: 30) |

**Example — AWS CLI:**

```json
{
  "service": "aws",
  "command": "aws s3 ls",
  "args": ["s3://my-bucket"]
}
```

**Example — PostgreSQL query:**

```json
{
  "service": "postgres",
  "command": "psql",
  "args": ["-c", "SELECT count(*) FROM users;"]
}
```

**Returns:** stdout and stderr of the command, with any credential values redacted from both.

> **Note:** The credential values are injected as environment variables into the subprocess only. They are not part of the command string or arguments. The agent never sees the environment variable values.

---

### `check`

Verify connectivity and authentication status for a configured service.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Service name |

**Example:**

```json
{ "service": "github" }
```

**Returns:** Connection status, account information (username, plan, stats), and last verified timestamp. Never returns the credential itself.

---

### `services`

List all configured services and their current status.

**Parameters:** None.

**Returns:** Array of service objects:

```json
[
  {
    "name": "github",
    "template": "GitHub",
    "status": "connected",
    "account": {
      "login": "alice",
      "name": "Alice Developer"
    },
    "last_verified": "2026-03-24T10:30:00Z"
  },
  {
    "name": "stripe",
    "template": "Stripe",
    "status": "connected",
    "account": {
      "business_name": "Alice's Shop"
    },
    "last_verified": "2026-03-24T09:15:00Z"
  }
]
```

Credential values are never included in the response.

## Configuration

### Environment Variables

Set these when starting the container via `docker run` or in a `.env` file alongside `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `STRAYLIGHT_PORT` | `9470` | Dashboard and REST API port |
| `STRAYLIGHT_MCP_PORT` | `4243` | MCP server port (stdio transport ignores this) |
| `STRAYLIGHT_LOG_LEVEL` | `info` | Log verbosity: debug, info, warn, error |
| `STRAYLIGHT_VAULT_ADDR` | `http://localhost:8200` | OpenBao vault address |
| `STRAYLIGHT_VAULT_TOKEN` | auto-generated | Override vault root token (not recommended) |
| `STRAYLIGHT_UNSEAL_KEY` | auto-derived | Override auto-unseal key |

### Docker Compose

For a persistent, auto-starting setup:

```yaml
version: "3.9"
services:
  straylight:
    image: ghcr.io/aj-geddes/straylight-ai:0.1.0
    container_name: straylight-ai
    restart: unless-stopped
    ports:
      - "9470:9470"
    volumes:
      - straylight-vault-data:/vault/data
    environment:
      - STRAYLIGHT_LOG_LEVEL=info

volumes:
  straylight-vault-data:
```

### Claude Code Hooks Configuration

Straylight ships a hook configuration file at `~/.claude/straylight-hooks.json`. It is referenced from your Claude Code settings. If you need to edit it manually:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "npx straylight-ai hook --phase pre --input-file /dev/stdin",
            "timeout": 5000
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
            "command": "npx straylight-ai hook --phase post --input-file /dev/stdin",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
```

## Troubleshooting

### Service shows "Error" status

1. Click the service card to see the specific error message.
2. Common causes:
   - **401 Unauthorized** — Credential is invalid or expired. Re-enter it via Edit.
   - **403 Forbidden** — Credential lacks required permissions. Check scopes/permissions.
   - **Connection refused** — Docker cannot reach the external API. Check your network/firewall.
   - **Vault sealed** — The vault became sealed (rare). Restart the container.

### `api_call` returns unexpected results

Use `check` to verify the service is connected first:

```
Check the github service status.
```

If `check` returns an error, fix the credential before debugging `api_call` responses.

### Claude Code doesn't see the `api_call` tool

Verify the MCP server is registered:

```bash
claude mcp list
```

If Straylight-AI is not in the list, re-register:

```bash
claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp
```

Then restart Claude Code.

### Container starts but dashboard is unreachable

Check that the container is running:

```bash
docker ps | grep straylight
```

Check the container logs for errors:

```bash
docker logs straylight-ai
```

### "exec" tool fails with permission denied

The command you're trying to run may not be available inside the Docker container. The container includes: `curl`, `psql`, `mysql`, `mongosh`, `redis-cli`, `aws`, `gcloud`, and `git`. For other tools, consider using `api_call` with the HTTP API instead of the CLI tool.

### Credential I entered seems to be stored wrong

Credentials are validated during the "Verify" step. If verification passes, the credential was stored correctly. If an `api_call` later fails with 401, the most likely cause is that the credential was rotated externally. Delete and re-add the service with the new credential.
