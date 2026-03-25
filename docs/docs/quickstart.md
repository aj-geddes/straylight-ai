---
layout: doc
title: "Quickstart"
description: "Install Straylight-AI in under 2 minutes. Run npx straylight-ai, add a service, connect Claude Code, and make your first zero-knowledge API call."
permalink: /docs/quickstart/
next_page:
  title: "User Guide"
  url: "/docs/user-guide/"
---

Get Straylight-AI running and make your first zero-knowledge API call in under 5 minutes.

## Prerequisites

Before you start, make sure you have:

- **Docker** running on your machine. [Install Docker Desktop](https://www.docker.com/products/docker-desktop/)
- **Node.js 18+** installed (check with `node --version`)
- **Claude Code** installed (`npm install -g @anthropic-ai/claude-code`) or another MCP client

Verify Docker is running:

```bash
docker info
```

You should see Docker system information, not an error.

## Step 1: Install and Start

Run a single command in your terminal:

```bash
npx straylight-ai
```

This command:

1. Pulls the `aj-geddes/straylight-ai:0.1.0` Docker image from GitHub Container Registry
2. Starts the container with a named volume for credential persistence
3. Waits for the OpenBao vault to initialize and unseal
4. Configures AppRole authentication
5. Starts the MCP server
6. Registers the MCP server with Claude Code automatically

**Expected output:**

```
Checking Docker... OK
Pulling aj-geddes/straylight-ai:0.1.0
0.1.0: Pulling from aj-geddes/straylight-ai
Digest: sha256:a3f2e1b4c5d6e7f8...
Status: Downloaded newer image
Starting container straylight-ai...
Waiting for OpenBao vault to initialize...
Vault initialized (auto-unseal enabled)
AppRole configured
MCP server listening
Registering with Claude Code... OK

Straylight-AI is running!
Dashboard: http://localhost:9470
MCP endpoint: stdio via npx straylight-ai mcp
```

Open the dashboard: [http://localhost:9470](http://localhost:9470)

## Step 2: Add Your First Service

Open the Straylight-AI dashboard at `http://localhost:9470` and click **Add Service**.

The service wizard walks you through three steps:

1. **Choose a template** — Select from the 16 built-in service templates (GitHub, Stripe, AWS, etc.) or choose "Custom REST API" for anything else.

2. **Enter your credential** — Paste your API key, PAT, or connection string into the credential field. The field is masked. The credential is encrypted and stored in the vault immediately.

3. **Verify the connection** — Straylight makes a test request to confirm the credential works. For GitHub, it reads your username. For Stripe, it retrieves account info. For AWS, it calls STS GetCallerIdentity.

### Example: Adding a GitHub PAT

1. Click **Add Service**
2. Select **GitHub** from the template list
3. Paste your Personal Access Token (PAT) into the Token field
   - Your PAT needs at minimum `read:user` scope for account verification
   - Add `repo` scope if you want Claude Code to access your repositories
4. Click **Verify & Save**
5. You should see your GitHub username and avatar in the service card

Your GitHub PAT is now stored in the vault. You can close the browser tab.

## Step 3: Connect Claude Code

Straylight-AI registers itself with Claude Code automatically during install. To verify:

```bash
claude mcp list
```

You should see `straylight-ai` in the list.

If it's not listed, register it manually:

```bash
claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp
```

Confirm it was added:

```bash
claude mcp list
# straylight-ai: stdio  npx straylight-ai mcp
```

## Step 4: Make Your First API Call

Start Claude Code in a project directory:

```bash
claude
```

Ask Claude Code to make a GitHub API call:

```
Check my GitHub profile using the straylight-ai api_call tool.
```

Claude Code will call the `api_call` MCP tool. You should see a response like:

```
Your GitHub profile:
- Login: alice
- Name: Alice Developer
- Public repos: 47
- Followers: 312
- Account created: 2018-03-15
```

## Step 5: Verify Zero-Knowledge

Confirm that your GitHub PAT never appeared in the output. Ask Claude Code directly:

```
What is my GitHub Personal Access Token?
```

Claude Code should respond that it doesn't have access to that information — because it doesn't. The PAT is in the vault. It was injected at the transport layer during the API call. It never entered Claude Code's context window.

You can also verify by asking:

```
Show me the raw output from the last api_call, including all headers.
```

The `Authorization` header will not be present in the output returned to Claude Code. The output sanitizer and transport-layer injection ensure this.

## Connecting Other MCP Clients

### Cursor

Add to your Cursor MCP settings (`~/.cursor/mcp.json` or via Settings > MCP):

```json
{
  "mcpServers": {
    "straylight-ai": {
      "command": "npx",
      "args": ["straylight-ai", "mcp"]
    }
  }
}
```

### Windsurf

Add to your Windsurf MCP configuration:

```json
{
  "mcpServers": {
    "straylight-ai": {
      "command": "npx",
      "args": ["straylight-ai", "mcp"]
    }
  }
}
```

### Any MCP Client

The MCP server runs via stdio transport. The command to start it is:

```bash
npx straylight-ai mcp
```

## Stopping and Restarting

Stop the container:

```bash
docker stop straylight-ai
```

Start it again (all credentials preserved):

```bash
npx straylight-ai
```

Your credentials are stored in a Docker named volume (`straylight-vault-data`) and persist across container restarts and updates.

## Updating

To update to the latest version:

```bash
docker pull ghcr.io/aj-geddes/straylight-ai:latest
docker stop straylight-ai
docker rm straylight-ai
npx straylight-ai
```

Your credentials are preserved in the named volume.

## Troubleshooting

### "Docker is not running"

Start Docker Desktop or the Docker daemon and try again.

### "Port 9470 is already in use"

Another process is using port 9470. Either stop it or specify a different port:

```bash
STRAYLIGHT_PORT=4243 npx straylight-ai
```

### "MCP not registered with Claude Code"

Run the manual registration command:

```bash
claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp
```

### "Vault failed to unseal"

This usually means the named volume has corrupted data. If you're OK losing stored credentials:

```bash
docker volume rm straylight-vault-data
npx straylight-ai
```

You'll need to re-add your services.

See the [User Guide](/straylight/docs/user-guide/) for more configuration options and troubleshooting.
