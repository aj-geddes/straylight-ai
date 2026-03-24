# Manual Test Guide: Straylight-AI with Claude Code

This guide walks through the complete end-to-end test of Straylight-AI with
a real Claude Code installation. Follow each step in order. The goal is to
confirm that Claude Code can make authenticated API calls through Straylight-AI
without the credential ever appearing in Claude's context window.

## Prerequisites

- Docker (or Podman) installed and running
- Claude Code CLI installed (`claude --version` should succeed)
- A Stripe test-mode API key (starts with `sk_test_`)
  - Sign up free at https://stripe.com (no payment required for test keys)
  - Find your key at https://dashboard.stripe.com/test/apikeys

---

## Step 1: Build and Start the Straylight-AI Container

```bash
# Clone the repository (if you haven't already).
git clone https://github.com/aj-geddes/straylight-ai
cd straylight

# Build the container image.
docker build -t straylight-ai:latest .

# Start the container.
# - Port 9470 is the Straylight-AI HTTP API.
# - The data volume persists credentials across restarts.
docker run -d \
  --name straylight-ai \
  -p 9470:9470 \
  -v straylight-data:/data \
  straylight-ai:latest
```

Verify the container is running and healthy:

```bash
curl http://localhost:9470/api/v1/health
```

Expected output:
```json
{"status":"ok","version":"0.1.0","openbao":"unsealed"}
```

If `openbao` shows `"sealed"` instead of `"unsealed"`, wait 10-15 seconds and
try again. OpenBao initialises asynchronously on first start.

---

## Step 2: Add Your Stripe Test API Key

Replace `sk_test_YOUR_KEY_HERE` with your actual Stripe test key.

```bash
curl -s -X POST http://localhost:9470/api/v1/services \
  -H "Content-Type: application/json" \
  -d '{
    "name": "stripe",
    "type": "http_proxy",
    "target": "https://api.stripe.com",
    "inject": "header",
    "header_name": "Authorization",
    "header_template": "Bearer {{.Secret}}",
    "credential": "sk_test_YOUR_KEY_HERE"
  }' | jq .
```

Expected output:
```json
{
  "name": "stripe",
  "type": "http_proxy",
  "target": "https://api.stripe.com",
  "inject": "header",
  "header_name": "Authorization",
  "header_template": "Bearer {{.Secret}}",
  "status": "available",
  "created_at": "...",
  "updated_at": "..."
}
```

Notice: the credential (`sk_test_...`) is NOT in the response. Straylight-AI
stores it in the OpenBao vault and never echoes it back.

---

## Step 3: Verify the Credential Is Stored

```bash
curl -s http://localhost:9470/api/v1/services/stripe/check | jq .
```

Expected output:
```json
{"name": "stripe", "status": "available"}
```

---

## Step 4: Build the MCP Host Binary

```bash
# From the project root:
go build -o ./straylight-mcp ./cmd/straylight-mcp
```

Or if using the npm bootstrap package:
```bash
npx straylight-ai install
```

---

## Step 5: Register the MCP Server with Claude Code

Add Straylight-AI as an MCP server in your Claude Code configuration.

**Option A: Using the Claude Code CLI**

```bash
claude mcp add straylight-ai \
  --command "$(pwd)/straylight-mcp" \
  --env STRAYLIGHT_URL=http://localhost:9470
```

**Option B: Edit `~/.claude/claude_desktop_config.json` manually**

```json
{
  "mcpServers": {
    "straylight-ai": {
      "command": "/path/to/straylight-mcp",
      "env": {
        "STRAYLIGHT_URL": "http://localhost:9470"
      }
    }
  }
}
```

Restart Claude Code after editing the config.

---

## Step 6: Verify the MCP Tools Are Available

In a Claude Code session, type:

```
What MCP tools are available?
```

Claude should list four tools:
- `straylight_api_call` — Make authenticated HTTP requests to external services
- `straylight_exec` — Execute commands with credentials injected as environment variables
- `straylight_check` — Check whether a credential is available for a service
- `straylight_services` — List all configured services

If the tools are not listed, check:
1. `docker ps` — is the container running?
2. `curl http://localhost:9470/api/v1/health` — is the API responding?
3. Claude Code logs — is the MCP binary connecting?

---

## Step 7: Ask Claude to Check the Stripe Credential

```
Use straylight_check to verify the stripe service is configured.
```

Expected Claude response (something like):

> I checked the Stripe service. The credential is available and ready to use.
> The status came back as "available".

What Claude should NOT say:
- Any `sk_test_...` value
- Any mention of the actual key

---

## Step 8: Ask Claude to Get the Stripe Balance

```
Use the Stripe API to get my account balance.
```

Claude should use `straylight_api_call` to call `GET /v1/balance` on Stripe.

Expected behaviour:
1. Claude calls `straylight_api_call` with `service="stripe"`, `path="/v1/balance"`.
2. Straylight-AI fetches the `sk_test_...` key from the vault.
3. Straylight-AI sends the request to `https://api.stripe.com/v1/balance` with
   the `Authorization: Bearer sk_test_...` header injected.
4. The Stripe response is returned to Claude.
5. Claude reports the balance information.

Typical Stripe test-mode balance response:
```json
{
  "object": "balance",
  "available": [{"amount": 0, "currency": "usd", ...}],
  "pending": [...]
}
```

---

## Step 9: Verify the Credential Never Appeared in Claude's Context

After the API call, ask Claude:

```
What is the Stripe API key you just used?
```

Claude should respond that it does not know the API key — it never saw it.
Straylight-AI injected the credential server-side. Claude only received the
JSON response from Stripe.

This is the key security property: **credentials never flow through the AI's
context window**.

---

## Step 10: Check the Audit Log

```bash
# View recent credential access log from the container.
docker exec straylight-ai cat /data/openbao/audit.log 2>/dev/null | tail -20

# Or check the container logs for credential access events.
docker logs straylight-ai 2>&1 | grep -i "credential\|credential_access" | tail -10
```

You should see log entries showing that the `stripe` credential was read from
the vault when the API call was made — confirming that access is auditable even
though Claude never saw the value.

---

## Step 11: List All Configured Services

Ask Claude:

```
What services are configured in Straylight-AI?
```

Claude will use `straylight_services` and report:
- Service name: `stripe`
- Capabilities: `api_call`
- Base URL: `https://api.stripe.com`
- Status: `available`

Again, no credential values in the response.

---

## Troubleshooting

### Container exits immediately

Check logs: `docker logs straylight-ai`

Common causes:
- Port 9470 already in use: `lsof -i :9470`
- Insufficient memory: OpenBao requires ~128 MB

### `straylight_check` returns `"not_configured"`

The credential was not stored successfully. Re-run Step 2.

### MCP tools not visible in Claude Code

- Verify `straylight-mcp` is in the PATH or the path in the config is absolute.
- Check the `STRAYLIGHT_URL` environment variable points to the running container.
- Run `straylight-mcp` manually and confirm it outputs JSON on startup:
  ```bash
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}' | ./straylight-mcp
  ```

### Stripe returns 401 Unauthorized

The test key may be invalid or expired. Check your Stripe dashboard at
https://dashboard.stripe.com/test/apikeys.

---

## Running the Automated Integration Test

The Go integration test exercises all these scenarios without requiring Docker,
OpenBao, or a real Stripe key:

```bash
# Run the Go integration tests (self-contained, no external dependencies).
go test -tags=integration -v -timeout=30s ./internal/integration/...

# Run the full shell-based integration test script (starts a live server).
./scripts/integration-test.sh
```

The Go tests use an in-memory vault mock and an `httptest.Server` to simulate
the Stripe API. They run in under one second and verify:

1. Tool listing returns all 4 tools.
2. Credential check reports "available".
3. API call reaches the mock upstream with the injected credential.
4. Response is returned to the caller.
5. The credential `test_FAKECRED_not_a_real_key_000` never appears in any response.
6. The sanitizer redacts the credential when the upstream echoes it back.
7. The vault audit log records credential accesses.
8. Service listing includes the test service.
9. Unknown service returns `isError: true`.
