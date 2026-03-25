---
layout: doc
title: "FAQ"
description: "Frequently asked questions about Straylight-AI: security guarantees, AI agent credential safety, compatibility with Claude Code and Cursor, open source license, and self-hosted setup."
permalink: /docs/faq/
prev_page:
  title: "User Guide"
  url: "/docs/user-guide/"
json_ld:
  "@context": "https://schema.org"
  "@type": "FAQPage"
  "mainEntity":
    - "@type": "Question"
      "name": "Does the AI agent ever see my API keys with Straylight-AI?"
      "acceptedAnswer":
        "@type": "Answer"
        "text": "No. Straylight-AI uses a zero-knowledge architecture where credentials are injected at the HTTP transport layer. The AI agent's context window never contains a credential string."
    - "@type": "Question"
      "name": "Is it safe to give AI agents access to my API keys?"
      "acceptedAnswer":
        "@type": "Answer"
        "text": "With Straylight-AI, yes. The agent never actually has access to your keys — it has access to the capability your keys provide. Straylight injects credentials at the transport layer, so the agent makes real API calls without ever seeing the credential."
---

## Security

### Does the AI agent ever see my API keys with Straylight-AI?

No. This is the core guarantee of the zero-knowledge architecture.

When an AI agent calls the `api_call` MCP tool, it provides a service name and request parameters — but no credential. Straylight fetches the credential from the encrypted vault, injects it as an HTTP header at the Go `net/http` transport layer, and returns only the response data to the agent.

The credential value is never in a Go variable that the MCP layer handles. It is never in the output returned to the agent. The output sanitizer provides an additional verification pass on every response.

To confirm this yourself: after making an API call through Straylight, ask the AI agent to repeat your API key. It cannot, because it was never told it.

---

### Is it safe to give AI agents access to my API keys?

With Straylight-AI, yes — because the agent never actually receives your API keys. It receives the *capability* your keys provide, not the keys themselves.

Without Straylight, AI agents commonly gain access to credentials through:

- Reading `.env` files when asked to debug or run code
- Capturing shell history with commands like `curl -H "Authorization: Bearer sk-..."`
- Log files that contain credential values
- Prompt injection via malicious API responses that cause the agent to echo secrets

Straylight closes all of these vectors through Claude Code hooks (blocks `.env` reads), transport-layer injection (credential never in MCP layer), and output sanitization (strips credentials from API responses).

---

### What happens to my credentials if someone else accesses the dashboard?

The dashboard is served on `localhost:9470` by default and is only accessible from the machine running Docker. It is not accessible over the network unless you explicitly expose it.

Even if someone accesses the dashboard, they cannot view credential values — the dashboard never displays full credential values, only masked versions (last 4 characters). Credentials are only readable by processes that authenticate to the vault using the AppRole credentials, which are internal to the container.

If you need to secure the dashboard further (shared machine, CI server), you can add HTTP basic auth via a reverse proxy (nginx, Caddy) in front of port 9470.

---

### Can credentials be extracted from the Docker container?

The vault data is stored encrypted (AES-256-GCM) in a Docker named volume. The encryption key is derived and stored separately from the data. Accessing the volume files directly gives you encrypted blobs, not credential values.

Within a running container, credentials are briefly in Go process memory during a request. If you have arbitrary code execution inside the container (which would require a serious Docker escape), you could potentially read process memory. This is a limitation of any in-process secrets management.

The practical risk for individual developers is low. For high-security environments, consider running Straylight on a dedicated machine with full-disk encryption.

---

### Does Straylight-AI send my credentials anywhere?

No. Straylight-AI is entirely self-hosted. It has no cloud component, no telemetry, no analytics, and no callback URLs. The Docker image is built from public source code on GitHub. You can audit every line.

When you make an `api_call` through Straylight, the request goes directly from the Docker container to the external API (e.g., `api.github.com`). Nothing passes through any Straylight-controlled server.

---

## Compatibility

### Can I use Straylight-AI with Cursor?

Yes. Cursor supports the Model Context Protocol. Add Straylight-AI to your Cursor MCP configuration:

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

Restart Cursor, and the `api_call`, `exec`, `check`, and `services` tools will be available.

---

### Can I use Straylight-AI with Windsurf?

Yes. Windsurf supports MCP. Configure it the same way as Cursor, using `npx straylight-ai mcp` as the command.

---

### Can I use Straylight-AI with any MCP client?

Yes, any client that supports MCP with stdio transport. The MCP server speaks the standard MCP protocol. The command to start it is `npx straylight-ai mcp`.

---

### Does Straylight-AI work on Windows?

Yes, via Docker Desktop for Windows. The `npx straylight-ai` installer command works in PowerShell and WSL. The MCP server works with both Windows-native Claude Code and WSL-based setups.

---

### Does Straylight-AI work on macOS?

Yes, fully supported on macOS with Docker Desktop for Mac (Intel and Apple Silicon).

---

### Does Straylight-AI work in CI/CD?

Straylight-AI is designed for developer machines, not CI/CD pipelines. For CI/CD, you typically want to inject credentials via the CI platform's secret management (GitHub Actions Secrets, GitLab CI Variables, etc.) rather than running a persistent local vault.

That said, you can run Straylight-AI as a service container in Docker Compose-based CI setups if you want consistent credential management across dev and CI environments.

---

## Data and Persistence

### What happens if the Docker container restarts?

Your credentials are preserved. They are stored in a Docker named volume (`straylight-vault-data`) that persists independently of the container. When the container starts, it automatically unseals the vault and all your services are available immediately.

You do not need to re-enter credentials after a restart.

---

### What happens if I run `docker rm straylight-ai`?

The container is removed but your credentials are preserved in the named volume. Running `npx straylight-ai` again will create a new container connected to the same volume.

To delete credentials permanently, you must also remove the volume:

```bash
docker rm straylight-ai
docker volume rm straylight-vault-data
```

---

### Can I back up my credentials?

The vault data is in the Docker volume `straylight-vault-data`, typically at `/var/lib/docker/volumes/straylight-vault-data/_data`. You can back up this directory, but the data is encrypted — you also need to back up the unseal key to restore access.

Alternatively, use the dashboard export feature (Settings > Export) to download an encrypted backup file.

---

### Can I import credentials from another instance?

Yes, using the dashboard export/import feature. Export from the source instance (Settings > Export), then import on the target instance (Settings > Import). Credentials are re-encrypted with the target instance's vault key during import.

---

## Setup

### How do I add a service that's not in the 16 templates?

Use the **Generic REST API** template. It supports:

- Any base URL
- Bearer token, Basic auth, API key header, or API key query parameter authentication
- Custom header name for API key authentication

If you need a template for a commonly-used service that isn't included, open a GitHub issue and it may be added in a future release.

---

### Can I have multiple instances for different projects?

Yes. You can run multiple containers on different ports:

```bash
npx straylight-ai                        # First instance (port 9470)
STRAYLIGHT_PORT=9471 npx straylight-ai   # Second instance (port 9471)
```

Register each with Claude Code under a different name:

```bash
claude mcp add work-straylight --transport stdio -- npx straylight-ai mcp
claude mcp add personal-straylight --transport stdio -- npx straylight-ai mcp --port 9471
```

---

### How do I rotate a credential?

In the dashboard, click the service card, click **Edit**, and paste the new credential value. Click **Verify & Save**. The old credential is overwritten in the vault.

---

### Can I use Straylight-AI without Docker?

Not currently. The Docker container bundles OpenBao vault, the Go backend, and the React dashboard. Running these separately is possible but not officially supported. If you have a strong reason to avoid Docker, open a GitHub issue.

---

## Open Source

### Is Straylight-AI open source?

Yes. Straylight-AI is open source under the MIT License. The full source code is available at [https://github.com/aj-geddes/straylight-ai](https://github.com/aj-geddes/straylight-ai).

You can read every line of code, build the Docker image yourself, and fork the project.

---

### Who maintains Straylight-AI?

Straylight-AI is built and maintained by High Velocity Solutions LLC. Contributions are welcome via pull request.

---

### What is the project's license?

[MIT License](https://github.com/aj-geddes/straylight-ai/blob/main/LICENSE). You can use it commercially, modify it, distribute it, and use it privately without restrictions. The only requirement is retaining the copyright notice.

---

### How do I report a security vulnerability?

Do not open a public GitHub issue for security vulnerabilities. Email `security@straylightai.dev` with:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment

We will acknowledge within 48 hours and aim to ship a fix within 14 days for critical issues.
