---
layout: doc
title: "User Guide"
description: "Complete Straylight-AI user guide: dashboard overview, adding services, all 16 service templates, database credentials, cloud credentials, secret scanner, file firewall, audit trail, MCP tool reference, configuration, and troubleshooting."
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

## Database Credentials

Straylight can connect an AI coding assistant to a database without ever exposing a connection string or password. Each time the AI queries the database, Straylight provisions a temporary database user with limited permissions, runs the query through a proxy, and automatically revokes the user when the lease expires.

### How to Add a Database Service

1. Click **Add Service** in the dashboard.
2. Select a database template: **PostgreSQL**, **MySQL**, or **Redis**.
3. Fill in the connection fields:

| Field | Description |
|-------|-------------|
| **Service name** | A short identifier used in the MCP tool (e.g., `prod-db`, `analytics`) |
| **Host** | Database server hostname or IP address |
| **Port** | Database port (PostgreSQL: 5432, MySQL: 3306, Redis: 6379) |
| **Database** | Database name (not applicable for Redis) |
| **Admin username** | A database user with permission to create and drop roles |
| **Admin password** | Password for the admin user — stored in the vault, never exposed |
| **SSL mode** | `require` (default), `verify-ca`, `verify-full`, or `disable` |

4. Click **Verify Connection**. Straylight tests connectivity using the admin credentials.
5. Click **Save**. The admin credentials are encrypted in the vault.

### How Temporary Credentials Work

When the AI calls `straylight_db_query`:

1. Straylight asks OpenBao's database secrets engine to create a temporary user on the target database.
2. OpenBao runs a `CREATE ROLE` (PostgreSQL) or `CREATE USER` (MySQL) statement scoped to the permissions defined in the service configuration.
3. Straylight connects to the database using the temporary credentials, runs the query, and returns the results.
4. When the lease TTL expires, OpenBao automatically runs `DROP ROLE` or `DROP USER`. The temporary user ceases to exist.

The AI coding assistant sees only the query results — never the connection string, admin password, or temporary credentials.

### TTL and Lease Settings

The default TTL for temporary credentials is **15 minutes**. The maximum TTL is **1 hour**.

You can adjust these in the service's advanced configuration:

| Setting | Default | Description |
|---------|---------|-------------|
| `default_ttl` | `15m` | Lease duration for each set of temp credentials |
| `max_ttl` | `1h` | Maximum duration, even if renewed |

Leases are renewed automatically while a query is in flight. After the query completes, the lease runs to expiry and is not renewed.

### Permissions: Read-Only by Default

Temporary users are created with `SELECT` permissions only. This means the AI can read data but cannot modify, insert, or delete rows.

If you need the AI to write data, you can change the role in the service's advanced configuration to `readwrite`. For fine-grained control, you can provide a custom creation SQL statement in the advanced configuration:

```sql
-- Example: read-only on a specific schema only
GRANT SELECT ON SCHEMA reporting TO "{{name}}";
```

OpenBao substitutes `{{name}}`, `{{password}}`, and `{{expiration}}` with values for the temporary user.

### Query Flow Example

Ask an AI coding assistant:

```
How many users signed up in the last 7 days? Use the prod-db service.
```

The AI calls:

```json
{
  "service": "prod-db",
  "query": "SELECT count(*) FROM users WHERE created_at > NOW() - INTERVAL '7 days'",
  "max_rows": 1
}
```

Straylight provisions a temporary credential, executes the query, and returns:

```json
{
  "columns": ["count"],
  "rows": [[1247]],
  "row_count": 1,
  "engine": "postgresql",
  "lease_ttl_seconds": 900
}
```

The AI reports the count to you. The temporary database user expires in 15 minutes.

---

## Cloud Provider Credentials

Straylight generates short-lived cloud credentials on demand, so the AI can run `aws`, `gcloud`, and `az` commands without ever seeing your access keys or service account credentials.

### How to Add a Cloud Service

1. Click **Add Service** in the dashboard.
2. Select **AWS**, **GCP**, or **Azure** as the template.
3. Enter the provider-specific configuration described below.
4. Click **Verify Connection**.
5. Click **Save**.

### AWS Configuration

Straylight uses AWS STS AssumeRole to generate temporary credentials.

| Field | Description |
|-------|-------------|
| **Access Key ID** | IAM access key for the user or role that will call STS AssumeRole |
| **Secret Access Key** | Corresponding secret key |
| **Role ARN** | ARN of the IAM role to assume (e.g., `arn:aws:iam::123456789012:role/straylight-session`) |
| **Region** | Default AWS region (e.g., `us-east-1`) |
| **Session duration** | Duration of temp credentials in seconds (default: 900, max: 43200) |

When the AI runs a command through `straylight_exec`, Straylight calls `sts:AssumeRole`, receives temporary `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` values, and injects them as environment variables into the subprocess. The AI sees only the command output.

### GCP Configuration

Straylight uses the service account credentials to generate short-lived OAuth2 access tokens.

| Field | Description |
|-------|-------------|
| **Service Account JSON** | Full JSON content of the service account key file |
| **Project ID** | GCP project ID |
| **Token lifetime** | Token lifetime in seconds (default: 3600, max: 43200) |

When the AI runs a `gcloud` command, Straylight generates a fresh access token, injects it via `CLOUDSDK_AUTH_ACCESS_TOKEN`, and the token expires automatically.

### Azure Configuration

Straylight uses a service principal to acquire temporary access tokens.

| Field | Description |
|-------|-------------|
| **Tenant ID** | Azure Active Directory tenant ID |
| **Client ID** | Service principal application (client) ID |
| **Client Secret** | Service principal client secret — stored in vault |
| **Subscription ID** | Azure subscription ID |

When the AI runs an `az` command, Straylight acquires a token scoped to `https://management.azure.com/.default` and injects it as `AZURE_ACCESS_TOKEN`.

### What the AI Sees

The AI coding assistant uses `straylight_exec` with a cloud service name and a CLI command. Straylight injects the temporary credentials as environment variables before executing the command. The credential values are never in the command string and are never returned in the output.

**Example — List S3 buckets:**

```json
{
  "service": "aws-prod",
  "command": "aws s3 ls"
}
```

**Example — List GCP compute instances:**

```json
{
  "service": "gcp-dev",
  "command": "gcloud compute instances list"
}
```

**Example — List Azure VMs:**

```json
{
  "service": "azure-staging",
  "command": "az vm list --output table"
}
```

In each case, the AI sees only the command output. No access keys, service account JSON, or client secrets appear in the response.

---

## Secret Scanner

The secret scanner walks a project directory and identifies files that contain secrets before the AI reads them. Use it at the start of a session on an unfamiliar codebase, or after adding new files, to understand what sensitive material is present.

### What the Scanner Detects

The scanner applies 14 pattern categories:

| Pattern | Examples |
|---------|---------|
| AWS access keys | `AKIA...` |
| GitHub PATs | `ghp_...`, `github_pat_...` |
| Stripe API keys | `sk_live_...`, `sk_test_...` |
| OpenAI keys | `sk-proj-...`, `sk-...` |
| Private keys | PEM-encoded private keys |
| `.env` secrets | `KEY=value` assignments in `.env` files |
| Connection strings | `postgres://`, `mysql://`, `mongodb+srv://` |
| Generic Bearer tokens | `Authorization: Bearer ...` patterns |
| Generic API keys | Common key name + value patterns |
| Slack webhooks | `https://hooks.slack.com/...` |
| SendGrid keys | `SG....` |
| Twilio tokens | `SK...` and auth token patterns |
| Basic auth | Base64-encoded credentials in URLs |
| Private key files | `.pem`, `id_rsa`, `id_ed25519` filenames |

### How to Trigger a Scan

Ask the AI coding assistant to scan the project:

```
Scan the current project for secrets using straylight_scan.
```

The AI calls:

```json
{
  "path": ".",
  "severity_filter": "all",
  "generate_ignore": true
}
```

### Understanding Results

Each finding includes:

| Field | Description |
|-------|-------------|
| `file` | Path to the file containing the match |
| `line` | Line number |
| `column` | Column number |
| `pattern` | Name of the detection pattern (e.g., `aws_access_key`) |
| `severity` | `high`, `medium`, or `low` |
| `match` | Redacted preview — the actual secret value is not shown |

**Example result:**

```json
{
  "findings": [
    {
      "file": ".env",
      "line": 3,
      "column": 1,
      "pattern": "aws_access_key",
      "severity": "high",
      "match": "AWS_ACCESS_KEY_ID=AKIA********************"
    },
    {
      "file": "config/database.yml",
      "line": 12,
      "column": 12,
      "pattern": "connection_string",
      "severity": "medium",
      "match": "postgres://admin:****@prod-db.example.com/app"
    }
  ],
  "files_scanned": 342,
  "files_skipped": 12,
  "duration_ms": 180
}
```

### Generating Ignore Rules

Pass `"generate_ignore": true` to get a block of rules you can paste into `.claudeignore`, `.cursorignore`, or `.rooignore`:

```json
{
  "path": ".",
  "generate_ignore": true
}
```

The response includes an `ignore_rules` field with content like:

```
# Generated by straylight_scan
.env
.env.*
config/database.yml
secrets/
```

Paste this content into the appropriate ignore file for your AI coding assistant.

### Adding Custom Patterns

You can define additional detection patterns in `config.yaml` under the `scanner` section:

```yaml
scanner:
  custom_patterns:
    - name: my_internal_token
      pattern: "MYCO_[A-Z0-9]{32}"
      severity: high
```

---

## Sensitive File Firewall

The file firewall intercepts file reads and redacts secrets before they enter the AI's context window. Use `straylight_read_file` instead of reading files directly when working with configuration files, environment files, or anything that might contain credentials.

### How It Works

When the AI calls `straylight_read_file`, Straylight:

1. Reads the file.
2. Applies the sanitizer to all detected secret values, replacing them with `[STRAYLIGHT:pattern-name]` placeholders.
3. Returns the sanitized content. The file structure — comments, field names, surrounding text — is preserved.

The AI can see what keys exist, what fields are configured, and the overall structure of the file. It cannot see the secret values themselves.

### Blocked Files

Some files are blocked outright. If the AI tries to read one of them through `straylight_read_file`, it receives a message explaining that the file contains credentials and directing it to the vault for secure access.

Default blocked patterns:

- `.env` and `.env.*`
- `*credentials*`
- `*secret*`
- `*serviceAccountKey*`
- `*.pem`
- `id_rsa*`
- `id_ed25519*`
- `credentials.json`

### Redacted Files

Other files are served with secret values replaced. The structure of the file is preserved so the AI can understand the configuration, but actual secret values are substituted.

When Straylight encounters structured data (YAML, JSON, TOML), it redacts the values of known sensitive keys:

| Redacted keys |
|---------------|
| `password` |
| `secret` |
| `token` |
| `api_key`, `apiKey` |
| `access_key`, `secret_key` |
| `connection_string`, `database_url` |
| `private_key` |
| `client_secret` |

**Example — reading a docker-compose file:**

Actual file:
```yaml
services:
  app:
    environment:
      DATABASE_URL: postgres://admin:hunter2@db:5432/myapp
      STRIPE_KEY: sk_live_abc123xyz
```

What the AI sees after `straylight_read_file`:
```yaml
services:
  app:
    environment:
      DATABASE_URL: [STRAYLIGHT:connection_string]
      STRIPE_KEY: [STRAYLIGHT:stripe_key]
```

### Custom Firewall Rules

You can extend or modify the default patterns in `config.yaml`:

```yaml
firewall:
  enabled: true
  always_redact:
    - ".env*"
    - "*credentials*"
    - "*.pem"
    - "id_rsa*"
    - "my-secrets-dir/*"
  structured_keys:
    - password
    - secret
    - token
    - api_key
    - my_custom_key_name
```

### What the AI Sees When a File is Blocked

If the AI tries to read a fully blocked file, `straylight_read_file` returns a message such as:

```
This file (.env) contains credentials and cannot be read directly.
Use the Straylight dashboard to add each credential as a service,
then access them through straylight_api_call or straylight_exec.
```

This directs the AI toward the correct, zero-knowledge workflow without exposing the secret values.

---

## Credential Audit Trail

Every credential access, tool invocation, and API call through Straylight is recorded in an append-only audit log. The log lets you review what the AI accessed, when, and what it did.

### What Gets Logged

Every invocation of an MCP tool produces an audit event. Each event includes:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp |
| `event_type` | Tool name: `api_call`, `exec`, `db_query`, `scan`, `read_file` |
| `service` | Service name used |
| `summary` | URL path, command, or query — with credential values redacted |
| `result` | `success`, `error`, or `blocked` |
| `duration_ms` | Request duration in milliseconds |

Credential values are never written to the audit log. The log records what was accessed, not the secrets themselves.

### Log Format

Events are written as JSON Lines (one JSON object per line):

```json
{"timestamp":"2026-03-26T14:22:01Z","event_type":"api_call","service":"github","summary":"GET /user/repos","result":"success","duration_ms":312}
{"timestamp":"2026-03-26T14:22:45Z","event_type":"db_query","service":"prod-db","summary":"SELECT count(*) FROM users WHERE...","result":"success","duration_ms":28}
{"timestamp":"2026-03-26T14:23:10Z","event_type":"read_file","service":"","summary":"path=.env","result":"blocked","duration_ms":1}
```

The log is append-only. Existing entries are never modified or deleted (subject to the configured retention policy).

### Where Logs Are Stored

Audit logs are written to `/data/audit/` inside the container. With the default Docker Compose configuration, this directory is persisted in the same named volume as the vault data.

To access logs from outside the container:

```bash
docker exec straylight-ai ls /data/audit/
docker exec straylight-ai cat /data/audit/audit-2026-03-26.jsonl
```

### Querying Audit Events via API

The REST API exposes audit events at `GET /api/v1/audit/events` with optional filters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | string | Filter by service name |
| `event_type` | string | Filter by tool name |
| `from` | ISO 8601 | Start of time range |
| `to` | ISO 8601 | End of time range |
| `result` | string | `success`, `error`, or `blocked` |
| `limit` | integer | Maximum events to return (default: 100) |

**Example — all events for the prod-db service today:**

```bash
curl http://localhost:9470/api/v1/audit/events \
  ?service=prod-db \
  &from=2026-03-26T00:00:00Z
```

### Retention

The default retention period is 90 days. Logs older than this are automatically deleted. Set `retention_days: 0` in the audit configuration for unlimited retention.

### Audit Dashboard

A dedicated audit page in the dashboard is planned for a future release. Until then, use the REST API or read the log files directly.

---

## MCP Tool Reference

These tools are available to Claude Code and any MCP client after connecting to Straylight. The full tool names used in the MCP protocol are prefixed with `straylight_`.

### `straylight_api_call`

Make an authenticated HTTP request to a configured service.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Service name as configured in dashboard |
| `method` | string | Yes | HTTP method: GET, POST, PUT, PATCH, DELETE |
| `path` | string | Yes | Path relative to service base URL (must start with `/`) |
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

### `straylight_exec`

Execute a CLI command with service credentials injected as environment variables in an isolated subprocess. For cloud services (AWS, GCP, Azure), temporary scoped credentials are generated automatically.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Service name |
| `command` | string | Yes | Shell command to execute (do not include secrets in the command string) |
| `timeout_seconds` | integer | No | Timeout in seconds (default: 30, max: 300) |

**Example — AWS CLI:**

```json
{
  "service": "aws-prod",
  "command": "aws s3 ls"
}
```

**Example — GCP:**

```json
{
  "service": "gcp-dev",
  "command": "gcloud compute instances list"
}
```

**Example — PostgreSQL query:**

```json
{
  "service": "postgres",
  "command": "psql -c 'SELECT count(*) FROM users;'"
}
```

**Returns:** stdout and stderr of the command, with any credential values redacted from both.

> Credential values are injected as environment variables into the subprocess only. They are not part of the command string and are not returned in the output.

---

### `straylight_check`

Verify connectivity and authentication status for a configured service. For database and cloud services, also reports lease status and credential expiry.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Service name |

**Example:**

```json
{ "service": "github" }
```

**Returns:** Connection status, account information (username, plan, stats), last verified timestamp, and (for database/cloud services) lease status and expiry. Never returns the credential itself.

---

### `straylight_services`

List all configured services and their current status. Includes HTTP proxy services, database services, and cloud provider services.

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
    "name": "prod-db",
    "template": "PostgreSQL",
    "type": "database",
    "status": "connected",
    "capabilities": ["db_query"],
    "last_verified": "2026-03-24T10:45:00Z"
  },
  {
    "name": "aws-prod",
    "template": "AWS",
    "type": "cloud",
    "status": "connected",
    "capabilities": ["cloud_exec"],
    "last_verified": "2026-03-24T10:50:00Z"
  }
]
```

Credential values are never included in the response.

---

### `straylight_db_query`

Execute a database query through Straylight. Straylight provisions temporary database credentials, runs the query, and returns sanitized results. The AI never sees the connection string or database password. Supports PostgreSQL, MySQL, and Redis.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Name of the configured database service |
| `query` | string | Yes | SQL query (PostgreSQL/MySQL) or Redis command (e.g., `GET key`) |
| `params` | array | No | Bind parameters for parameterized queries — use `$1`, `$2` (PostgreSQL) or `?` (MySQL) in the query |
| `max_rows` | integer | No | Maximum rows to return (default: 100, max: 10000) |

**Example — count recent signups:**

```json
{
  "service": "prod-db",
  "query": "SELECT count(*) FROM users WHERE created_at > $1",
  "params": ["2026-03-01T00:00:00Z"],
  "max_rows": 1
}
```

**Example — Redis get:**

```json
{
  "service": "cache",
  "query": "GET session:user:42"
}
```

**Returns:**

```json
{
  "columns": ["count"],
  "rows": [[1247]],
  "row_count": 1,
  "engine": "postgresql",
  "lease_id": "database/creds/prod-db/abc123",
  "lease_ttl_seconds": 900
}
```

> Use parameterized queries (`$1`, `$2` or `?`) rather than string interpolation to prevent SQL injection.

---

### `straylight_scan`

Scan a project directory for secrets and sensitive files. Reports findings by file, line, pattern type, and severity. Optionally generates ignore rules for AI coding assistant tools.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | No | Directory to scan (default: current working directory) |
| `generate_ignore` | boolean | No | Include recommended ignore rules in the response (default: false) |
| `severity_filter` | string | No | Return only findings at or above this level: `high`, `medium`, `low`, or `all` (default: `all`) |

**Example:**

```json
{
  "path": ".",
  "generate_ignore": true,
  "severity_filter": "high"
}
```

**Returns:**

```json
{
  "findings": [
    {
      "file": ".env",
      "line": 3,
      "column": 1,
      "pattern": "aws_access_key",
      "severity": "high",
      "match": "AWS_ACCESS_KEY_ID=AKIA********************"
    }
  ],
  "files_scanned": 342,
  "files_skipped": 12,
  "duration_ms": 180,
  "ignore_rules": "# Generated by straylight_scan\n.env\n.env.*\n"
}
```

---

### `straylight_read_file`

Read a file with secrets automatically redacted. Use this instead of reading files directly when the file may contain credentials, API keys, connection strings, or other secrets. The file structure and non-secret content are preserved.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Path to the file (relative to project root or absolute) |
| `encoding` | string | No | File encoding (default: `utf-8`) |

**Example:**

```json
{
  "path": "docker-compose.yml"
}
```

**Returns:**

```json
{
  "content": "services:\n  app:\n    environment:\n      DATABASE_URL: [STRAYLIGHT:connection_string]\n      STRIPE_KEY: [STRAYLIGHT:stripe_key]\n",
  "redactions": 2,
  "redacted_patterns": ["connection_string", "stripe_key"],
  "file_size": 1024,
  "warning": null
}
```

If the file matches a blocked pattern (`.env`, private keys, credentials files), the `content` field is omitted and an explanatory message is returned instead.

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
