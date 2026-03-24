# Service Registry Data Model

## Overview

The service registry is the central data structure tracking all configured services.
It has two storage locations:

1. **Configuration (config.yaml)**: Service metadata, connection settings, injection rules
2. **OpenBao (KV v2)**: Credential values (API keys, OAuth tokens)

This split ensures that credentials never appear in config files and config files
never need to be encrypted.

## Data Model

### Service (in config.yaml)

```
Service
  name:               string     -- Primary key. Lowercase, [a-z][a-z0-9_-]{0,62}
  type:               enum       -- http_proxy | oauth
  target:             uri        -- Base URL of external service
  inject:             enum       -- header | query | body
  header_template:    string     -- Go template for header value
  header_name:        string     -- HTTP header name (default: Authorization)
  query_param:        string     -- Query param name (if inject=query)
  default_headers:    map[string]string  -- Additional headers per request
  timeout_seconds:    int        -- Request timeout (default: 30)
  exec_config:        ExecConfig -- Command wrapping configuration
  oauth_config:       OAuthConfig -- OAuth settings (if type=oauth)
  credential_patterns: []string  -- Regex patterns for sanitizer
  created_at:         timestamp  -- When service was added
  updated_at:         timestamp  -- Last configuration change
```

### ExecConfig (embedded in Service)

```
ExecConfig
  env_var:            string     -- Environment variable for credential
  allowed_commands:   []string   -- Command prefix allowlist (optional)
  env_extras:         map[string]string  -- Additional env vars (non-secret)
```

### OAuthConfig (embedded in Service)

```
OAuthConfig
  provider:           string     -- Provider identifier (github, google, stripe)
  client_id:          string     -- OAuth client ID
  auth_url:           uri        -- Authorization endpoint
  token_url:          uri        -- Token endpoint
  scopes:             []string   -- Requested scopes
  auto_refresh:       bool       -- Auto-refresh expired tokens
  redirect_uri:       uri        -- Callback URL
```

## OpenBao Secret Paths

### Static Credentials (API keys, tokens)

```
Path:    secret/data/services/{name}/credential
Payload: {
           "data": {
             "api_key": "sk_live_...",     -- or "token", etc.
             "type": "api_key"             -- credential type tag
           }
         }
```

### OAuth Tokens

```
Path:    secret/data/services/{name}/oauth
Payload: {
           "data": {
             "access_token": "gho_...",
             "refresh_token": "ghr_...",
             "token_type": "bearer",
             "expires_at": "2026-03-22T11:30:00Z",
             "scopes": "repo,read:org"
           }
         }
```

### OAuth Client Secret

```
Path:    secret/data/oauth/{provider}/client
Payload: {
           "data": {
             "client_secret": "..."
           }
         }
```

## Credential Lifecycle

### Static Credentials (API Keys)

```
States: [not_configured] --> [available] --> [revoked/deleted]

Transitions:
  not_configured -> available:   User pastes key in Web UI
  available -> available:        User updates key
  available -> not_configured:   User deletes service
```

### OAuth Credentials

```
States: [not_configured] --> [authorizing] --> [available] --> [expired] --> [available]
                                                                    |
                                                                    v
                                                              [refresh_failed]

Transitions:
  not_configured -> authorizing:    User clicks "Connect" in Web UI
  authorizing -> available:         OAuth callback received with valid code
  authorizing -> not_configured:    User cancels or error occurs
  available -> expired:             Token expiry time passes
  expired -> available:             Auto-refresh succeeds
  expired -> refresh_failed:        Auto-refresh fails
  refresh_failed -> authorizing:    User re-authorizes
  available -> not_configured:      User disconnects service
```

## Service Templates (Built-in)

Pre-configured templates for common services. These are compiled into the Go binary
and returned by the `/api/v1/templates` endpoint.

| Template | Type | Target | Inject | Header Template | Env Var | Patterns |
|----------|------|--------|--------|-----------------|---------|----------|
| stripe | http_proxy | https://api.stripe.com | header | Bearer {{.secret}} | STRIPE_API_KEY | sk_live_*, sk_test_* |
| github | oauth | https://api.github.com | header | Bearer {{.secret}} | GH_TOKEN | ghp_*, gho_* |
| openai | http_proxy | https://api.openai.com | header | Bearer {{.secret}} | OPENAI_API_KEY | sk-* |
| anthropic | http_proxy | https://api.anthropic.com | header | {{.secret}} | ANTHROPIC_API_KEY | sk-ant-* |
| google | oauth | https://www.googleapis.com | header | Bearer {{.secret}} | -- | ya29.* |
| aws | http_proxy | -- | custom | -- | AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY | AKIA*, aws_* |
| gitlab | http_proxy | https://gitlab.com/api/v4 | header | Bearer {{.secret}} | GITLAB_TOKEN | glpat-* |
| slack | http_proxy | https://slack.com/api | header | Bearer {{.secret}} | SLACK_TOKEN | xoxb-*, xoxp-* |

## OpenBao Policy

```hcl
# Policy: straylight-service-access
# Applied to the AppRole used by the Go process

# Read/write service credentials
path "secret/data/services/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/services/*" {
  capabilities = ["list", "read", "delete"]
}

# Read/write OAuth client secrets
path "secret/data/oauth/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/oauth/*" {
  capabilities = ["list", "read", "delete"]
}
```

## Indexes and Lookups

The service registry supports the following lookups:

| Lookup | Implementation | Use Case |
|--------|---------------|----------|
| By name | Map key in config.yaml | MCP tool calls (service parameter) |
| By type | Linear scan (< 100 services) | Web UI filtering |
| All services | Map iteration | straylight_services tool |
| Credential by name | OpenBao GET | Proxy credential injection |
| Templates by ID | Compiled map | Web UI service setup |

At the scale of the free tier (single user, < 100 services), all lookups are O(1)
or O(n) with trivial n. No database or indexing infrastructure is needed.

## Data Integrity Rules

1. **Service name uniqueness**: Enforced by map key in config.yaml
2. **Service name format**: Validated by regex `^[a-z][a-z0-9_-]{0,62}$`
3. **Target URL required**: Every service must have a valid base URL
4. **Credential isolation**: Credentials exist only in OpenBao, never in config
5. **OAuth requires client_id**: OAuth-type services must have a client_id
6. **No orphan credentials**: Deleting a service deletes its OpenBao paths
7. **No orphan config**: Creating a service without a credential is allowed (status: not_configured)
