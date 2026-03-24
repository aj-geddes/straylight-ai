# Multi-Auth Data Model

## Entity Relationship Diagram

```
+---------------------------+
|    ServiceTemplate        |
+---------------------------+
| id: string (PK)           |
| display_name: string      |
| description: string       |
| icon: string              |
| target: string (URL)      |
| default_headers: map      |
| exec_config?: ExecConfig  |
+---------------------------+
         |
         | 1..* auth_methods
         v
+---------------------------+
|      AuthMethod           |
+---------------------------+
| id: string (PK within     |
|     template scope)       |
| name: string              |
| description: string       |
| auto_refresh: bool        |
| token_prefix?: string     |
+---------------------------+
    |                |
    | 1..*           | 1
    v                v
+------------------+  +---------------------+
| CredentialField  |  |  InjectionConfig    |
+------------------+  +---------------------+
| key: string (PK) |  | type: InjectionType |
| label: string     |  | header_name?: str   |
| type: FieldType   |  | header_template?: s |
| placeholder?: str |  | query_param?: str   |
| required: bool    |  | headers?: map       |
| pattern?: regex   |  | strategy?: string   |
| help_text?: str   |  +---------------------+
+------------------+


+---------------------------+        +---------------------------+
|    Service (Instance)     |        |     OpenBao Vault         |
+---------------------------+        +---------------------------+
| name: string (PK)         |        | Path: services/{name}/    |
| type: string               |        |        credential         |
| target: string             |        +---------------------------+
| status: string             |        | auth_method: string       |
| auth_method: string ------+------->| {field_key}: string       |
| inject: string (legacy)   |        | {field_key}: string       |
| header_name: str (legacy)  |        | ...                       |
| header_template: (legacy)  |        +---------------------------+
| default_headers: map       |
| exec_enabled: bool         |                OR (legacy)
| created_at: timestamp      |
| updated_at: timestamp      |        +---------------------------+
+---------------------------+        | Path: services/{name}/    |
                                     |        credential         |
                                     +---------------------------+
                                     | value: string             |
                                     | type: "api_key"           |
                                     +---------------------------+
```

## InjectionType Enum

```
bearer_header     Single token -> Authorization: Bearer {token}
custom_header     Single token -> {HeaderName}: {rendered HeaderTemplate}
multi_header      Multiple fields -> multiple headers from config.Headers map
query_param       Single token -> ?{QueryParam}={token}
basic_auth        Two fields -> Authorization: Basic base64(username:password)
oauth             No paste fields -> handled by OAuth flow (existing)
named_strategy    Code-backed -> dispatches to registered strategy by name (Phase 2)
```

## FieldType Enum

```
password     Masked input (API keys, tokens, secrets)
text         Visible input (usernames, app IDs, key IDs)
textarea     Multi-line input (PEM keys, JSON blobs)
```

## Template Instance: GitHub

```yaml
id: github
display_name: GitHub
description: GitHub REST and GraphQL API
icon: github
target: https://api.github.com
default_headers:
  Accept: application/vnd.github+json
  X-GitHub-Api-Version: "2022-11-28"
exec_config:
  env_var: GH_TOKEN

auth_methods:
  - id: github_pat_classic
    name: Personal Access Token (classic)
    description: Classic GitHub PAT with broad repository access
    token_prefix: "ghp_"
    fields:
      - key: token
        label: Personal Access Token
        type: password
        placeholder: ghp_xxxxxxxxxxxx
        required: true
        pattern: "^ghp_[a-zA-Z0-9]{36}$"
    injection:
      type: bearer_header

  - id: github_fine_grained_pat
    name: Fine-grained PAT
    description: Scoped token with granular repository and permission control
    token_prefix: "github_pat_"
    fields:
      - key: token
        label: Fine-grained Personal Access Token
        type: password
        placeholder: github_pat_xxxxxxxxxxxx
        required: true
        pattern: "^github_pat_"
    injection:
      type: bearer_header

  - id: github_app
    name: GitHub App
    description: Authenticate as a GitHub App installation (auto-generates JWT)
    auto_refresh: true
    fields:
      - key: app_id
        label: App ID
        type: text
        placeholder: "12345"
        required: true
        pattern: "^[0-9]+$"
      - key: installation_id
        label: Installation ID
        type: text
        placeholder: "67890"
        required: true
        pattern: "^[0-9]+$"
      - key: private_key
        label: Private Key (PEM)
        type: textarea
        placeholder: "-----BEGIN RSA PRIVATE KEY-----\n..."
        required: true
    injection:
      type: named_strategy
      strategy: github_app_jwt

  - id: github_oauth
    name: OAuth
    description: Browser-based GitHub OAuth authorization
    fields: []   # No paste fields; OAuth flow handles credential acquisition
    injection:
      type: oauth
```

## Template Instance: Stripe

```yaml
id: stripe
display_name: Stripe
description: Stripe payment processing API
icon: stripe
target: https://api.stripe.com
default_headers:
  Content-Type: application/x-www-form-urlencoded

auth_methods:
  - id: stripe_api_key
    name: API Key
    description: Standard Stripe secret key
    fields:
      - key: token
        label: Secret Key
        type: password
        placeholder: sk_test_xxxxxxxxxxxx
        required: true
        pattern: "^sk_(test|live)_"
    injection:
      type: bearer_header

  - id: stripe_restricted_key
    name: Restricted Key
    description: Stripe restricted API key with limited permissions
    fields:
      - key: token
        label: Restricted Key
        type: password
        placeholder: rk_test_xxxxxxxxxxxx
        required: true
        pattern: "^rk_(test|live)_"
    injection:
      type: bearer_header

  - id: stripe_connect_oauth
    name: Stripe Connect OAuth
    description: Browser-based Stripe Connect authorization
    fields: []
    injection:
      type: oauth
```

## Template Instance: Anthropic

```yaml
id: anthropic
display_name: Anthropic
description: Anthropic Claude API
icon: anthropic
target: https://api.anthropic.com
default_headers:
  Content-Type: application/json

auth_methods:
  - id: anthropic_api_key
    name: API Key
    description: Anthropic API key (injected as x-api-key header)
    fields:
      - key: token
        label: API Key
        type: password
        placeholder: sk-ant-xxxxxxxxxxxx
        required: true
        pattern: "^sk-ant-"
    injection:
      type: custom_header
      header_name: x-api-key
      header_template: "{{.Secret}}"
```

## Template Instance: AWS

```yaml
id: aws
display_name: AWS
description: Amazon Web Services APIs
icon: aws
target: https://amazonaws.com

auth_methods:
  - id: aws_access_key
    name: Access Key + Secret Key
    description: IAM user access key pair
    fields:
      - key: access_key_id
        label: Access Key ID
        type: text
        placeholder: AKIAIOSFODNN7EXAMPLE
        required: true
        pattern: "^AKIA[0-9A-Z]{16}$"
      - key: secret_access_key
        label: Secret Access Key
        type: password
        placeholder: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        required: true
    injection:
      type: named_strategy
      strategy: aws_sigv4

  - id: aws_session_token
    name: Session Token (STS)
    description: Temporary credentials with session token
    fields:
      - key: access_key_id
        label: Access Key ID
        type: text
        required: true
      - key: secret_access_key
        label: Secret Access Key
        type: password
        required: true
      - key: session_token
        label: Session Token
        type: password
        required: true
    injection:
      type: named_strategy
      strategy: aws_sigv4
```

## Template Instance: Custom Service (Generic)

```yaml
id: custom
display_name: Custom Service
description: Configure a custom API service
icon: custom
target: ""   # User provides

auth_methods:
  - id: api_key_bearer
    name: API Key (Bearer)
    description: Token sent as Authorization Bearer header
    fields:
      - key: token
        label: API Key
        type: password
        required: true
    injection:
      type: bearer_header

  - id: api_key_custom_header
    name: API Key (Custom Header)
    description: Token sent in a custom header
    fields:
      - key: header_name
        label: Header Name
        type: text
        placeholder: X-Api-Key
        required: true
      - key: token
        label: API Key
        type: password
        required: true
    injection:
      type: custom_header
      # header_name comes from credential field "header_name" at creation time

  - id: basic_auth
    name: Basic Auth
    description: Username and password with HTTP Basic authentication
    fields:
      - key: username
        label: Username
        type: text
        required: true
      - key: password
        label: Password
        type: password
        required: true
    injection:
      type: basic_auth

  - id: query_param
    name: Query Parameter
    description: Token sent as a URL query parameter
    fields:
      - key: param_name
        label: Parameter Name
        type: text
        placeholder: api_key
        required: true
      - key: token
        label: API Key
        type: password
        required: true
    injection:
      type: query_param

  - id: custom_oauth
    name: OAuth
    description: Browser-based OAuth authorization
    fields: []
    injection:
      type: oauth
```
