# Multi-Auth-Method Sequence Diagrams

## 1. Service Creation with Auth Method Selection

```mermaid
sequenceDiagram
    participant User
    participant UI as Web UI
    participant API as Internal API
    participant Registry
    participant Vault as OpenBao

    User->>UI: Click "Add Service"
    UI->>API: GET /api/v1/templates
    API-->>UI: templates[] with auth_methods[]

    UI->>User: Show TemplatePicker grid
    User->>UI: Select "GitHub"
    UI->>User: Show AuthMethodPicker<br/>(PAT classic, Fine-grained PAT, GitHub App, OAuth)

    User->>UI: Select "Fine-grained PAT"
    UI->>User: Show CredentialForm<br/>(fields: [{key: "token", label: "Fine-grained PAT", type: "password"}])

    User->>UI: Paste github_pat_xxxx token
    UI->>UI: Client-side validation (pattern: ^github_pat_)
    UI->>API: POST /api/v1/services<br/>{name: "github", auth_method: "github_fine_grained_pat",<br/> credentials: {token: "github_pat_xxx"}, ...}

    API->>Registry: Create(svc, authMethod, credentials)
    Registry->>Vault: WriteSecret("services/github/credential",<br/>{auth_method: "github_fine_grained_pat", token: "github_pat_xxx"})
    Vault-->>Registry: OK
    Registry-->>API: Service created
    API-->>UI: 201 {name: "github", auth_method: "github_fine_grained_pat", status: "available"}
    UI->>User: Show ServiceConfig page
```

## 2. Proxy Request with Auth Method Dispatch

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant MCP as MCP Host
    participant API as Internal API
    participant Proxy
    participant Registry
    participant Vault as OpenBao
    participant Upstream as GitHub API

    Agent->>MCP: straylight_api_call<br/>{service: "github", path: "/repos/..."}
    MCP->>API: POST /api/v1/mcp/tool-call
    API->>Proxy: HandleAPICall(req)

    Proxy->>Registry: Get("github")
    Registry-->>Proxy: Service{auth_method: "github_fine_grained_pat", ...}

    Proxy->>Proxy: resolveInjectionConfig(svc)<br/>-> InjectionConfig{type: "bearer_header"}

    Proxy->>Proxy: credential("github") [cache check]
    alt Cache miss
        Proxy->>Registry: GetCredentials("github")
        Registry->>Vault: ReadSecret("services/github/credential")
        Vault-->>Registry: {auth_method: "github_fine_grained_pat", token: "github_pat_xxx"}
        Registry-->>Proxy: ("github_fine_grained_pat", {token: "github_pat_xxx"})
        Proxy->>Proxy: Cache credentials
    end

    Proxy->>Proxy: injectorRegistry["bearer_header"].Inject(req, config, creds)
    Note right of Proxy: Sets Authorization: Bearer github_pat_xxx

    Proxy->>Upstream: GET /repos/... (with auth header)
    Upstream-->>Proxy: 200 {repo data}
    Proxy->>Proxy: Sanitize response
    Proxy-->>API: APICallResponse
    API-->>MCP: Tool result
    MCP-->>Agent: Response
```

## 3. Legacy Service (Backward Compatibility)

```mermaid
sequenceDiagram
    participant Proxy
    participant Registry
    participant Vault as OpenBao

    Proxy->>Registry: Get("stripe")
    Registry-->>Proxy: Service{inject: "header", header_template: "Bearer {{.secret}}",<br/>auth_method: "" (empty)}

    Proxy->>Proxy: resolveInjectionConfig(svc)<br/>auth_method is empty -> legacy fallback<br/>inject="header" -> InjectionConfig{type: "custom_header",<br/>header_name: "Authorization",<br/>header_template: "Bearer {{.secret}}"}

    Proxy->>Registry: GetCredentials("stripe")
    Registry->>Vault: ReadSecret("services/stripe/credential")
    Vault-->>Registry: {value: "sk_live_xxx", type: "api_key"}<br/>(legacy format, no auth_method key)
    Registry-->>Proxy: ("api_key", {value: "sk_live_xxx"})

    Note right of Proxy: Legacy credential: field key is "value"<br/>Injector maps "value" -> {{.Secret}}

    Proxy->>Proxy: injectorRegistry["custom_header"].Inject(req, config, {value: "sk_live_xxx"})
    Note right of Proxy: Renders "Bearer sk_live_xxx"<br/>Sets Authorization header
```

## 4. Multi-Field Credential (Basic Auth Example)

```mermaid
sequenceDiagram
    participant User
    participant UI as Web UI
    participant API as Internal API
    participant Vault as OpenBao

    User->>UI: Select custom service template
    UI->>User: Show AuthMethodPicker (API Key, Bearer, Basic Auth, Custom Header, OAuth)
    User->>UI: Select "Basic Auth"
    UI->>User: Show CredentialForm<br/>(fields: [{key: "username", label: "Username", type: "text"},<br/> {key: "password", label: "Password", type: "password"}])

    User->>UI: Enter username + password
    UI->>API: POST /api/v1/services<br/>{name: "my-service", auth_method: "basic_auth",<br/> credentials: {username: "admin", password: "s3cret"}, ...}

    API->>Vault: WriteSecret("services/my-service/credential",<br/>{auth_method: "basic_auth", username: "admin", password: "s3cret"})

    Note right of API: Later, during proxy request:
    Note right of API: BasicAuthInjector reads username + password,<br/>encodes base64("admin:s3cret"),<br/>sets Authorization: Basic YWRtaW46czNjcmV0
```

## 5. OAuth Auth Method (Existing Flow, No Change)

```mermaid
sequenceDiagram
    participant User
    participant UI as Web UI
    participant API as Internal API
    participant OAuth as OAuth Handler
    participant Provider as GitHub OAuth

    User->>UI: Select "GitHub" template
    UI->>User: Show AuthMethodPicker
    User->>UI: Select "OAuth"
    UI->>User: Show "Connect with GitHub" button<br/>(no credential fields for OAuth)

    User->>UI: Click "Connect with GitHub"
    UI->>API: Redirect to /api/v1/oauth/github/start?service_name=github
    API->>OAuth: StartOAuth()
    OAuth-->>User: Redirect to GitHub authorization page

    User->>Provider: Authorize
    Provider-->>OAuth: Callback with code
    OAuth->>OAuth: Exchange code for tokens
    OAuth->>API: Store tokens in vault
    OAuth-->>User: Redirect to /services/github?oauth=success
```
