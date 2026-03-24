# ADR-007: Auth Method Data Model

**Date**: 2026-03-23
**Status**: Proposed

## Context

Every Straylight-AI service template currently maps to a single authentication
strategy: paste one API key, which gets injected as a header or query parameter.
This is insufficient for real-world services:

- **GitHub** supports classic PATs (`ghp_*`), fine-grained PATs
  (`github_pat_*`), GitHub App credentials (3 fields), and OAuth.
- **AWS** requires two or three fields (access key, secret key, optional session
  token) and uses Signature v4 instead of simple header injection.
- **Anthropic** injects via `x-api-key` header, not `Authorization: Bearer`.
- **Google** supports service account JSON, OAuth, and simple API keys.

The current `Service` struct has a flat shape: one `HeaderTemplate`, one
`HeaderName`, one `Inject` mode. There is no concept of "which auth method did
the user choose" or "what credential fields does this method require."

### Constraints

- Templates must be data-driven: adding a new auth method should require zero
  Go code changes (only template data).
- Backward compatibility: existing services created with the old single-key
  model must continue to work.
- The auth method definition must be sufficient for both the UI (to render the
  correct form) and the proxy (to inject credentials correctly).
- Credential values are never stored in the registry; only in OpenBao.

### Scale

Current: 8 built-in templates, each with 1 auth method.
Target: 8+ templates, each with 1-5 auth methods. Future: user-defined
templates with custom auth methods.

## Decision Drivers

- **Dev velocity**: Templates should be data-only; no code per auth method
- **UI simplicity**: The frontend must render forms dynamically from the schema
- **Proxy correctness**: Each auth method maps to a specific injection strategy
- **Backward compatibility**: Existing services must keep working
- **Extensibility**: New auth methods (AWS SigV4, GitHub App JWT) should plug in
  without restructuring

## Options Considered

### Option 1: Flat expansion -- add fields to Service struct

Add `AuthMethod string`, `CredentialFields []FieldDef` directly to the existing
`Service` struct. Templates remain `map[string]Service`.

**Pros**:
- Minimal structural change
- Easy to implement quickly

**Cons**:
- Service struct becomes bloated with UI concerns (labels, placeholders)
- No clean separation between "template definition" (static) and "service
  instance" (runtime)
- Templates and instances share the same type, which is already confusing
- Difficult to represent "choose one of N auth methods" in a flat struct

### Option 2: Separate AuthMethod type with strategy pattern

Introduce an `AuthMethod` struct that describes one way to authenticate with a
service. Templates hold a slice of `AuthMethod`. When a user creates a service,
they choose one auth method; the service stores the chosen method's ID. The
`AuthMethod` defines its required credential fields and its injection strategy.

**Pros**:
- Clean separation: template defines options, service records the choice
- Data-driven: new auth methods are just new `AuthMethod` entries in template data
- UI can render any auth method's form from `CredentialFields`
- Proxy dispatches on `InjectionType` enum, not ad-hoc struct fields
- Backward compatible: existing services default to a "legacy" auth method

**Cons**:
- More types to define and maintain
- Migration path needed for existing services (but straightforward)
- Slightly more complex template definition

### Option 3: Plugin system with registered handlers

Define an `AuthMethodHandler` interface. Each auth method registers a handler
that knows how to render its UI, validate credentials, and inject them. This is
a full plugin architecture.

**Pros**:
- Maximum flexibility
- Handlers can do anything (JWT signing, SigV4, etc.)

**Cons**:
- Massive overengineering for current needs
- Requires code per auth method (defeats data-driven goal)
- Plugin lifecycle adds complexity
- Go does not have a natural plugin mechanism for this

## Decision

Chose **Option 2: Separate AuthMethod type with strategy pattern** because:

1. It cleanly separates the "menu of options" (template auth methods) from the
   "chosen option" (service instance auth method ID). This maps directly to the
   user's mental model: "I picked GitHub, then I chose Fine-grained PAT."

2. It is fully data-driven for the common cases (header injection, query param,
   multi-header). The proxy dispatches on an `InjectionType` enum, not bespoke
   code per service.

3. It leaves room for Phase 2 code-backed strategies (AWS SigV4, GitHub App JWT)
   by allowing the injection type to reference a named strategy that has Go code
   behind it, while keeping the common cases code-free.

4. Backward compatibility is straightforward: existing services that have no
   `auth_method` field default to `"api_key"`, and the proxy's existing
   header/query injection logic is simply wrapped as the default strategy.

## Consequences

**Positive**:
- Adding Slack bot-token vs. user-token is a template data change only
- UI dynamically renders credential forms with proper labels and validation
- Proxy injection logic is decoupled from service identity
- Future auth methods (AWS, GitHub App) have a clear extension point

**Negative**:
- More types and indirection than the current flat model
- Template definitions are more verbose (but more correct)
- Existing services need a default auth_method backfill (low risk)

**Risks**:
- Injection strategies could proliferate. Mitigation: define a small closed set
  of injection types (bearer_header, custom_header, multi_header, query_param,
  basic_auth) and only add new types when a concrete need arises.
- Data-driven model may not handle complex auth (AWS SigV4). Mitigation: the
  design explicitly accommodates "named strategy" injection types that have Go
  code, gated behind Phase 2.

**Tech Debt**:
- The existing `Service.Inject`, `Service.HeaderName`, `Service.HeaderTemplate`,
  `Service.QueryParam` fields become redundant once all services use
  `AuthMethod.Injection`. They should be kept for backward compatibility in
  Phase 1 and deprecated in Phase 3. Paydown plan: after all services are
  migrated to auth-method-aware creation, remove the legacy fields.

## Implementation Notes

### Core Types (Go)

```go
// AuthMethod describes one way to authenticate with a service.
type AuthMethod struct {
    ID          string            `json:"id"          yaml:"id"`
    Name        string            `json:"name"        yaml:"name"`
    Description string            `json:"description" yaml:"description"`
    Fields      []CredentialField `json:"fields"      yaml:"fields"`
    Injection   InjectionConfig   `json:"injection"   yaml:"injection"`
    AutoRefresh bool              `json:"auto_refresh" yaml:"auto_refresh"`
    TokenPrefix string            `json:"token_prefix,omitempty" yaml:"token_prefix,omitempty"`
}

// CredentialField describes one input the user must provide.
type CredentialField struct {
    Key         string `json:"key"         yaml:"key"`
    Label       string `json:"label"       yaml:"label"`
    Type        string `json:"type"        yaml:"type"`        // "password", "text", "textarea"
    Placeholder string `json:"placeholder" yaml:"placeholder"`
    Required    bool   `json:"required"    yaml:"required"`
    Pattern     string `json:"pattern,omitempty" yaml:"pattern,omitempty"`  // regex for client-side validation
    HelpText    string `json:"help_text,omitempty" yaml:"help_text,omitempty"`
}

// InjectionConfig describes how credentials are injected into requests.
type InjectionConfig struct {
    Type           string            `json:"type"            yaml:"type"`            // See InjectionType enum
    HeaderName     string            `json:"header_name,omitempty"     yaml:"header_name,omitempty"`
    HeaderTemplate string            `json:"header_template,omitempty" yaml:"header_template,omitempty"`
    QueryParam     string            `json:"query_param,omitempty"     yaml:"query_param,omitempty"`
    Headers        map[string]string `json:"headers,omitempty"         yaml:"headers,omitempty"`         // for multi_header
    Strategy       string            `json:"strategy,omitempty"        yaml:"strategy,omitempty"`        // for code-backed strategies
}
```

### Injection Types (closed enum)

```
bearer_header   -- Authorization: Bearer {token}
custom_header   -- {header_name}: {header_template with {{.secret}}}
multi_header    -- Multiple headers from multiple credential fields
query_param     -- ?{query_param}={token}
basic_auth      -- Authorization: Basic base64(username:password)
oauth           -- Handled by existing OAuth flow, not credential paste
named_strategy  -- Dispatches to registered Go code (Phase 2: aws_sigv4, github_app_jwt)
```

### Template Structure

```go
type ServiceTemplate struct {
    ID             string            `json:"id"`
    DisplayName    string            `json:"display_name"`
    Description    string            `json:"description"`
    Icon           string            `json:"icon"`
    Target         string            `json:"target"`
    DefaultHeaders map[string]string `json:"default_headers,omitempty"`
    AuthMethods    []AuthMethod      `json:"auth_methods"`
    ExecConfig     *ExecConfig       `json:"exec_config,omitempty"`
}
```

### Service Instance (what gets stored in registry)

The `Service` struct gains one new field:

```go
AuthMethodID string `json:"auth_method,omitempty" yaml:"auth_method,omitempty"`
```

This records which auth method the user chose. The proxy looks up the full
`AuthMethod` definition from the template to determine injection behavior.

### Anti-patterns to avoid

- Do NOT store the full `AuthMethod` struct in each service instance. Store only
  the ID and look up the definition from the template. This keeps service
  instances small and ensures template updates propagate.
- Do NOT add service-specific injection code. If a service needs special
  injection logic, it should be a named strategy registered once, not inline code.
- Do NOT validate credential values against upstream APIs during creation.
  Validation patterns are for format checking only (prefix, length).

## Validation Criteria

- Templates define at least one auth method each
- Every auth method has a unique ID within its template
- Every auth method has at least one credential field (except OAuth)
- UI renders the correct form for each auth method
- Existing services with no `auth_method` field default to working behavior
- Adding a new auth method to an existing template requires only data changes
