# ADR-009: Injection Strategy Dispatch

**Date**: 2026-03-23
**Status**: Proposed

## Context

The proxy currently has a single `injectCredential()` function with a switch on
`svc.Inject` (either `"header"` or `"query"`). The credential is always a single
string. With multi-auth-method support:

- Different auth methods inject credentials differently (Bearer header, custom
  header name, Basic Auth encoding, multiple headers, query parameter)
- Some auth methods have multiple credential fields that map to different parts
  of the request
- Some auth methods require transformation (Basic Auth base64 encoding) or
  complex signing (AWS SigV4, GitHub App JWT)

The proxy must dispatch to the correct injection logic based on the auth method's
injection configuration, not just the service's flat `Inject` field.

### Constraints

- The proxy is on the hot path: every agent API call goes through it
- Injection must work with the credential cache (credential is fetched once,
  then used for multiple requests within the TTL)
- Phase 1 must support: bearer_header, custom_header, multi_header, query_param,
  basic_auth
- Phase 2 strategies (aws_sigv4, github_app_jwt) must be accommodated in the
  design but not implemented yet
- OAuth injection is already handled by the existing OAuth token flow and does
  not change

## Decision Drivers

- **Performance**: No reflection, no dynamic dispatch overhead for common cases
- **Correctness**: Each injection type must produce exactly the right HTTP
  request
- **Extensibility**: Phase 2 strategies (SigV4, JWT signing) must plug in
  without restructuring
- **Testability**: Each strategy must be independently testable
- **Backward compatibility**: Existing services with flat `Inject` field must
  keep working

## Options Considered

### Option 1: Expand the existing switch statement

Add more cases to the existing `injectCredential()` switch:

```go
switch injectionType {
case "bearer_header": ...
case "custom_header": ...
case "multi_header": ...
case "query_param": ...
case "basic_auth": ...
}
```

**Pros**:
- Simple, low ceremony
- All injection logic in one place
- Easy to understand

**Cons**:
- Function grows large as injection types are added
- Phase 2 strategies (SigV4 with request body hashing) are complex enough to
  merit separate units
- Harder to test individual strategies in isolation

### Option 2: Strategy interface with registered implementations

Define an `Injector` interface. Each injection type implements it. A registry
maps injection type strings to `Injector` instances. The proxy looks up the
injector by type and calls it.

```go
type Injector interface {
    Inject(req *http.Request, config InjectionConfig, credentials map[string]string) error
}
```

**Pros**:
- Each strategy is independently testable
- New strategies are added by implementing the interface and registering
- SigV4 and JWT signing naturally fit as strategy implementations
- Clean separation of concerns

**Cons**:
- More types and indirection
- Interface dispatch has negligible but non-zero overhead
- Risk of over-abstraction for what are currently simple operations

### Option 3: Function registry (no interface)

Map injection type strings to `func(req, config, creds)` functions:

```go
var injectors = map[string]func(*http.Request, InjectionConfig, map[string]string) error{
    "bearer_header": injectBearerHeader,
    "custom_header": injectCustomHeader,
    ...
}
```

**Pros**:
- Lighter weight than an interface
- Still allows isolated testing of each function
- Easy to register new functions

**Cons**:
- Functions cannot carry state (needed for SigV4 which may need HTTP client
  for STS)
- Less discoverable than a typed interface
- Cannot enforce method contracts at compile time

## Decision

Chose **Option 2: Strategy interface** because:

1. **Phase 2 strategies need state**. AWS SigV4 requires access to the current
   time, request body hash, and potentially an STS client for session tokens.
   GitHub App JWT generation requires crypto operations and a clock. An interface
   allows implementations to carry their dependencies.

2. **Testability**. Each injector can be tested with a mock `*http.Request`
   and verified credential map. The proxy test only needs to verify that the
   correct injector is called.

3. **The overhead is negligible**. Go interface dispatch is one vtable lookup.
   The proxy already does a vault read, HTTP client dial, and TLS handshake per
   request. An interface call adds zero measurable latency.

4. **Backward compatibility is clean**. The existing `injectCredential()`
   function becomes the `BearerHeaderInjector` and `QueryParamInjector`
   implementations. The proxy's `buildUpstreamRequest` method switches from
   calling `injectCredential()` to calling `injectorRegistry.Get(type).Inject()`.

## Consequences

**Positive**:
- Each injection strategy is a self-contained, testable unit
- Adding AWS SigV4 or GitHub App JWT is "implement Injector, register it"
- Existing proxy tests validate backward compatibility through the interface
- Strategy implementations can be tested without a full proxy setup

**Negative**:
- More files and types than the current flat switch
- Developers must know about the registry when adding strategies
- Slight indirection makes "find where injection happens" less obvious

**Risks**:
- Strategy proliferation (too many injection types). Mitigation: the injection
  type enum is closed. New types require an ADR. We expect at most 8-10 types
  total.
- Inconsistent error handling across strategies. Mitigation: the `Injector`
  interface returns `error`; all errors are wrapped with strategy context by the
  proxy before returning.

**Tech Debt**:
- The existing `injectCredential()` function should be refactored into the
  interface pattern rather than kept alongside it. Paydown: Phase 1 wraps
  existing code in the interface; Phase 1.1 deletes the old function.

## Implementation Notes

### Interface

```go
// Injector applies credentials to an outbound HTTP request.
type Injector interface {
    // Inject modifies req in place to include the authentication credentials.
    // config provides the injection parameters from the auth method definition.
    // credentials is the map of field_key -> value read from the vault.
    Inject(req *http.Request, config InjectionConfig, credentials map[string]string) error
}
```

### Built-in Injectors (Phase 1)

```go
// BearerHeaderInjector sets Authorization: Bearer {token}
// Credential field: "token" (or "value" for legacy)
type BearerHeaderInjector struct{}

// CustomHeaderInjector sets {header_name}: {rendered_template}
// Uses config.HeaderName and config.HeaderTemplate
// Credential field: "token" (mapped into template as {{.Secret}})
type CustomHeaderInjector struct{}

// MultiHeaderInjector sets multiple headers from multiple credential fields
// Uses config.Headers map: header_name -> "{{.field_key}}"
type MultiHeaderInjector struct{}

// QueryParamInjector sets ?{query_param}={token}
// Credential field: "token" (or "value" for legacy)
type QueryParamInjector struct{}

// BasicAuthInjector sets Authorization: Basic base64(username:password)
// Credential fields: "username", "password"
type BasicAuthInjector struct{}
```

### Phase 2 Injectors (named strategies)

```go
// AWSSigV4Injector signs requests using AWS Signature Version 4
// Credential fields: "access_key_id", "secret_access_key", "session_token" (optional)
// Requires: region, service name from config

// GitHubAppJWTInjector generates a JWT from GitHub App credentials
// Credential fields: "app_id", "installation_id", "private_key"
// Requires: JWT signing, installation token exchange
```

### Injector Registry

```go
var defaultInjectors = map[string]Injector{
    "bearer_header": &BearerHeaderInjector{},
    "custom_header": &CustomHeaderInjector{},
    "multi_header":  &MultiHeaderInjector{},
    "query_param":   &QueryParamInjector{},
    "basic_auth":    &BasicAuthInjector{},
    // Phase 2:
    // "aws_sigv4":       &AWSSigV4Injector{},
    // "github_app_jwt":  &GitHubAppJWTInjector{},
}
```

### Proxy Integration

The proxy's `buildUpstreamRequest` method changes from:

```go
if err := injectCredential(upstreamReq, svc, cred); err != nil { ... }
```

To:

```go
injectionConfig := resolveInjectionConfig(svc)
injector := injectorRegistry[injectionConfig.Type]
if injector == nil {
    return nil, fmt.Errorf("unsupported injection type %q", injectionConfig.Type)
}
if err := injector.Inject(upstreamReq, injectionConfig, credentials); err != nil { ... }
```

Where `resolveInjectionConfig()` handles backward compatibility:

```go
func resolveInjectionConfig(svc Service) InjectionConfig {
    // If service has an auth_method, look up the injection config from the template
    if svc.AuthMethodID != "" {
        template := Templates[svc.Name] // or from a template lookup
        for _, am := range template.AuthMethods {
            if am.ID == svc.AuthMethodID {
                return am.Injection
            }
        }
    }
    // Legacy fallback: convert flat Service fields to InjectionConfig
    switch svc.Inject {
    case "header":
        return InjectionConfig{
            Type:           "custom_header",
            HeaderName:     svc.HeaderName,
            HeaderTemplate: svc.HeaderTemplate,
        }
    case "query":
        return InjectionConfig{
            Type:       "query_param",
            QueryParam: svc.QueryParam,
        }
    }
    return InjectionConfig{Type: "bearer_header"}
}
```

### Credential Field Mapping

Each injector documents which credential field keys it reads:

| Injector | Required Fields | Optional Fields |
|----------|----------------|-----------------|
| bearer_header | `token` (or legacy `value`) | |
| custom_header | `token` (or legacy `value`) | |
| multi_header | varies per config.Headers | |
| query_param | `token` (or legacy `value`) | |
| basic_auth | `username`, `password` | |
| aws_sigv4 (Phase 2) | `access_key_id`, `secret_access_key` | `session_token` |
| github_app_jwt (Phase 2) | `app_id`, `installation_id`, `private_key` | |

## Validation Criteria

- Every built-in injector has unit tests with at least 3 cases (happy path,
  missing field, malformed field)
- Proxy integration test covers each injection type end-to-end
- Legacy services (no auth_method field) use the existing injection behavior
  via backward-compatible resolution
- Injector registration is validated at startup (no nil injectors)
- Adding a new injector requires only: implement interface, register in map,
  add to template
