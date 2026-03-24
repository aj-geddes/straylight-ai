# Implementation Guide: Multi-Auth-Method Support

## Overview

This guide provides a phased build plan for implementing multi-auth-method
support. Each work package is designed to be independently testable and
deployable. All changes are backward compatible with existing services.

**Key design documents**:
- ADR-007: Auth method data model (`adr/ADR-007-auth-method-model.md`)
- ADR-008: Credential storage evolution (`adr/ADR-008-credential-storage.md`)
- ADR-009: Injection strategy dispatch (`adr/ADR-009-injection-strategies.md`)
- Data model: `diagrams/data-model.md`
- Sequence diagrams: `diagrams/auth-method-flow.md`
- API contract changes: `contracts/api-changes.yaml`
- Go schema: `schemas/auth-method-schema.go`
- TypeScript schema: `schemas/auth-method-schema.ts`

---

## Phase 1: Core Data Model and Backend (4 work packages)

### WP-MA-1: New Types and Template Definitions

**Goal**: Define the AuthMethod, CredentialField, InjectionConfig, and
ServiceTemplate types. Rewrite the built-in templates to use the new
ServiceTemplate type with auth methods.

**Files to create**:
- `internal/services/auth_methods.go` -- New types (AuthMethod, CredentialField,
  InjectionConfig, InjectionType constants, FieldType constants)
- `internal/services/auth_methods_test.go` -- Validation tests

**Files to modify**:
- `internal/services/templates.go` -- Replace `map[string]Service` with
  `map[string]ServiceTemplate`. Each template gets its auth_methods slice.

**Type definitions**: See `schemas/auth-method-schema.go` for exact struct shapes.

**Template definitions**: See `diagrams/data-model.md` for the full template
definitions for GitHub, Stripe, OpenAI, Anthropic, Slack, GitLab, Google, and
Custom.

**Implementation notes**:
- Add a `ValidateAuthMethod(am AuthMethod) error` function that enforces:
  - ID is non-empty and matches `^[a-z][a-z0-9_]{0,62}$`
  - Name is non-empty
  - Fields have unique keys within the auth method
  - No field key is a reserved metadata key (`auth_method`, `type`)
  - Injection type is a valid enum value
  - If injection type is `custom_header`, HeaderName must be set
  - If injection type is `query_param`, QueryParam must be set
  - If injection type is `named_strategy`, Strategy must be set
  - OAuth injection type must have empty Fields slice
- Add a `ValidateTemplate(t ServiceTemplate) error` function that enforces:
  - At least one auth method
  - Auth method IDs are unique within the template
  - All auth methods pass ValidateAuthMethod

**Tests (minimum)**:
- ValidateAuthMethod accepts valid auth method
- ValidateAuthMethod rejects empty ID, empty name, reserved field keys
- ValidateAuthMethod rejects custom_header without HeaderName
- ValidateTemplate rejects template with zero auth methods
- ValidateTemplate rejects duplicate auth method IDs
- All built-in templates pass validation

**Backward compatibility**: The existing `Templates` variable type changes from
`map[string]Service` to `map[string]ServiceTemplate`. This requires updating
`handleListTemplates` in `routes.go` (trivial -- it already serializes to JSON).
The frontend TypeScript type changes too (WP-MA-5).

**Dependencies**: None (first work package).

---

### WP-MA-2: Multi-Field Credential Storage

**Goal**: Evolve credential storage to support multiple fields per service while
maintaining backward compatibility with existing single-field secrets.

**Files to modify**:
- `internal/services/registry.go`

**Changes**:

1. Add `AuthMethodID string` field to `Service` struct:
   ```go
   AuthMethodID string `json:"auth_method,omitempty" yaml:"auth_method,omitempty"`
   ```

2. Add `writeCredentials` method (new, multi-field):
   ```go
   func (r *Registry) writeCredentials(name, authMethod string, fields map[string]string) error
   ```
   Stores `auth_method` as a metadata key alongside the credential field values
   in a single vault secret at `services/{name}/credential`.

3. Add `GetCredentials` method (new, multi-field read with legacy fallback):
   ```go
   func (r *Registry) GetCredentials(name string) (authMethod string, fields map[string]string, err error)
   ```
   - If vault secret has `auth_method` key: new format, return all other keys
     as fields.
   - If vault secret has `value` key but no `auth_method`: legacy format,
     return `("api_key", {"value": val})`.
   - Otherwise: return error.

4. Add `CreateWithAuth` method:
   ```go
   func (r *Registry) CreateWithAuth(svc Service, authMethod string, credentials map[string]string) error
   ```
   Like `Create` but stores auth method ID and multi-field credentials.

5. Add `RotateCredentials` method:
   ```go
   func (r *Registry) RotateCredentials(name string, credentials map[string]string) error
   ```
   Like `RotateCredential` but writes all fields atomically. Preserves the
   existing `auth_method` value.

6. Keep existing `Create(svc, credential string)` and
   `GetCredential(name string) (string, error)` methods working. The old
   `Create` internally calls `writeCredentials(name, "api_key", {"value": credential})`.
   The old `GetCredential` internally calls `GetCredentials` and returns
   `fields["value"]` or `fields["token"]`.

**Tests (minimum)**:
- CreateWithAuth stores multi-field credentials in vault
- GetCredentials reads new format correctly
- GetCredentials reads legacy format correctly (backward compat)
- RotateCredentials replaces all fields atomically
- Legacy Create still works (stores as {"value": ..., "auth_method": "api_key"})
- Legacy GetCredential still works (reads from new format via backward compat)

**Dependencies**: None (can be done in parallel with WP-MA-1).

---

### WP-MA-3: Injection Strategy Interface and Built-in Injectors

**Goal**: Refactor the proxy's credential injection from a flat switch to a
strategy pattern with registered injectors.

**Files to create**:
- `internal/proxy/injector.go` -- Injector interface, InjectorRegistry,
  built-in injector implementations
- `internal/proxy/injector_test.go` -- Unit tests for each injector

**Files to modify**:
- `internal/proxy/proxy.go` -- Replace `injectCredential()` call with
  injector dispatch

**Injector interface**:
```go
type Injector interface {
    Inject(req *http.Request, config services.InjectionConfig, credentials map[string]string) error
}
```

**Built-in injectors**:

1. `BearerHeaderInjector` -- Sets `Authorization: Bearer {creds["token"]}`.
   Falls back to `creds["value"]` for legacy compatibility.

2. `CustomHeaderInjector` -- Sets `{config.HeaderName}: {rendered config.HeaderTemplate}`.
   The template receives `creds["token"]` (or `creds["value"]`) as `{{.Secret}}`.

3. `MultiHeaderInjector` -- Iterates `config.Headers` map. For each
   `header_name -> template`, renders the template with the matching credential
   field and sets the header.

4. `QueryParamInjector` -- Sets `?{config.QueryParam}={creds["token"]}`.
   Falls back to `creds["value"]` for legacy.

5. `BasicAuthInjector` -- Reads `creds["username"]` and `creds["password"]`,
   base64-encodes `username:password`, sets `Authorization: Basic {encoded}`.

**Registry**:
```go
var DefaultInjectors = map[services.InjectionType]Injector{
    services.InjectionBearerHeader:  &BearerHeaderInjector{},
    services.InjectionCustomHeader:  &CustomHeaderInjector{},
    services.InjectionMultiHeader:   &MultiHeaderInjector{},
    services.InjectionQueryParam:    &QueryParamInjector{},
    services.InjectionBasicAuth:     &BasicAuthInjector{},
}
```

**Proxy changes**:

1. Change `Proxy` struct to hold an injector registry:
   ```go
   type Proxy struct {
       // ... existing fields ...
       injectors map[services.InjectionType]Injector
   }
   ```

2. Change `credential()` method to return `(string, map[string]string, error)`.
   The first return is the auth method ID; the second is the credential fields map.
   Cache entry changes from `cachedCredential{value string}` to
   `cachedCredentials{authMethod string; fields map[string]string}`.

3. Change `ServiceResolver` interface:
   ```go
   type ServiceResolver interface {
       Get(name string) (services.Service, error)
       GetCredential(name string) (string, error)           // Keep for backward compat
       GetCredentials(name string) (string, map[string]string, error)  // New
   }
   ```

4. Add `resolveInjectionConfig(svc services.Service) services.InjectionConfig`:
   - If `svc.AuthMethodID != ""`: look up template, find matching auth method,
     return its injection config.
   - Else (legacy): convert `svc.Inject`/`svc.HeaderName`/`svc.HeaderTemplate`
     to an `InjectionConfig`.

5. Replace `injectCredential(req, svc, cred)` call in `buildUpstreamRequest`
   with:
   ```go
   config := resolveInjectionConfig(svc)
   injector := p.injectors[config.Type]
   if injector == nil {
       return nil, fmt.Errorf("unsupported injection type %q", config.Type)
   }
   err := injector.Inject(upstreamReq, config, credentials)
   ```

6. Keep the old `injectCredential` function as a private helper called by
   `CustomHeaderInjector` and `QueryParamInjector` (reuse, not duplication).

**Tests (minimum)**:
- BearerHeaderInjector sets correct header with "token" key
- BearerHeaderInjector falls back to "value" key (legacy)
- BearerHeaderInjector returns error on missing credential
- CustomHeaderInjector renders template with custom header name
- CustomHeaderInjector uses default "Authorization" when header_name empty
- MultiHeaderInjector sets multiple headers from credential map
- QueryParamInjector sets correct query parameter
- BasicAuthInjector encodes username:password correctly
- BasicAuthInjector returns error on missing username or password
- resolveInjectionConfig returns correct config for legacy services
- resolveInjectionConfig returns correct config for auth-method services
- Full proxy integration test with each injection type

**Backward compatibility**: All existing proxy_test.go tests must pass without
modification. The existing test services have no AuthMethodID, so they exercise
the legacy path.

**Dependencies**: WP-MA-1 (for type definitions), WP-MA-2 (for GetCredentials).

---

### WP-MA-4: API Endpoint Updates

**Goal**: Update the HTTP API endpoints to accept and return the new auth method
fields.

**Files to modify**:
- `internal/server/routes.go`

**Changes**:

1. Update `createServiceRequest` struct:
   ```go
   type createServiceRequest struct {
       Name           string            `json:"name"`
       Type           string            `json:"type"`
       Target         string            `json:"target"`
       AuthMethod     string            `json:"auth_method,omitempty"`
       Inject         string            `json:"inject"`           // legacy
       HeaderName     string            `json:"header_name,omitempty"`  // legacy
       HeaderTemplate string            `json:"header_template,omitempty"` // legacy
       QueryParam     string            `json:"query_param,omitempty"` // legacy
       DefaultHeaders map[string]string `json:"default_headers,omitempty"`
       Credentials    map[string]string `json:"credentials,omitempty"` // new multi-field
       Credential     string            `json:"credential,omitempty"`  // legacy single
   }
   ```

2. Update `handleCreateService`:
   - If `req.AuthMethod != ""` and `req.Credentials` is non-empty:
     call `Registry.CreateWithAuth(svc, req.AuthMethod, req.Credentials)`
   - Else if `req.Credential != ""`:
     call `Registry.Create(svc, req.Credential)` (legacy path)
   - Else:
     return 400 "credential or credentials required"

3. Update `updateServiceRequest` struct similarly.

4. Update `handleUpdateService`:
   - If `req.Credentials` is non-empty: write multi-field credentials
   - Else if `req.Credential != ""`: write single credential (legacy)
   - Else: preserve existing credentials

5. Update `rotateCredentialRequest`:
   ```go
   type rotateCredentialRequest struct {
       Credentials map[string]string `json:"credentials,omitempty"`
       Credential  string            `json:"credential,omitempty"`
   }
   ```

6. Update `handleListTemplates` to serialize `ServiceTemplate` instead of
   `Service`.

7. Add credential field validation in `handleCreateService`:
   - When `auth_method` is provided, look up the template and auth method
   - Validate that all required fields from the auth method definition are
     present in the credentials map
   - Validate field values against patterns if defined

**Tests**:
- POST /api/v1/services with auth_method + credentials creates service
- POST /api/v1/services with legacy credential still works
- POST /api/v1/services with auth_method but missing required field returns 400
- POST /api/v1/services with auth_method validates field patterns
- PUT /api/v1/services/{name} with credentials updates multi-field creds
- POST /api/v1/services/{name}/rotate with credentials rotates all fields
- GET /api/v1/templates returns templates with auth_methods
- GET /api/v1/services/{name} includes auth_method in response

**Dependencies**: WP-MA-1, WP-MA-2.

---

## Phase 1: Frontend (2 work packages)

### WP-MA-5: Updated TypeScript Types and API Client

**Goal**: Update frontend types to match the new API contract.

**Files to modify**:
- `web/src/types/service.ts` -- Updated types per `schemas/auth-method-schema.ts`
- `web/src/api/client.ts` -- Update createService/updateService to accept the
  new request shapes

**Changes**: See `schemas/auth-method-schema.ts` for exact type definitions.

**Key points**:
- `ServiceTemplate` gains `auth_methods: AuthMethod[]`
- `CreateServiceRequest` gains `auth_method?` and `credentials?` (map)
- `Service` gains `auth_method?` and `auth_method_name?`
- Legacy fields (`credential`, `inject`, `header_template`) are kept but
  marked with JSDoc `@deprecated`

**Dependencies**: WP-MA-4 (API must be deployed first, or develop against
mock data).

---

### WP-MA-6: Auth Method Selection UI

**Goal**: Update the service creation flow to let users choose an auth method
and fill in dynamic credential fields.

**Files to modify**:
- `web/src/components/TemplatePicker.tsx` -- No functional changes needed
  (templates still have `display_name` and `icon`)
- `web/src/components/PasteKeyDialog.tsx` -- Major rewrite to support multi-auth

**Files to create**:
- `web/src/components/AuthMethodPicker.tsx` -- New component for auth method
  selection within a template
- `web/src/components/CredentialForm.tsx` -- New component that dynamically
  renders credential fields from an AuthMethod definition

**UI Flow** (updated service creation):

```
1. User clicks "Add Service"
2. TemplatePicker shows grid of templates (no change)
3. User clicks a template (e.g., "GitHub")
4. NEW: AuthMethodPicker shows the template's auth methods as radio buttons
   or cards:
   - [x] Personal Access Token (classic)
   - [ ] Fine-grained PAT
   - [ ] GitHub App
   - [ ] OAuth (Connect with GitHub button)
5. User selects an auth method
6. NEW: CredentialForm renders the selected auth method's fields:
   - For PAT classic: one password field labeled "Personal Access Token"
     with placeholder "ghp_xxxxxxxxxxxx"
   - For GitHub App: three fields (App ID text, Installation ID text,
     Private Key textarea)
   - For OAuth: a "Connect with GitHub" button (no fields)
7. User fills in fields and clicks Save
8. Frontend sends POST /api/v1/services with auth_method and credentials
```

**AuthMethodPicker component**:
```tsx
interface AuthMethodPickerProps {
  authMethods: AuthMethod[];
  selected: string | null;
  onSelect: (authMethodId: string) => void;
}
```
- Renders each auth method as a selectable card/radio with name and description
- OAuth methods show a distinct visual treatment (e.g., "Connect with {provider}"
  button style)
- Pre-selects the first non-OAuth method by default

**CredentialForm component**:
```tsx
interface CredentialFormProps {
  authMethod: AuthMethod;
  values: Record<string, string>;
  onChange: (key: string, value: string) => void;
  errors: Record<string, string>;
}
```
- Renders each `CredentialField` as the appropriate input type
- password -> `<input type="password">`
- text -> `<input type="text">`
- textarea -> `<textarea>` with monospace font (for PEM keys)
- Shows placeholder, help_text, and validation errors per field
- Validates against `pattern` regex on blur (client-side)

**Updated PasteKeyDialog**:
- In create mode with a template that has auth_methods: show AuthMethodPicker
  then CredentialForm
- In create mode with legacy template (no auth_methods, shouldn't happen after
  migration): show single credential field (backward compat)
- In update mode: show CredentialForm for the service's current auth method
- When the selected auth method has `injection.type === "oauth"`: show OAuth
  connect button instead of credential fields

**ServiceConfig page updates**:
- Display `auth_method_name` in the service detail card
- "Update Credential" button shows CredentialForm for the current auth method
  (multi-field if applicable)

**Tests**:
- AuthMethodPicker renders all auth methods from a template
- AuthMethodPicker calls onSelect when a method is clicked
- CredentialForm renders correct input types (password, text, textarea)
- CredentialForm validates patterns on blur
- CredentialForm shows required field errors
- Full create flow: template -> auth method -> fields -> submit
- OAuth auth method shows connect button instead of fields
- Update credential flow renders correct fields for current auth method

**Dependencies**: WP-MA-5.

---

## Phase 2: Advanced Auth Methods (future, not in initial scope)

### WP-MA-7: GitHub App JWT Generation

- Implement `GitHubAppJWTInjector` that:
  1. Reads `app_id`, `installation_id`, `private_key` from credentials
  2. Generates a JWT signed with the private key (RS256)
  3. Exchanges the JWT for an installation access token via GitHub API
  4. Caches the installation token (valid for 1 hour)
  5. Injects `Authorization: token {installation_token}`
- Register as `named_strategy: "github_app_jwt"`

### WP-MA-8: Google Service Account

- Implement `GoogleServiceAccountInjector` that:
  1. Reads `service_account_json` from credentials
  2. Parses the JSON to extract private key and client email
  3. Generates a signed JWT for the target API scope
  4. Exchanges for an access token via Google's token endpoint
  5. Caches the access token (valid for 1 hour)
  6. Injects `Authorization: Bearer {access_token}`
- Register as `named_strategy: "google_service_account"`

### WP-MA-9: AWS Signature V4

- Implement `AWSSigV4Injector` that:
  1. Reads `access_key_id`, `secret_access_key`, optional `session_token`
  2. Signs the request using AWS Signature Version 4
  3. Adds `Authorization`, `X-Amz-Date`, optional `X-Amz-Security-Token` headers
- This requires access to the request body (for payload hash) which the current
  injector interface supports (it receives `*http.Request`)
- Register as `named_strategy: "aws_sigv4"`
- Depends on adding `region` and `aws_service` to InjectionConfig or to
  template metadata

---

## Dependency Graph

```
WP-MA-1 (Types + Templates)  ──┐
                                ├──> WP-MA-3 (Injectors)
WP-MA-2 (Credential Storage) ──┤
                                ├──> WP-MA-4 (API Endpoints)
                                │         │
                                │         v
                                │    WP-MA-5 (TS Types)
                                │         │
                                │         v
                                │    WP-MA-6 (UI Components)
                                │
                                └──> Phase 2 (WP-MA-7, 8, 9)
```

WP-MA-1 and WP-MA-2 can be done in parallel.
WP-MA-3 depends on both WP-MA-1 and WP-MA-2.
WP-MA-4 depends on WP-MA-1 and WP-MA-2.
WP-MA-5 depends on WP-MA-4 (or can develop against mock data).
WP-MA-6 depends on WP-MA-5.

---

## Migration and Backward Compatibility

### No Data Migration Required

Existing services in the registry have no `auth_method` field (empty string).
Existing credentials in vault have the legacy format `{"value": "...", "type": "api_key"}`.

Both cases are handled by backward-compatible code:
- `resolveInjectionConfig()` falls back to legacy `Inject`/`HeaderName`/`HeaderTemplate`
  when `AuthMethodID` is empty
- `GetCredentials()` detects legacy format and returns `("api_key", {"value": val})`
- Injectors fall back to reading `creds["value"]` when `creds["token"]` is absent

### API Backward Compatibility

- `POST /api/v1/services` with `credential` (string) still works
- `POST /api/v1/services` with `credentials` (map) is the new path
- If both are provided, `credentials` takes precedence
- `GET /api/v1/services` returns `auth_method: null` for legacy services
- `GET /api/v1/templates` returns the new `ServiceTemplate` format; the frontend
  must be updated to handle it (WP-MA-5)

### Template Format Change

The `GET /api/v1/templates` response shape changes from:
```json
{"templates": [{"name": "github", "type": "http_proxy", ...}]}
```
To:
```json
{"templates": [{"id": "github", "display_name": "GitHub", "auth_methods": [...], ...}]}
```

This is a breaking change for the frontend. WP-MA-5 must be deployed alongside
or after WP-MA-4. If the frontend and backend are deployed independently, the
frontend should handle both formats during the transition.

---

## Testing Strategy

### Unit Tests (per work package)

Each work package lists its minimum test requirements. Follow TDD: write tests
first, then implement.

### Integration Tests

After all Phase 1 work packages are complete:

1. **Full create flow**: Create a service with each built-in template's first
   auth method. Verify credential storage and proxy injection.

2. **Legacy compatibility**: Create a service using the legacy API format.
   Verify it works identically to before.

3. **Multi-field credential**: Create a service with Basic Auth. Verify both
   fields are stored and the proxy sends correct Authorization header.

4. **Credential rotation**: Rotate multi-field credentials. Verify old
   credentials are fully replaced.

5. **Template listing**: GET /api/v1/templates returns all templates with
   auth methods and correct field definitions.

### Coverage Target

- 80% line coverage for new code
- 100% coverage for injector implementations (security-critical)
- All existing tests pass unchanged

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Template format change breaks frontend | Medium | High | Deploy frontend update (WP-MA-5/6) with or immediately after backend (WP-MA-4) |
| Legacy credential fallback has edge cases | Low | Medium | Comprehensive backward compat tests in WP-MA-2 |
| Injector dispatch adds latency | Very Low | Low | Interface dispatch is ~1ns; benchmark to confirm |
| Phase 2 strategies require interface changes | Low | Medium | Phase 2 injectors receive `*http.Request` which gives full access; interface should be sufficient |
| Custom template auth method references non-existent strategy | Low | Low | Validate injection type against registry at service creation time |
