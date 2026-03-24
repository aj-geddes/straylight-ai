# ADR-008: Credential Storage Evolution

**Date**: 2026-03-23
**Status**: Proposed

## Context

Today the vault stores credentials at `services/{name}/credential` as a single
key-value pair:

```json
{
  "value": "<the-api-key>",
  "type": "api_key"
}
```

With multi-auth-method support, credentials may have multiple fields. For
example, AWS requires `access_key_id` + `secret_access_key` (+ optional
`session_token`). Basic Auth requires `username` + `password`. GitHub App
requires `app_id` + `installation_id` + `private_key`.

The vault storage model must evolve to support arbitrary credential field sets
while remaining backward compatible with the existing single-field format.

### Constraints

- OpenBao KV v2 stores arbitrary `map[string]interface{}` per secret path
- Vault paths are already namespaced per service: `services/{name}/credential`
- The proxy reads credentials via `Registry.GetCredential()` which currently
  returns a single `string`
- OAuth tokens are stored at a separate path: `services/{name}/oauth_tokens`
- Credential values must never appear in the registry, logs, or API responses

## Decision Drivers

- **Backward compatibility**: Existing `{"value": "...", "type": "api_key"}`
  must keep working
- **Simplicity**: Minimal changes to vault read/write paths
- **Multi-field support**: AWS, Basic Auth, GitHub App require 2-3 fields
- **Proxy performance**: Credential lookups should not require multiple vault
  reads

## Options Considered

### Option 1: Store all fields as a flat map at the same path

Store all credential fields as top-level keys in the vault secret at the
existing path `services/{name}/credential`:

```json
{
  "auth_method": "aws_access_key",
  "access_key_id": "AKIA...",
  "secret_access_key": "wJalrX..."
}
```

For backward compatibility, existing secrets with `"value"` and `"type"` keys
are read as legacy format.

**Pros**:
- Same vault path, same number of vault operations
- Simple migration: new writes include `auth_method` discriminator
- Existing secrets work without migration (legacy format detection)
- Single vault read returns all fields

**Cons**:
- Field naming must be coordinated between template and vault (but this is
  the `CredentialField.Key` from the auth method definition)
- Slightly more complex deserialization

### Option 2: Store each field at a separate vault path

Store each credential field at `services/{name}/credential/{field_key}`:

```
services/my-aws/credential/access_key_id -> {"value": "AKIA..."}
services/my-aws/credential/secret_access_key -> {"value": "wJalrX..."}
```

**Pros**:
- Atomic per-field rotation
- Clear separation

**Cons**:
- Multiple vault reads per proxy request (2-3x for AWS)
- More complex write and delete logic
- Vault list operations needed to discover fields
- Significantly more vault traffic

### Option 3: Store as a JSON blob in a single value field

Store the entire credential set as a JSON string in the existing `"value"` key:

```json
{
  "value": "{\"access_key_id\":\"AKIA...\",\"secret_access_key\":\"wJalrX...\"}",
  "type": "aws_access_key"
}
```

**Pros**:
- Backward compatible by default (value is always a string)
- Single vault read

**Cons**:
- Double serialization (JSON inside JSON)
- Loses vault's native key-value semantics
- Vault UI shows an opaque JSON blob instead of discrete fields
- Harder to audit individual fields

## Decision

Chose **Option 1: Flat map at the same path** because:

1. **Single vault read per proxy request**. The proxy already reads one secret
   per request. Multi-field credentials should not multiply vault traffic.

2. **Natural fit for OpenBao KV v2**. Vault secrets are already
   `map[string]interface{}`. Storing fields as top-level keys is idiomatic.

3. **Backward compatibility is trivial**. The discriminator field `auth_method`
   is absent in legacy secrets. When absent, the proxy falls back to reading
   the `"value"` key (existing behavior). No data migration required.

4. **Auditable**. Each credential field is a distinct key in the vault secret,
   visible in vault audit logs and UI.

## Consequences

**Positive**:
- Zero-downtime migration: existing secrets keep working
- No additional vault traffic for multi-field credentials
- Clean audit trail per field
- Natural mapping from `CredentialField.Key` to vault secret key

**Negative**:
- All credential fields for a service are rotated atomically (cannot rotate
  just the secret key without also writing the access key). This is acceptable
  because credential fields are logically coupled.
- The `GetCredential(name string) (string, error)` method signature must change
  to return `map[string]string` for multi-field support. This is a breaking
  internal API change but affects only the proxy package.

**Risks**:
- Field key collisions with metadata keys (`auth_method`, `type`). Mitigation:
  credential field keys are defined in templates; we reserve `auth_method` and
  `type` as metadata prefixes and validate that no template uses them as field keys.

**Tech Debt**:
- The legacy `"value"` + `"type"` format should be migrated to the new format
  when a service's credential is next rotated. No active migration needed.
  Paydown plan: after 6 months, add a startup migration that rewrites legacy
  secrets to the new format.

## Implementation Notes

### Vault Write (new format)

```go
func (r *Registry) writeCredentials(name string, authMethod string, fields map[string]string) error {
    data := make(map[string]interface{}, len(fields)+1)
    data["auth_method"] = authMethod
    for k, v := range fields {
        data[k] = v
    }
    return r.vault.WriteSecret(credentialPath(name), data)
}
```

### Vault Read (backward compatible)

```go
func (r *Registry) GetCredentials(name string) (authMethod string, fields map[string]string, err error) {
    data, err := r.vault.ReadSecret(credentialPath(name))
    if err != nil {
        return "", nil, err
    }

    // New format: has "auth_method" key
    if am, ok := data["auth_method"].(string); ok {
        fields := make(map[string]string)
        for k, v := range data {
            if k == "auth_method" {
                continue
            }
            if s, ok := v.(string); ok {
                fields[k] = s
            }
        }
        return am, fields, nil
    }

    // Legacy format: has "value" key
    if val, ok := data["value"].(string); ok {
        return "api_key", map[string]string{"value": val}, nil
    }

    return "", nil, fmt.Errorf("unrecognized credential format")
}
```

### Reserved metadata keys

The following keys are reserved and must not be used as `CredentialField.Key`:
- `auth_method`
- `type` (legacy)

Template validation must enforce this.

## Validation Criteria

- Existing services with legacy `{"value": "...", "type": "api_key"}` secrets
  continue to work without migration
- New multi-field credentials are stored and retrieved correctly
- Credential rotation replaces all fields atomically
- Vault audit logs show individual field keys (not opaque blobs)
- No credential values appear in registry, logs, or API responses
