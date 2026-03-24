# Design Package: Multi-Auth-Method Support

**Date**: 2026-03-23
**Author**: Architect Agent
**Status**: Proposed

## Summary

Extend Straylight-AI service templates to support multiple authentication methods
per service. Currently every service only accepts a single "API Key" paste field.
Real services support multiple authentication methods (PAT, OAuth, service
account, multi-field credentials). This design introduces a data-driven auth
method model so that templates declaratively define their supported auth methods,
the UI dynamically renders the correct credential form, and the proxy injects
credentials according to the chosen method's injection strategy.

## Key Decisions

| Decision | ADR | Choice |
|----------|-----|--------|
| Auth method data model | ADR-007 | Data-driven `AuthMethod` struct embedded in templates |
| Credential storage evolution | ADR-008 | Multi-field vault storage with `auth_method` discriminator |
| Injection strategy dispatch | ADR-009 | Strategy pattern with `InjectionStrategy` interface |

## Scope

**In scope (Phase 1)**:
- Auth method schema for templates (Go structs, TypeScript types)
- Multi-field credential entry UI
- Vault storage supporting multiple credential fields per auth method
- Injection strategies: bearer header, custom header, multi-header, query param
- Updated API contracts for create/update service
- Backward compatibility with existing single-key services

**In scope (Phase 2)**:
- GitHub App JWT generation (App ID + Installation ID + PEM)
- Google service account JSON parsing and JWT signing
- AWS Signature v4 signing

**Out of scope**:
- New OAuth providers (existing OAuth flow is untouched)
- Service-specific API wrappers
- Credential validation against upstream APIs

## Success Metrics

- All existing tests pass without modification (backward compatibility)
- New services can be created with any defined auth method
- Adding a new auth method to a template requires zero code changes (data only)
- UI renders dynamic credential forms based on template auth method definitions
- Proxy correctly injects credentials for all Phase 1 injection strategies

## Design Artifacts

```
docs/design-multi-auth/
  README.md                          # This file
  adr/
    ADR-007-auth-method-model.md     # Auth method data model design
    ADR-008-credential-storage.md    # Vault storage evolution
    ADR-009-injection-strategies.md  # Proxy injection dispatch
  diagrams/
    auth-method-flow.md              # Sequence diagrams
    data-model.md                    # Entity relationship diagram
  contracts/
    api-changes.yaml                 # OpenAPI delta for multi-auth
  schemas/
    auth-method-schema.go            # Go struct definitions
    auth-method-schema.ts            # TypeScript type definitions
  implementation-guide.md            # Phased build plan
```
