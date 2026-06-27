// Package tokenexchange implements a generic RFC 8693-shaped token-exchange
// engine: an identity-proof source (OpenBao identity token / SPIRE SVID / CI
// OIDC) is exchanged, via a per-provider adapter, for short-lived downstream
// credentials, which are cached with proactive pre-expiry refresh.
//
// Every minted credential is fresh and audience-scoped. The engine has no API
// to relay an inbound token (MCP no-passthrough by construction).
package tokenexchange

import (
	"context"
	"time"
)

// IdentityProof is a signed assertion of the broker's workload identity,
// suitable as the subject_token of an RFC 8693 exchange. It is never persisted
// to a path reachable by AI tools.
type IdentityProof struct {
	// Token is the signed JWT / SVID (the RFC 8693 subject_token).
	Token string
	// TokenType is the RFC 8693 subject_token_type.
	TokenType string
	// Issuer is the trust-root issuer URL (for audit / diagnostics).
	Issuer string
	// ExpiresAt bounds reuse of the proof itself.
	ExpiresAt time.Time
}

// IdentityRequest parameterizes a request for an identity proof.
type IdentityRequest struct {
	// Audience is the intended consumer of the proof, per-exchange. Required.
	Audience string
	// SessionID, when non-empty, requests a session-scoped proof (Wave-1
	// sources ignore it — deployment-scoped, Decision C1).
	SessionID string
	// Claims are optional extra claims a session-scoped source may embed.
	Claims map[string]string
}

// IdentitySource produces a fresh IdentityProof for a given audience.
// It is the pluggable trust root: OpenBao issuer (default), SPIRE Workload
// API (fleets), or CI OIDC.
type IdentitySource interface {
	// Identity returns a freshly-minted, audience-scoped identity proof.
	Identity(ctx context.Context, req IdentityRequest) (*IdentityProof, error)
	// SourceType identifies the source: "openbao", "spire", or "ci-oidc".
	SourceType() string
}

// ExchangeInput is the provider-agnostic input to an exchange.
type ExchangeInput struct {
	// Proof is the identity assertion to exchange. Set by the Engine before
	// calling the adapter.
	Proof *IdentityProof
	// Audience is the downstream audience/resource (RFC 8707). Must be
	// non-empty; the Engine refuses empty audiences (MCP no-passthrough).
	Audience string
	// Params carries provider-specific parameters (role ARN, WIF pool, etc.).
	Params map[string]string
	// RequestedTTL is the desired credential lifetime.
	RequestedTTL time.Duration
}

// ExchangedCredential is the short-lived downstream credential.
type ExchangedCredential struct {
	// EnvVars is the injectable representation (AWS_*, CLOUDSDK_*, AZURE_*),
	// or a single bearer token under "token" for HTTP/GitHub use.
	EnvVars map[string]string
	// ExpiresAt is when the credential becomes invalid.
	ExpiresAt time.Time
	// Audience echoes the scoping audience for audit (proves no passthrough).
	Audience string
	// Scope is a human-readable audit description (no secret material).
	Scope string
}

// ExchangeAdapter performs one provider's RFC 8693 exchange:
// identity proof -> short-lived provider credential.
// One implementation per provider.
type ExchangeAdapter interface {
	// Exchange calls the provider's STS/token endpoint with the identity proof
	// and returns short-lived credentials.
	Exchange(ctx context.Context, in ExchangeInput) (*ExchangedCredential, error)
	// ProviderType identifies the adapter: "aws", "gcp", "azure", etc.
	ProviderType() string
}
