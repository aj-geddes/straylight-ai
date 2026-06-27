package tokenexchange

import (
	"context"
	"fmt"
	"time"
)

// TokenGenerator is the narrow interface for minting an OpenBao identity token.
// vault.Client satisfies this interface via its GenerateIdentityToken method,
// keeping the tokenexchange package free of a direct dependency on internal/vault.
type TokenGenerator interface {
	// GenerateIdentityToken mints a signed identity token for the given role
	// and audience. It returns the raw JWT and its expiry time.
	GenerateIdentityToken(role, audience string) (string, time.Time, error)
}

// OpenBaoIdentitySource implements IdentitySource using OpenBao's identity-token
// issuer (ADR-012 Decision B1). It is the default trust root for Wave 1.
//
// The identity token is minted in-process and scoped to the requested audience.
// It is never persisted to a vault path reachable by AI tools.
type OpenBaoIdentitySource struct {
	role string
	gen  TokenGenerator
}

// NewOpenBaoIdentitySource creates an OpenBaoIdentitySource that mints tokens
// for the named OpenBao identity role using the provided TokenGenerator.
func NewOpenBaoIdentitySource(role string, gen TokenGenerator) *OpenBaoIdentitySource {
	return &OpenBaoIdentitySource{role: role, gen: gen}
}

// SourceType implements IdentitySource.
func (s *OpenBaoIdentitySource) SourceType() string { return "openbao" }

// Identity implements IdentitySource. It mints a fresh, audience-scoped identity
// token from OpenBao and returns it as an IdentityProof. The token is never
// cached here; the Engine caches the resulting ExchangedCredential instead.
func (s *OpenBaoIdentitySource) Identity(_ context.Context, req IdentityRequest) (*IdentityProof, error) {
	token, expiresAt, err := s.gen.GenerateIdentityToken(s.role, req.Audience)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: openbao identity source: %w", err)
	}
	return &IdentityProof{
		Token:     token,
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		ExpiresAt: expiresAt,
	}, nil
}
