// Package mcpauth implements OAuth 2.1 Resource Server token validation for
// the remote MCP endpoint (ADR-015). It validates access tokens minted by a
// trusted external Authorization Server (the user's IdP). It NEVER mints
// tokens and NEVER relays the validated token downstream (no-passthrough).
//
// Role separation (ADR-015 §B.4): this package is the RS validator — it
// consumes tokens FROM external IdPs. It is disjoint from internal/oidc, which
// is Straylight's own OIDC issuer role (minting tokens TO clouds). Different
// packages, different keys, different audiences, different directions.
package mcpauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// straylightInternalIssuers is the set of issuer URLs that belong to
// Straylight's own workload-identity OIDC role (ADR-012). These MUST NOT
// appear in TrustedIssuers — enforced by the constructor.
var straylightInternalIssuers = []string{
	"https://straylight.internal",
}

// Identity is the validated, no-secret representation of the calling user.
// It is the ONLY thing derived from the inbound token that crosses into the
// request path; the raw token is discarded after validation.
type Identity struct {
	Subject   string   // token `sub`
	Issuer    string   // token `iss` (a trusted AS)
	Audience  string   // token `aud` == our resource URI (verified)
	Email     string   // optional, for audit display
	Scopes    []string // token `scope`/`scp`, for per-user policy
	ExpiresAt time.Time
	Claims    map[string]string // selected, non-sensitive claims for audit
}

// ValidationError is a classified token validation failure.
// Code is one of the constants below. It maps to a WWW-Authenticate
// error= value as defined in RFC 6750 §3.1.
type ValidationError struct {
	Code        string // e.g. "invalid_token", "invalid_algorithm"
	Message     string
	ResourceURI string // the RS resource URI, for WWW-Authenticate
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("mcpauth: %s: %s", e.Code, e.Message)
}

// WWWAuthenticateHeader formats a Bearer WWW-Authenticate header per RFC 6750
// and RFC 9728 §5.1. prmURI is the URL of the Protected Resource Metadata.
func (e *ValidationError) WWWAuthenticateHeader(prmURI string) string {
	// RFC 6750 §3.1 + RFC 9728 §5.1 format:
	// Bearer realm="straylight", resource_metadata="...", error="...", error_description="..."
	return fmt.Sprintf(`Bearer realm="straylight", resource_metadata=%q, error=%q, error_description=%q`,
		prmURI, e.Code, e.Message)
}

// TokenValidator validates a raw bearer token and returns an Identity, or an
// error classified as a *ValidationError for WWW-Authenticate response.
type TokenValidator interface {
	Validate(ctx context.Context, rawToken string) (*Identity, error)
}

// JWKSProvider fetches and caches the AS's public signing keys.
// The fetch MUST route through the egress Guard.CheckHost before dial (SSRF
// defense), mirroring ADR-014's discovery/import fetch discipline.
type JWKSProvider interface {
	KeyFor(ctx context.Context, issuer, kid string) (crypto.PublicKey, error)
}

// SSRFGuard is the subset of egress.Guard used by the SSRF-gated JWKS provider.
// It is defined here as a consumer-declared interface to avoid import cycles.
type SSRFGuard interface {
	IsHostAllowed(ctx context.Context, host string) bool
}

// ValidatorConfig wires a JWT validator.
type ValidatorConfig struct {
	// Resource is our canonical resource URI (expected aud claim, RFC 8707/9068).
	Resource string
	// TrustedIssuers is the set of allowed iss values (the AS list). Must not
	// contain Straylight's own issuer URL (role-disjointness invariant, ADR-015).
	TrustedIssuers []string
	// OwnIssuerURL is Straylight's own OIDC issuer URL at runtime (e.g.
	// "http://localhost:9470"). When non-empty, New() enforces role-disjointness
	// by rejecting any TrustedIssuers entry that equals OwnIssuerURL.
	// This closes the gap left by the legacy sentinel-only check: the runtime
	// issuer is port-specific and not covered by "https://straylight.internal".
	OwnIssuerURL string
	// JWKSProvider fetches+caches AS signing keys (SSRF-gated).
	JWKSProvider JWKSProvider
	// AllowedAlgs restricts which signing algorithms are accepted.
	// "none" and symmetric algorithms (HS*) are never permitted regardless of this list.
	AllowedAlgs []string
	// ClockSkew is a small leeway for exp/nbf verification.
	ClockSkew time.Duration
}

// validator is the concrete TokenValidator implementation.
type validator struct {
	cfg ValidatorConfig
}

// New constructs a TokenValidator from cfg, validating invariants at construction
// time (fail-early, not fail-on-first-call).
func New(cfg ValidatorConfig) (TokenValidator, error) {
	if cfg.Resource == "" {
		return nil, fmt.Errorf("mcpauth: Resource must not be empty")
	}
	if len(cfg.TrustedIssuers) == 0 {
		return nil, fmt.Errorf("mcpauth: TrustedIssuers must not be empty")
	}
	if cfg.JWKSProvider == nil {
		return nil, fmt.Errorf("mcpauth: JWKSProvider must not be nil")
	}
	for _, iss := range cfg.TrustedIssuers {
		if iss == "*" {
			return nil, fmt.Errorf("mcpauth: wildcard issuer '*' is not permitted")
		}
		if isStraylightIssuer(iss) {
			return nil, fmt.Errorf("mcpauth: TrustedIssuers must not contain Straylight's own issuer %q "+
				"(ADR-015 role-disjointness: the RS role validates external IdP tokens; "+
				"the issuer role mints workload-identity tokens to clouds — disjoint)", iss)
		}
		if cfg.OwnIssuerURL != "" && iss == cfg.OwnIssuerURL {
			return nil, fmt.Errorf("mcpauth: TrustedIssuers must not contain Straylight's own runtime issuer %q "+
				"(ADR-015 role-disjointness: OwnIssuerURL must not appear in TrustedIssuers)", iss)
		}
	}
	for _, alg := range cfg.AllowedAlgs {
		if err := validateAlg(alg); err != nil {
			return nil, err
		}
	}
	return &validator{cfg: cfg}, nil
}

// Validate verifies rawToken and returns the caller's Identity.
// Validation order (fail-closed on any failure):
//  1. Parse and check structure (three base64url segments).
//  2. Reject alg:none and symmetric algs.
//  3. Check issuer in TrustedIssuers.
//  4. Fetch the AS public key by kid via JWKSProvider.
//  5. Verify signature.
//  6. Check audience == Resource.
//  7. Check exp/nbf within ClockSkew.
func (v *validator) Validate(ctx context.Context, rawToken string) (*Identity, error) {
	if rawToken == "" {
		return nil, &ValidationError{Code: "malformed_token", Message: "empty token"}
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, &ValidationError{Code: "malformed_token",
			Message: fmt.Sprintf("expected 3 JWT segments, got %d", len(parts))}
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &ValidationError{Code: "malformed_token", Message: "invalid header encoding"}
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, &ValidationError{Code: "malformed_token", Message: "invalid header JSON"}
	}

	// Reject forbidden algorithms (alg:none and symmetric).
	if err := validateAlg(header.Alg); err != nil {
		return nil, &ValidationError{Code: "invalid_algorithm", Message: err.Error()}
	}
	// Must be in our AllowedAlgs list.
	if len(v.cfg.AllowedAlgs) > 0 && !containsAlg(v.cfg.AllowedAlgs, header.Alg) {
		return nil, &ValidationError{Code: "invalid_algorithm",
			Message: fmt.Sprintf("algorithm %q not in allowed list", header.Alg)}
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &ValidationError{Code: "malformed_token", Message: "invalid claims encoding"}
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, &ValidationError{Code: "malformed_token", Message: "invalid claims JSON"}
	}

	// Issuer check — before key fetch (cheap filter).
	if !v.isTrustedIssuer(claims.Iss) {
		return nil, &ValidationError{Code: "invalid_issuer",
			Message: fmt.Sprintf("issuer %q is not trusted", claims.Iss)}
	}

	// Fetch the signing key by kid (SSRF-gated via JWKSProvider).
	pubKey, err := v.cfg.JWKSProvider.KeyFor(ctx, claims.Iss, header.Kid)
	if err != nil {
		if ve, ok := err.(*ValidationError); ok {
			return nil, ve
		}
		return nil, &ValidationError{Code: "invalid_signature",
			Message: "could not retrieve signing key: " + err.Error()}
	}

	// Verify signature.
	if err := verifySignature(header.Alg, parts[0]+"."+parts[1], parts[2], pubKey); err != nil {
		return nil, &ValidationError{Code: "invalid_signature", Message: err.Error()}
	}

	// Audience check (RFC 8707/9068 resource indicator — the confused-deputy linchpin).
	if !claims.hasAudience(v.cfg.Resource) {
		return nil, &ValidationError{Code: "invalid_audience",
			Message: fmt.Sprintf("token audience does not include resource %q", v.cfg.Resource)}
	}

	// Expiry and not-before check.
	// RFC 9068 §2.2 requires exp; reject tokens that omit it (eternal-token vulnerability).
	if claims.Exp == 0 {
		return nil, &ValidationError{Code: "invalid_token",
			Message: "token missing required exp claim (RFC 9068)"}
	}
	now := time.Now()
	skew := v.cfg.ClockSkew
	if claims.Exp != 0 {
		expTime := time.Unix(claims.Exp, 0)
		if now.After(expTime.Add(skew)) {
			return nil, &ValidationError{Code: "token_expired",
				Message: fmt.Sprintf("token expired at %s", expTime.UTC())}
		}
	}
	if claims.Nbf != 0 {
		nbfTime := time.Unix(claims.Nbf, 0)
		if now.Before(nbfTime.Add(-skew)) {
			return nil, &ValidationError{Code: "token_not_yet_valid",
				Message: fmt.Sprintf("token not valid before %s", nbfTime.UTC())}
		}
	}

	// Build Identity — the raw token is discarded here and never stored.
	id := &Identity{
		Subject:   claims.Sub,
		Issuer:    claims.Iss,
		Audience:  v.cfg.Resource,
		Email:     claims.Email,
		Scopes:    parseScopes(claims.Scope, claims.Scp),
		ExpiresAt: time.Unix(claims.Exp, 0),
		Claims:    selectClaims(claims),
	}
	return id, nil
}

// isTrustedIssuer reports whether iss is in the configured TrustedIssuers set.
func (v *validator) isTrustedIssuer(iss string) bool {
	for _, trusted := range v.cfg.TrustedIssuers {
		if trusted == iss {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss   string      `json:"iss"`
	Sub   string      `json:"sub"`
	Aud   interface{} `json:"aud"` // string or []string per RFC 7519
	Exp   int64       `json:"exp"`
	Iat   int64       `json:"iat"`
	Nbf   int64       `json:"nbf"`
	Email string      `json:"email"`
	Scope string      `json:"scope"`
	Scp   []string    `json:"scp"`
}

func (c jwtClaims) hasAudience(want string) bool {
	switch v := c.Aud.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// supportedAlgs is the set of algorithms implemented by verifySignature.
// Rejected at construction so operators see a clear error, not an opaque
// signature failure at token-validation time.
var supportedAlgs = map[string]bool{
	"RS256": true,
}

// validateAlg returns an error if alg is "none", a symmetric HS* alg, empty,
// or an asymmetric algorithm that is not yet implemented.
func validateAlg(alg string) error {
	if alg == "" {
		return fmt.Errorf("algorithm must not be empty")
	}
	if strings.EqualFold(alg, "none") {
		return fmt.Errorf("algorithm 'none' is not permitted")
	}
	if strings.HasPrefix(strings.ToUpper(alg), "HS") {
		return fmt.Errorf("symmetric algorithm %q is not permitted (no shared secret with IdP)", alg)
	}
	if !supportedAlgs[alg] {
		return fmt.Errorf("algorithm %q not yet supported; supported: RS256", alg)
	}
	return nil
}

// containsAlg reports whether alg is in the list (case-sensitive).
func containsAlg(list []string, alg string) bool {
	for _, a := range list {
		if a == alg {
			return true
		}
	}
	return false
}

// verifySignature verifies the detached JWS signature over signingInput.
// Only RS256 is currently implemented; ES256 support would go here too.
func verifySignature(alg, signingInput, sigB64 string, pubKey crypto.PublicKey) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	switch alg {
	case "RS256":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RS256 requires an RSA public key, got %T", pubKey)
		}
		h := sha256.New()
		h.Write([]byte(signingInput))
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h.Sum(nil), sig)
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// parseScopes returns scopes from either a space-separated scope string or
// an scp array. It merges both if present (IdP-specific).
func parseScopes(scope string, scp []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range strings.Fields(scope) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range scp {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// selectClaims extracts a small, non-sensitive set of claims for audit attribution.
// It NEVER includes the raw token, secrets, or PII beyond what's already in Identity.
func selectClaims(c jwtClaims) map[string]string {
	m := make(map[string]string)
	if c.Iss != "" {
		m["iss"] = c.Iss
	}
	if c.Sub != "" {
		m["sub"] = c.Sub
	}
	return m
}

// isStraylightIssuer reports whether iss is one of Straylight's own issuer URLs.
func isStraylightIssuer(iss string) bool {
	for _, internal := range straylightInternalIssuers {
		if iss == internal {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SSRF-gated JWKS provider
// ---------------------------------------------------------------------------

// ssrfGatedJWKSProvider is a JWKSProvider that uses an SSRFGuard to block
// fetches to private/link-local hosts before dialing. In Phase 1 (no network
// fetch), it uses an injected key store for test scenarios. The network-fetch
// path is wired in serve() with egress.Guard.
type ssrfGatedJWKSProvider struct {
	guard    SSRFGuard
	keyStore map[string]map[string]crypto.PublicKey // issuer -> kid -> key
}

// NewSSRFGatedJWKSProvider constructs a JWKSProvider that checks the issuer URL
// host against guard before any network fetch. keyStore pre-seeds keys for testing.
func NewSSRFGatedJWKSProvider(guard SSRFGuard, keyStore map[string]map[string]crypto.PublicKey) JWKSProvider {
	return &ssrfGatedJWKSProvider{guard: guard, keyStore: keyStore}
}

func (p *ssrfGatedJWKSProvider) KeyFor(ctx context.Context, issuer, kid string) (crypto.PublicKey, error) {
	// Extract host from issuer URL for SSRF check.
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return nil, &ValidationError{Code: "invalid_signature",
			Message: fmt.Sprintf("malformed issuer URL %q", issuer)}
	}
	host := u.Hostname() // strips port

	if p.guard != nil && !p.guard.IsHostAllowed(ctx, host) {
		return nil, &ValidationError{Code: "invalid_signature",
			Message: fmt.Sprintf("SSRF guard denied JWKS fetch for host %q", host)}
	}

	// Try the in-process key store first.
	if p.keyStore != nil {
		if kids, ok := p.keyStore[issuer]; ok {
			if key, ok := kids[kid]; ok {
				return key, nil
			}
		}
	}

	return nil, &ValidationError{Code: "invalid_signature",
		Message: fmt.Sprintf("no key found for issuer %q kid %q", issuer, kid)}
}
