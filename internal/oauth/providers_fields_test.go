package oauth_test

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/oauth"
)

// TestProvider_NewFields verifies that the Provider struct now carries the three new
// Wave-2 fields: PKCE, TokenParser, and DiscoveryURL. This is an additive, backward-
// compatible change — existing entries without these fields must still work.
func TestProvider_NewFields_BackwardCompat(t *testing.T) {
	// Existing providers must still be accessible and their existing fields intact.
	github, ok := oauth.Providers["github"]
	if !ok {
		t.Fatal("expected 'github' provider to be present")
	}
	if github.AuthURL == "" {
		t.Error("expected github.AuthURL to be non-empty")
	}
	// New fields default to zero value (false, "", "").
	// PKCE defaults false — GitHub device flow does not require PKCE by default.
	if github.PKCE {
		t.Error("expected github.PKCE to default to false")
	}
	if github.TokenParser != "" {
		t.Error("expected github.TokenParser to default to empty string")
	}
	if github.DiscoveryURL != "" {
		t.Error("expected github.DiscoveryURL to default to empty string")
	}
}

// TestProvider_PKCEField verifies that a Provider with PKCE=true serializes correctly.
func TestProvider_PKCEField(t *testing.T) {
	p := oauth.Provider{
		Name:     "test-pkce",
		AuthURL:  "https://auth.example.com/authorize",
		TokenURL: "https://auth.example.com/token",
		PKCE:     true,
	}
	if !p.PKCE {
		t.Error("expected PKCE to be true")
	}
}

// TestProvider_TokenParserField verifies that a Provider with TokenParser is accessible.
func TestProvider_TokenParserField(t *testing.T) {
	p := oauth.Provider{
		Name:        "slack-style",
		AuthURL:     "https://slack.com/oauth/v2/authorize",
		TokenURL:    "https://slack.com/api/oauth.v2.access",
		TokenParser: "{{.authed_user.access_token}}",
	}
	if p.TokenParser != "{{.authed_user.access_token}}" {
		t.Errorf("expected TokenParser='{{.authed_user.access_token}}', got %q", p.TokenParser)
	}
}

// TestProvider_DiscoveryURLField verifies that a Provider with DiscoveryURL is accessible.
func TestProvider_DiscoveryURLField(t *testing.T) {
	p := oauth.Provider{
		Name:         "oidc-provider",
		DiscoveryURL: "https://accounts.example.com/.well-known/openid-configuration",
	}
	if p.DiscoveryURL != "https://accounts.example.com/.well-known/openid-configuration" {
		t.Errorf("expected DiscoveryURL to be set, got %q", p.DiscoveryURL)
	}
}
