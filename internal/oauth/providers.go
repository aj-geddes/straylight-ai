// Package oauth implements the OAuth 2.0 authorization code flow for services
// that use OAuth instead of static API keys.
package oauth

// Provider holds the static configuration for a supported OAuth provider.
type Provider struct {
	// Name is the canonical identifier for this provider (e.g., "github").
	Name string
	// AuthURL is the provider's authorization endpoint.
	AuthURL string
	// TokenURL is the provider's token exchange endpoint.
	TokenURL string
	// DeviceCodeURL is the provider's device authorization endpoint (RFC 8628).
	// When non-empty the provider supports the Device Authorization Flow and
	// users will be shown the DeviceFlowStep UI instead of OAuthSetupStep.
	// Stripe does not support device flow; leave empty for those.
	DeviceCodeURL string
	// DefaultScopes are the OAuth scopes requested by default.
	DefaultScopes []string
	// ExtraAuthParams are additional query parameters appended to the
	// authorization URL. Used for provider-specific requirements such as
	// Google's access_type=offline and prompt=consent.
	ExtraAuthParams map[string]string
	// DefaultClientID is the baked-in OAuth App client_id for the device flow.
	// This is set by the Straylight-AI product registration so users never
	// need to register their own OAuth App for providers that support device flow.
	// Override at runtime with the STRAYLIGHT_GITHUB_CLIENT_ID env var.
	DefaultClientID string
}

// Providers is the registry of supported OAuth providers.
// Tests may temporarily override this variable to inject a fake token server.
var Providers = map[string]Provider{
	"github": {
		Name:          "github",
		AuthURL:       "https://github.com/login/oauth/authorize",
		TokenURL:      "https://github.com/login/oauth/access_token",
		// DeviceCodeURL enables the zero-config Device Authorization Flow (RFC 8628).
		// Users see "Go to github.com/login/device and enter XXXX-XXXX" instead
		// of being asked to register their own OAuth App.
		DeviceCodeURL: "https://github.com/login/device/code",
		DefaultScopes: []string{"repo", "read:org"},
		// DefaultClientID is intentionally left empty until AJ registers the
		// Straylight-AI GitHub OAuth App with Device Flow enabled.
		// Set STRAYLIGHT_GITHUB_CLIENT_ID env var to activate device flow for all users.
		DefaultClientID: "",
	},
	"google": {
		Name:          "google",
		AuthURL:       "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:      "https://oauth2.googleapis.com/token",
		// DeviceCodeURL enables the zero-config Device Authorization Flow (RFC 8628).
		// Note: Google's device code response uses "verification_url" instead of
		// "verification_uri" — the handler normalizes this field name.
		DeviceCodeURL: "https://oauth2.googleapis.com/device/code",
		DefaultScopes: []string{"openid", "email", "profile"},
		// Google requires access_type=offline to receive a refresh token and
		// prompt=consent to force the consent screen on every authorization,
		// ensuring a fresh refresh token is issued.
		ExtraAuthParams: map[string]string{
			"access_type": "offline",
			"prompt":      "consent",
		},
	},
	"microsoft": {
		Name:     "microsoft",
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		// DeviceCodeURL enables the zero-config Device Authorization Flow (RFC 8628).
		// Uses /common/ tenant for multi-tenant support.
		DeviceCodeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
		DefaultScopes: []string{"openid", "email", "profile", "User.Read"},
	},
	"stripe": {
		Name:          "stripe",
		AuthURL:       "https://connect.stripe.com/oauth/authorize",
		TokenURL:      "https://connect.stripe.com/oauth/token",
		DefaultScopes: []string{"read_write"},
	},
	"facebook": {
		Name:          "facebook",
		AuthURL:       "https://www.facebook.com/v19.0/dialog/oauth",
		TokenURL:      "https://graph.facebook.com/v19.0/oauth/access_token",
		DefaultScopes: []string{"email", "public_profile"},
	},
}
