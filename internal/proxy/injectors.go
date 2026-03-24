package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/straylight-ai/straylight/internal/services"
)

// primaryTokenField returns the value of the "token" field if present,
// falling back to "value" for legacy compatibility.
// Returns ("", false) if neither field is present.
func primaryTokenField(fields map[string]string) (string, bool) {
	if v, ok := fields["token"]; ok {
		return v, true
	}
	if v, ok := fields["value"]; ok {
		return v, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// BearerHeaderInjector
// ---------------------------------------------------------------------------

// BearerHeaderInjector sets the Authorization header to "Bearer {token}".
// It reads the credential from the "token" field, falling back to "value"
// for backward compatibility with legacy single-field credentials.
type BearerHeaderInjector struct{}

// Inject sets Authorization: Bearer {token} on req.
func (b *BearerHeaderInjector) Inject(req *http.Request, fields map[string]string, _ services.InjectionConfig) error {
	token, ok := primaryTokenField(fields)
	if !ok {
		return fmt.Errorf("bearer_header: credential fields must contain 'token' or 'value'")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// ---------------------------------------------------------------------------
// CustomHeaderInjector
// ---------------------------------------------------------------------------

// CustomHeaderInjector sets a named HTTP header to the rendered credential value.
// The header name comes from config.HeaderName (defaults to "Authorization").
// If config.HeaderTemplate is set, the template is rendered with {{.Secret}} replaced
// by the credential; otherwise the raw credential value is used.
type CustomHeaderInjector struct{}

// Inject sets the configured header on req.
func (c *CustomHeaderInjector) Inject(req *http.Request, fields map[string]string, config services.InjectionConfig) error {
	token, ok := primaryTokenField(fields)
	if !ok {
		return fmt.Errorf("custom_header: credential fields must contain 'token' or 'value'")
	}

	rendered, err := renderTemplate(config.HeaderTemplate, token)
	if err != nil {
		return fmt.Errorf("custom_header: render header template: %w", err)
	}
	// When no template is set, renderTemplate returns the template string unchanged.
	// For an empty template, use the raw token value.
	if config.HeaderTemplate == "" {
		rendered = token
	}

	headerName := config.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	req.Header.Set(headerName, rendered)
	return nil
}

// ---------------------------------------------------------------------------
// MultiHeaderInjector
// ---------------------------------------------------------------------------

// MultiHeaderInjector sets multiple HTTP headers from multiple credential fields.
// config.Headers maps credential field keys to header names, e.g.:
//
//	{"access_key_id": "X-Access-Key", "secret": "X-Secret"}
//
// All mapped credential fields must be present in fields.
type MultiHeaderInjector struct{}

// Inject sets one header per entry in config.Headers.
func (m *MultiHeaderInjector) Inject(req *http.Request, fields map[string]string, config services.InjectionConfig) error {
	for fieldKey, headerName := range config.Headers {
		val, ok := fields[fieldKey]
		if !ok {
			return fmt.Errorf("multi_header: missing credential field %q", fieldKey)
		}
		req.Header.Set(headerName, val)
	}
	return nil
}

// ---------------------------------------------------------------------------
// QueryParamInjector
// ---------------------------------------------------------------------------

// QueryParamInjector appends a query parameter carrying the credential value.
// The parameter name comes from config.QueryParam. The credential is read from
// the "token" field, falling back to "value" for legacy compatibility.
type QueryParamInjector struct{}

// Inject adds the configured query parameter to req.URL.
func (q *QueryParamInjector) Inject(req *http.Request, fields map[string]string, config services.InjectionConfig) error {
	token, ok := primaryTokenField(fields)
	if !ok {
		return fmt.Errorf("query_param: credential fields must contain 'token' or 'value'")
	}

	query := req.URL.Query()
	query.Set(config.QueryParam, token)
	req.URL.RawQuery = query.Encode()
	return nil
}

// ---------------------------------------------------------------------------
// BasicAuthInjector
// ---------------------------------------------------------------------------

// BasicAuthInjector sets the Authorization header to the HTTP Basic Auth
// encoding of username:password. It reads credentials from the "username"
// and "password" fields.
type BasicAuthInjector struct{}

// Inject sets Authorization: Basic base64(username:password) on req.
func (b *BasicAuthInjector) Inject(req *http.Request, fields map[string]string, _ services.InjectionConfig) error {
	username, hasUser := fields["username"]
	if !hasUser {
		return fmt.Errorf("basic_auth: credential fields must contain 'username'")
	}

	password, hasPass := fields["password"]
	if !hasPass {
		return fmt.Errorf("basic_auth: credential fields must contain 'password'")
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+encoded)
	return nil
}
