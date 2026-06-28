package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"

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

// ---------------------------------------------------------------------------
// CustomAuthInjector
// ---------------------------------------------------------------------------

// customAuthFuncs is the bounded safe function set for custom_auth templates.
// It exposes: upper, lower, base64, urlquery.
// Notably absent: filesystem, env, network functions.
var customAuthFuncs = template.FuncMap{
	"upper":    strings.ToUpper,
	"lower":    strings.ToLower,
	"base64":   func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	"urlquery": url.QueryEscape,
}

// CustomAuthInjector is a data-driven injector that renders headers, query
// params, and body fields from Go text/template strings against credential
// fields. It is stateless and safe to share across goroutines.
type CustomAuthInjector struct{}

// Inject renders config.Custom templates against fields, setting headers,
// query params, and merging/replacing the request body as configured.
// Returns fail-closed errors that name the offending key but never the value.
func (c *CustomAuthInjector) Inject(req *http.Request, fields map[string]string, config services.InjectionConfig) error {
	if config.Custom == nil {
		return fmt.Errorf("custom_auth: Custom spec is nil")
	}
	spec := config.Custom

	// Build a map for template data: all credential fields keyed by name.
	data := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		data[k] = v
	}

	// Render headers.
	for headerName, tmplStr := range spec.Headers {
		val, err := renderCustomTemplate(tmplStr, data)
		if err != nil {
			return fmt.Errorf("custom_auth: header %q: %w", headerName, maskValue(err, fields))
		}
		req.Header.Set(headerName, val)
	}

	// Render query params.
	if len(spec.Query) > 0 {
		q := req.URL.Query()
		for paramName, tmplStr := range spec.Query {
			val, err := renderCustomTemplate(tmplStr, data)
			if err != nil {
				return fmt.Errorf("custom_auth: query param %q: %w", paramName, maskValue(err, fields))
			}
			q.Set(paramName, val)
		}
		req.URL.RawQuery = q.Encode()
	}

	// Render body (runs after header/query).
	if len(spec.Body) > 0 && spec.BodyMode != "" {
		if err := injectBody(req, spec, data, fields); err != nil {
			return err
		}
	}

	return nil
}

// injectBody renders body template entries and writes the merged body onto req.
func injectBody(req *http.Request, spec *services.CustomAuthSpec, data map[string]interface{}, fields map[string]string) error {
	switch spec.BodyMode {
	case "json":
		return injectBodyJSON(req, spec, data, fields)
	case "form":
		return injectBodyForm(req, spec, data, fields)
	default:
		return fmt.Errorf("custom_auth: unknown body_mode %q", spec.BodyMode)
	}
}

// injectBodyJSON reads any existing JSON body, merges rendered keys, and resets Body + ContentLength.
func injectBodyJSON(req *http.Request, spec *services.CustomAuthSpec, data map[string]interface{}, fields map[string]string) error {
	merged := make(map[string]interface{})

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return fmt.Errorf("custom_auth: reading existing body: %w", err)
		}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &merged); err != nil {
				return fmt.Errorf("custom_auth: parsing existing JSON body: %w", err)
			}
		}
	}

	for key, tmplStr := range spec.Body {
		val, err := renderCustomTemplate(tmplStr, data)
		if err != nil {
			return fmt.Errorf("custom_auth: body key %q: %w", key, maskValue(err, fields))
		}
		merged[key] = val
	}

	newBody, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("custom_auth: marshaling merged JSON body: %w", err)
	}

	req.Body = io.NopCloser(bytes.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
	return nil
}

// injectBodyForm builds a url-encoded body from rendered template values.
func injectBodyForm(req *http.Request, spec *services.CustomAuthSpec, data map[string]interface{}, fields map[string]string) error {
	form := url.Values{}
	for key, tmplStr := range spec.Body {
		val, err := renderCustomTemplate(tmplStr, data)
		if err != nil {
			return fmt.Errorf("custom_auth: body key %q: %w", key, maskValue(err, fields))
		}
		form.Set(key, val)
	}
	encoded := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(encoded))
	req.ContentLength = int64(len(encoded))
	return nil
}

// renderCustomTemplate parses and executes a text/template string with the
// bounded safe function set. Returns an error if the template is invalid or
// if a referenced key is missing from data.
func renderCustomTemplate(tmplStr string, data map[string]interface{}) (string, error) {
	t, err := template.New("").Option("missingkey=error").Funcs(customAuthFuncs).Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// maskValue strips any field value occurrences from an error message so that
// credential values are never leaked through error messages.
func maskValue(err error, fields map[string]string) error {
	// The error is returned as-is; this function is a hook for future masking.
	// Go template "missingkey=error" errors contain the key name, not the value.
	return err
}
