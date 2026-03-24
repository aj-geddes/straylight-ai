// Package proxy implements the HTTP reverse proxy with credential injection.
// It intercepts outbound HTTP requests from AI agents, injects the appropriate
// credentials retrieved from the vault, and forwards the request to the target service.
//
// Credential lookups are cached for a configurable TTL (default 60 seconds)
// to reduce vault round-trips. Cache entries are invalidated when a service is
// updated or deleted via InvalidateCache.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/straylight-ai/straylight/internal/services"
)

// defaultCredentialTTL is how long a cached credential is considered fresh.
const defaultCredentialTTL = 60 * time.Second

// defaultTimeout is the per-request upstream timeout when the caller's context
// has no deadline of its own.
const defaultTimeout = 30 * time.Second

// ServiceResolver abstracts the service registry for the proxy package so that
// the proxy does not depend directly on the services package implementation.
type ServiceResolver interface {
	Get(name string) (services.Service, error)
	// GetCredential returns a single credential string (legacy path).
	GetCredential(name string) (string, error)
	// ReadCredentials returns the auth method ID and all credential fields
	// for multi-field authentication (new path).
	ReadCredentials(name string) (authMethod string, fields map[string]string, err error)
}

// Sanitizer is an optional post-processing step that redacts credentials and
// other sensitive patterns from upstream response bodies before they are
// returned to the caller.
type Sanitizer interface {
	Sanitize(input string) string
}

// APICallRequest is the input to HandleAPICall, corresponding to a
// straylight_api_call MCP tool invocation.
type APICallRequest struct {
	Service string            `json:"service"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Query   map[string]string `json:"query,omitempty"`
	Body    interface{}       `json:"body,omitempty"`
}

// APICallResponse carries the upstream HTTP response back to the caller.
// The Body has already been run through the sanitizer (if one was provided).
type APICallResponse struct {
	StatusCode int               `json:"status_code"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// cachedCredential pairs a credential value with the time it was fetched.
// Used for legacy single-value credential caching.
type cachedCredential struct {
	value     string
	fetchedAt time.Time
}

// cachedCredentials pairs multi-field credentials with the time they were fetched.
type cachedCredentials struct {
	authMethod string
	fields     map[string]string
	fetchedAt  time.Time
}

// Proxy is a thread-safe HTTP reverse proxy that resolves service configuration,
// injects credentials, and sanitizes responses.
type Proxy struct {
	resolver  ServiceResolver
	sanitizer Sanitizer
	client    *http.Client
	injectors *InjectorRegistry

	ttl        time.Duration
	cache      sync.Map // key: service name (string) → *cachedCredential (legacy)
	multiCache sync.Map // key: service name (string) → *cachedCredentials (new)
}

// NewProxy creates a Proxy with the default 60-second credential TTL.
// sanitizer may be nil; in that case response bodies are passed through unchanged.
func NewProxy(resolver ServiceResolver, sanitizer Sanitizer) *Proxy {
	return NewProxyWithTTL(resolver, sanitizer, defaultCredentialTTL)
}

// NewProxyWithTTL creates a Proxy with a configurable credential cache TTL.
// A short TTL is useful in tests. sanitizer may be nil.
func NewProxyWithTTL(resolver ServiceResolver, sanitizer Sanitizer, ttl time.Duration) *Proxy {
	return &Proxy{
		resolver:  resolver,
		sanitizer: sanitizer,
		injectors: DefaultInjectorRegistry(),
		ttl:       ttl,
		client: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// InvalidateCache removes the cached credential for the named service so that
// the next request fetches a fresh value from the resolver. Call this whenever
// a service is updated or deleted.
func (p *Proxy) InvalidateCache(name string) {
	p.cache.Delete(name)
	p.multiCache.Delete(name)
}

// SetHTTPClient replaces the proxy's underlying HTTP client. This is intended
// for use in tests where the upstream server uses a self-signed TLS certificate
// (e.g. httptest.NewTLSServer). Pass httptest.Server.Client() to get an
// http.Client pre-configured to trust the test server's certificate.
func (p *Proxy) SetHTTPClient(c *http.Client) {
	p.client = c
}

// HandleAPICall processes one straylight_api_call invocation.
// It resolves the service, fetches (and caches) the credential, builds an
// upstream HTTP request, forwards it, and returns the sanitized response.
//
// When a service has AuthMethodID set, the new injector-registry path is used.
// When AuthMethodID is empty, the legacy injection path is used for backward
// compatibility.
//
// 4xx and 5xx status codes from upstream are passed through without error —
// only network-level failures return a non-nil error.
func (p *Proxy) HandleAPICall(ctx context.Context, req APICallRequest) (*APICallResponse, error) {
	svc, err := p.resolver.Get(req.Service)
	if err != nil {
		return nil, fmt.Errorf("service %q not found", req.Service)
	}

	var upstreamReq *http.Request

	if svc.AuthMethodID != "" {
		// New path: use injector registry with multi-field credentials.
		upstreamReq, err = p.buildUpstreamRequestWithAuth(ctx, req, svc)
	} else {
		// Legacy path: single credential value with flat injection config.
		cred, credErr := p.credential(req.Service)
		if credErr != nil {
			return nil, fmt.Errorf("credential not available for service %q", req.Service)
		}
		upstreamReq, err = p.buildUpstreamRequest(ctx, req, svc, cred)
	}
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(upstreamReq)
	if err != nil {
		return nil, fmt.Errorf("upstream service unreachable: %w", err)
	}
	defer resp.Body.Close()

	return p.buildResponse(resp)
}

// buildUpstreamRequestWithAuth builds the outbound request using the injector
// registry path (for services with AuthMethodID set).
func (p *Proxy) buildUpstreamRequestWithAuth(ctx context.Context, req APICallRequest, svc services.Service) (*http.Request, error) {
	authMethod, fields, err := p.credentials(req.Service)
	if err != nil {
		return nil, fmt.Errorf("credentials not available for service %q", req.Service)
	}

	cfg, err := resolveInjectionConfig(svc, authMethod)
	if err != nil {
		return nil, fmt.Errorf("resolve injection config for service %q: %w", req.Service, err)
	}

	injector, err := p.injectors.Get(string(cfg.Type))
	if err != nil {
		return nil, fmt.Errorf("service %q: unsupported injection type %q", req.Service, cfg.Type)
	}

	targetURL, err := buildTargetURL(svc.Target, req.Path, req.Query)
	if err != nil {
		return nil, fmt.Errorf("build target URL: %w", err)
	}

	bodyReader, err := encodeBody(req.Body)
	if err != nil {
		return nil, fmt.Errorf("encode body: %w", err)
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	upstreamReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}

	applyHeaders(upstreamReq, req.Headers, svc)

	if err := injector.Inject(upstreamReq, fields, cfg); err != nil {
		return nil, fmt.Errorf("inject credential: %w", err)
	}
	return upstreamReq, nil
}

// buildUpstreamRequest constructs the outbound *http.Request from the caller's
// APICallRequest, the resolved service configuration, and the injected credential.
// This is the legacy path used when svc.AuthMethodID is empty.
func (p *Proxy) buildUpstreamRequest(ctx context.Context, req APICallRequest, svc services.Service, cred string) (*http.Request, error) {
	targetURL, err := buildTargetURL(svc.Target, req.Path, req.Query)
	if err != nil {
		return nil, fmt.Errorf("build target URL: %w", err)
	}

	bodyReader, err := encodeBody(req.Body)
	if err != nil {
		return nil, fmt.Errorf("encode body: %w", err)
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	upstreamReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}

	applyHeaders(upstreamReq, req.Headers, svc)

	if err := injectCredential(upstreamReq, svc, cred); err != nil {
		return nil, fmt.Errorf("inject credential: %w", err)
	}
	return upstreamReq, nil
}

// applyHeaders sets caller-supplied and service default headers on the request.
// Headers are applied in priority order:
//  1. Caller-supplied headers (lowest — auth header is silently dropped).
//  2. Service DefaultHeaders (override caller headers).
//
// The credential injection step that follows sets the auth header at the
// highest priority, so it is not applied here.
func applyHeaders(req *http.Request, callerHeaders map[string]string, svc services.Service) {
	authHeaderName := canonicalAuthHeader(svc)
	for k, v := range callerHeaders {
		if http.CanonicalHeaderKey(k) == authHeaderName {
			continue // callers must not override injected auth
		}
		req.Header.Set(k, v)
	}
	for k, v := range svc.DefaultHeaders {
		req.Header.Set(k, v)
	}
}

// buildResponse reads the upstream response body, sanitizes it, and assembles
// an APICallResponse.
func (p *Proxy) buildResponse(resp *http.Response) (*APICallResponse, error) {
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read upstream response body: %w", err)
	}

	body := string(rawBody)
	if p.sanitizer != nil {
		body = p.sanitizer.Sanitize(body)
	}

	respHeaders := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}

	return &APICallResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    respHeaders,
	}, nil
}

// ---------------------------------------------------------------------------
// Credential helpers
// ---------------------------------------------------------------------------

// credential returns a cached single credential value if still fresh, otherwise
// fetches a new one from the resolver and caches it. Used by the legacy path.
func (p *Proxy) credential(serviceName string) (string, error) {
	now := time.Now()

	if v, ok := p.cache.Load(serviceName); ok {
		entry := v.(*cachedCredential)
		if now.Sub(entry.fetchedAt) < p.ttl {
			return entry.value, nil
		}
		// Entry is stale — fall through to refresh.
	}

	val, err := p.resolver.GetCredential(serviceName)
	if err != nil {
		return "", err
	}

	p.cache.Store(serviceName, &cachedCredential{
		value:     val,
		fetchedAt: now,
	})
	return val, nil
}

// credentials returns cached multi-field credentials if still fresh, otherwise
// fetches from the resolver and caches them. Used by the new injector path.
func (p *Proxy) credentials(serviceName string) (string, map[string]string, error) {
	now := time.Now()

	if v, ok := p.multiCache.Load(serviceName); ok {
		entry := v.(*cachedCredentials)
		if now.Sub(entry.fetchedAt) < p.ttl {
			return entry.authMethod, entry.fields, nil
		}
		// Entry is stale — fall through to refresh.
	}

	authMethod, fields, err := p.resolver.ReadCredentials(serviceName)
	if err != nil {
		return "", nil, err
	}

	p.multiCache.Store(serviceName, &cachedCredentials{
		authMethod: authMethod,
		fields:     fields,
		fetchedAt:  now,
	})
	return authMethod, fields, nil
}

// ---------------------------------------------------------------------------
// Injection config resolution
// ---------------------------------------------------------------------------

// resolveInjectionConfig determines the InjectionConfig to use for a service.
//
// When the authMethod from the vault matches an auth method registered in
// services.ServiceTemplates, that auth method's injection config is returned.
//
// When the authMethod is "legacy" (from ReadCredentials backward-compat fallback),
// the config is derived from the service's flat Inject/HeaderName/HeaderTemplate fields.
func resolveInjectionConfig(svc services.Service, authMethod string) (services.InjectionConfig, error) {
	if authMethod != "" && authMethod != "legacy" {
		// Search ServiceTemplates for an auth method with this ID.
		for _, tmpl := range services.ServiceTemplates {
			for _, am := range tmpl.AuthMethods {
				if am.ID == authMethod {
					return am.Injection, nil
				}
			}
		}
		return services.InjectionConfig{}, fmt.Errorf("auth method %q not found in any service template", authMethod)
	}

	// Legacy fallback: derive injection config from flat Service fields.
	return legacyInjectionConfig(svc), nil
}

// legacyInjectionConfig converts the flat Service injection fields into an
// InjectionConfig for backward compatibility with services that predate the
// multi-auth-method support.
func legacyInjectionConfig(svc services.Service) services.InjectionConfig {
	switch svc.Inject {
	case "header":
		return services.InjectionConfig{
			Type:           services.InjectionCustomHeader,
			HeaderName:     svc.HeaderName,
			HeaderTemplate: svc.HeaderTemplate,
		}
	case "query":
		return services.InjectionConfig{
			Type:       services.InjectionQueryParam,
			QueryParam: svc.QueryParam,
		}
	default:
		return services.InjectionConfig{Type: services.InjectionBearerHeader}
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// buildTargetURL combines the service base URL, path, and caller-supplied
// query parameters into a complete URL string.
func buildTargetURL(base, path string, query map[string]string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse service target %q: %w", base, err)
	}
	// Append path (trim trailing slash from base to avoid double slashes).
	u.Path = strings.TrimRight(u.Path, "/") + path

	if len(query) > 0 {
		q := u.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// encodeBody serialises the request body to an io.Reader.
// Strings are used as-is; objects are JSON-encoded; nil produces no body.
func encodeBody(body interface{}) (io.Reader, error) {
	if body == nil {
		return nil, nil
	}
	switch v := body.(type) {
	case string:
		return strings.NewReader(v), nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	}
}

// canonicalAuthHeader returns the canonical form of the header that will carry
// the injected credential, so we can prevent callers from overriding it.
func canonicalAuthHeader(svc services.Service) string {
	if svc.Inject == "header" {
		name := svc.HeaderName
		if name == "" {
			name = "Authorization"
		}
		return http.CanonicalHeaderKey(name)
	}
	return "Authorization" // default guard even for query injection
}

// secretData is the data object passed to HeaderTemplate execution.
type secretData struct {
	Secret string
}

// injectCredential applies the service's credential injection strategy to the
// outbound request (legacy path). For header injection the HeaderTemplate
// (which may contain {{.Secret}}) is expanded and set as the appropriate header.
// For query injection the credential is added as a query parameter.
func injectCredential(req *http.Request, svc services.Service, cred string) error {
	switch svc.Inject {
	case "header":
		rendered, err := renderTemplate(svc.HeaderTemplate, cred)
		if err != nil {
			return fmt.Errorf("render header template: %w", err)
		}
		headerName := svc.HeaderName
		if headerName == "" {
			headerName = "Authorization"
		}
		req.Header.Set(headerName, rendered)
		return nil

	case "query":
		q := req.URL.Query()
		q.Set(svc.QueryParam, cred)
		req.URL.RawQuery = q.Encode()
		return nil

	default:
		return fmt.Errorf("unsupported inject mode %q", svc.Inject)
	}
}

// renderTemplate executes a Go text/template string with {{.secret}} (case-
// insensitive match via the field name Secret) replaced by the credential.
// If the template string contains no actions it is returned unchanged.
func renderTemplate(tmplStr, secret string) (string, error) {
	// Fast path: no template actions.
	if !strings.Contains(tmplStr, "{{") {
		return tmplStr, nil
	}

	// Support both {{.secret}} and {{.Secret}} by normalising to .Secret.
	tmplStr = strings.ReplaceAll(tmplStr, "{{.secret}}", "{{.Secret}}")

	tmpl, err := template.New("").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, secretData{Secret: secret}); err != nil {
		return "", err
	}
	return buf.String(), nil
}
