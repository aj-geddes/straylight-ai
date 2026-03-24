package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Test helpers / fakes
// ---------------------------------------------------------------------------

// fakeResolver implements proxy.ServiceResolver using an in-memory store.
type fakeResolver struct {
	mu          sync.RWMutex
	svcs        map[string]services.Service
	creds       map[string]string
	credCallLog []string // service names requested
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		svcs:  make(map[string]services.Service),
		creds: make(map[string]string),
	}
}

func (f *fakeResolver) addService(svc services.Service, cred string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.svcs[svc.Name] = svc
	f.creds[svc.Name] = cred
}

func (f *fakeResolver) Get(name string) (services.Service, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	svc, ok := f.svcs[name]
	if !ok {
		return services.Service{}, fmt.Errorf("services: %q not found", name)
	}
	return svc, nil
}

func (f *fakeResolver) GetCredential(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.credCallLog = append(f.credCallLog, name)
	cred, ok := f.creds[name]
	if !ok {
		return "", fmt.Errorf("services: %q not found", name)
	}
	return cred, nil
}

func (f *fakeResolver) ReadCredentials(name string) (string, map[string]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	cred, ok := f.creds[name]
	if !ok {
		return "", nil, fmt.Errorf("services: %q not found", name)
	}
	return "legacy", map[string]string{"value": cred}, nil
}

func (f *fakeResolver) credCallCount(name string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	count := 0
	for _, n := range f.credCallLog {
		if n == name {
			count++
		}
	}
	return count
}

// fakeSanitizer records Sanitize calls and applies a simple replacement.
type fakeSanitizer struct {
	called int32
}

func (s *fakeSanitizer) Sanitize(input string) string {
	atomic.AddInt32(&s.called, 1)
	return strings.ReplaceAll(input, "SECRET", "[REDACTED]")
}

// ---------------------------------------------------------------------------
// Helper: build a test upstream server
// ---------------------------------------------------------------------------

func upstreamEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back request details as JSON so tests can inspect them.
		resp := map[string]interface{}{
			"path":    r.URL.Path,
			"method":  r.Method,
			"headers": r.Header,
			"query":   r.URL.RawQuery,
		}
		body, _ := io.ReadAll(r.Body)
		resp["body"] = string(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewProxy_NonNilResult(t *testing.T) {
	r := newFakeResolver()
	p := proxy.NewProxy(r, nil)
	if p == nil {
		t.Fatal("NewProxy returned nil")
	}
}

// ---------------------------------------------------------------------------
// HandleAPICall — happy path: header injection (Bearer token)
// ---------------------------------------------------------------------------

func TestHandleAPICall_HeaderInjection_Bearer(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "stripe",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "sk-test-token")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "stripe",
		Method:  "GET",
		Path:    "/v1/balance",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Parse the echo response to verify the injected header.
	var echo map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &echo); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	headers, _ := echo["headers"].(map[string]interface{})
	authSlice, _ := headers["Authorization"].([]interface{})
	if len(authSlice) == 0 {
		t.Fatalf("Authorization header not present in upstream request; headers: %v", headers)
	}
	if authSlice[0] != "Bearer sk-test-token" {
		t.Errorf("expected 'Bearer sk-test-token', got %q", authSlice[0])
	}
}

// ---------------------------------------------------------------------------
// HandleAPICall — header injection with default header name "Authorization"
// ---------------------------------------------------------------------------

func TestHandleAPICall_HeaderInjection_DefaultHeaderName(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	// HeaderName is empty → should default to "Authorization"
	r.addService(services.Service{
		Name:           "openai",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "sk-openai-key")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "openai",
		Method:  "GET",
		Path:    "/v1/models",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var echo map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &echo); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	headers, _ := echo["headers"].(map[string]interface{})
	authSlice, _ := headers["Authorization"].([]interface{})
	if len(authSlice) == 0 {
		t.Fatalf("Authorization header not present")
	}
	if authSlice[0] != "Bearer sk-openai-key" {
		t.Errorf("expected 'Bearer sk-openai-key', got %q", authSlice[0])
	}
}

// ---------------------------------------------------------------------------
// HandleAPICall — custom header name
// ---------------------------------------------------------------------------

func TestHandleAPICall_HeaderInjection_CustomHeaderName(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "custom-api",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "X-Api-Key",
		HeaderTemplate: "{{.secret}}",
	}, "my-raw-key")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "custom-api",
		Method:  "GET",
		Path:    "/data",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var echo map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &echo); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	headers, _ := echo["headers"].(map[string]interface{})
	keySlice, _ := headers["X-Api-Key"].([]interface{})
	if len(keySlice) == 0 {
		t.Fatalf("X-Api-Key header not present; headers: %v", headers)
	}
	if keySlice[0] != "my-raw-key" {
		t.Errorf("expected 'my-raw-key', got %q", keySlice[0])
	}
}

// ---------------------------------------------------------------------------
// HandleAPICall — query parameter injection
// ---------------------------------------------------------------------------

func TestHandleAPICall_QueryParamInjection(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:       "weather-api",
		Type:       "http_proxy",
		Target:     upstream.URL,
		Inject:     "query",
		QueryParam: "api_key",
	}, "weather-secret-key")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "weather-api",
		Method:  "GET",
		Path:    "/current",
		Query:   map[string]string{"city": "London"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var echo map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &echo); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	rawQuery, _ := echo["query"].(string)
	if !strings.Contains(rawQuery, "api_key=weather-secret-key") {
		t.Errorf("expected api_key=weather-secret-key in query %q", rawQuery)
	}
	if !strings.Contains(rawQuery, "city=London") {
		t.Errorf("expected city=London in query %q", rawQuery)
	}
}

// ---------------------------------------------------------------------------
// HandleAPICall — DefaultHeaders applied
// ---------------------------------------------------------------------------

func TestHandleAPICall_DefaultHeaders(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "github",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "token {{.secret}}",
		DefaultHeaders: map[string]string{
			"Accept":     "application/vnd.github.v3+json",
			"User-Agent": "Straylight-AI/1.0",
		},
	}, "ghp_token")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "github",
		Method:  "GET",
		Path:    "/user",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var echo map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &echo); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	headers, _ := echo["headers"].(map[string]interface{})

	acceptSlice, _ := headers["Accept"].([]interface{})
	if len(acceptSlice) == 0 || acceptSlice[0] != "application/vnd.github.v3+json" {
		t.Errorf("expected Accept header, got %v", acceptSlice)
	}
	uaSlice, _ := headers["User-Agent"].([]interface{})
	if len(uaSlice) == 0 || uaSlice[0] != "Straylight-AI/1.0" {
		t.Errorf("expected User-Agent header, got %v", uaSlice)
	}
}

// ---------------------------------------------------------------------------
// HandleAPICall — caller-supplied headers forwarded (but not overriding auth)
// ---------------------------------------------------------------------------

func TestHandleAPICall_CallerHeadersForwarded(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "stripe",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "sk-real")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "stripe",
		Method:  "POST",
		Path:    "/v1/charges",
		Headers: map[string]string{
			"Idempotency-Key": "my-key-123",
			"Authorization":   "Bearer ATTACKER", // must NOT override injected auth
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var echo map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &echo); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	headers, _ := echo["headers"].(map[string]interface{})

	// Caller header forwarded.
	idempSlice, _ := headers["Idempotency-Key"].([]interface{})
	if len(idempSlice) == 0 || idempSlice[0] != "my-key-123" {
		t.Errorf("expected Idempotency-Key header, got %v", idempSlice)
	}

	// Injected auth NOT overridden by caller.
	authSlice, _ := headers["Authorization"].([]interface{})
	if len(authSlice) == 0 || authSlice[0] != "Bearer sk-real" {
		t.Errorf("expected injected Authorization 'Bearer sk-real', got %v", authSlice)
	}
}

// ---------------------------------------------------------------------------
// Credential caching — second call must NOT call GetCredential again
// ---------------------------------------------------------------------------

func TestCredentialCaching_SecondRequestDoesNotCallResolver(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "stripe",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "sk-cached")

	p := proxy.NewProxy(r, nil)
	ctx := context.Background()

	// First call.
	if _, err := p.HandleAPICall(ctx, proxy.APICallRequest{Service: "stripe", Method: "GET", Path: "/v1/a"}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call.
	if _, err := p.HandleAPICall(ctx, proxy.APICallRequest{Service: "stripe", Method: "GET", Path: "/v1/b"}); err != nil {
		t.Fatalf("second call: %v", err)
	}

	if count := r.credCallCount("stripe"); count != 1 {
		t.Errorf("expected GetCredential called 1 time, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Cache invalidation — after InvalidateCache, GetCredential is called again
// ---------------------------------------------------------------------------

func TestCacheInvalidation(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "stripe",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "sk-v1")

	p := proxy.NewProxy(r, nil)
	ctx := context.Background()

	if _, err := p.HandleAPICall(ctx, proxy.APICallRequest{Service: "stripe", Method: "GET", Path: "/v1/a"}); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Update credential in resolver and invalidate cache.
	r.mu.Lock()
	r.creds["stripe"] = "sk-v2"
	r.mu.Unlock()
	p.InvalidateCache("stripe")

	if _, err := p.HandleAPICall(ctx, proxy.APICallRequest{Service: "stripe", Method: "GET", Path: "/v1/b"}); err != nil {
		t.Fatalf("second call: %v", err)
	}

	// GetCredential should have been called twice (once before, once after invalidation).
	if count := r.credCallCount("stripe"); count != 2 {
		t.Errorf("expected GetCredential called 2 times after invalidation, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Sanitizer integration — response body passed through sanitizer
// ---------------------------------------------------------------------------

func TestHandleAPICall_SanitizerApplied(t *testing.T) {
	// Upstream returns a body containing "SECRET"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":"value-SECRET-here"}`)
	}))
	t.Cleanup(srv.Close)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "svc",
		Type:           "http_proxy",
		Target:         srv.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	san := &fakeSanitizer{}
	p := proxy.NewProxy(r, san)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "svc",
		Method:  "GET",
		Path:    "/data",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if atomic.LoadInt32(&san.called) == 0 {
		t.Error("sanitizer was not called")
	}
	if strings.Contains(resp.Body, "SECRET") {
		t.Errorf("sanitizer did not redact SECRET; body: %s", resp.Body)
	}
	if !strings.Contains(resp.Body, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in body; got: %s", resp.Body)
	}
}

// ---------------------------------------------------------------------------
// Sanitizer nil — pass-through without panic
// ---------------------------------------------------------------------------

func TestHandleAPICall_NilSanitizerPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "svc",
		Type:           "http_proxy",
		Target:         srv.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Body != `{"ok":true}` {
		t.Errorf("unexpected body: %q", resp.Body)
	}
}

// ---------------------------------------------------------------------------
// Error: unknown service
// ---------------------------------------------------------------------------

func TestHandleAPICall_UnknownService(t *testing.T) {
	r := newFakeResolver()
	p := proxy.NewProxy(r, nil)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "ghost",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected error for unknown service, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should mention service name; got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error: missing credential
// ---------------------------------------------------------------------------

func TestHandleAPICall_MissingCredential(t *testing.T) {
	r := newFakeResolver()
	// Register service but no credential.
	r.mu.Lock()
	r.svcs["svc"] = services.Service{
		Name:           "svc",
		Type:           "http_proxy",
		Target:         "https://example.com",
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}
	// creds["svc"] intentionally absent
	r.mu.Unlock()

	p := proxy.NewProxy(r, nil)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "svc",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected error for missing credential, got nil")
	}
	if !strings.Contains(err.Error(), "svc") {
		t.Errorf("error should mention service name; got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error: upstream network unreachable
// ---------------------------------------------------------------------------

func TestHandleAPICall_UpstreamUnreachable(t *testing.T) {
	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "deadend",
		Type:           "http_proxy",
		Target:         "http://127.0.0.1:19999", // nothing listening here
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxy(r, nil)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "deadend",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected error for unreachable upstream, got nil")
	}
}

// ---------------------------------------------------------------------------
// Error: upstream 4xx/5xx passed through
// ---------------------------------------------------------------------------

func TestHandleAPICall_UpstreamErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_token"}`)
	}))
	t.Cleanup(srv.Close)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "svc",
		Type:           "http_proxy",
		Target:         srv.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "bad-tok")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "svc",
		Method:  "GET",
		Path:    "/protected",
	})
	if err != nil {
		t.Fatalf("unexpected error (4xx should be passed through, not errored): %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, "invalid_token") {
		t.Errorf("expected body to contain error details; got: %s", resp.Body)
	}
}

// ---------------------------------------------------------------------------
// Timeout: context cancellation
// ---------------------------------------------------------------------------

func TestHandleAPICall_ContextTimeout(t *testing.T) {
	// Slow upstream that sleeps 2 seconds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "slow",
		Type:           "http_proxy",
		Target:         srv.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxy(r, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := p.HandleAPICall(ctx, proxy.APICallRequest{
		Service: "slow",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Response headers returned
// ---------------------------------------------------------------------------

func TestHandleAPICall_ResponseHeadersReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Rate-Limit", "100")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "svc",
		Type:           "http_proxy",
		Target:         srv.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Headers["X-Rate-Limit"] != "100" {
		t.Errorf("expected X-Rate-Limit: 100, got: %v", resp.Headers)
	}
}

// ---------------------------------------------------------------------------
// POST with body
// ---------------------------------------------------------------------------

func TestHandleAPICall_PostWithBody(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "api",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxy(r, nil)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "api",
		Method:  "POST",
		Path:    "/create",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    map[string]interface{}{"name": "test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var echo map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &echo); err != nil {
		t.Fatalf("parse echo: %v", err)
	}
	body, _ := echo["body"].(string)
	if !strings.Contains(body, "test") {
		t.Errorf("expected body to contain 'test'; got: %s", body)
	}
}

// ---------------------------------------------------------------------------
// Thread safety — concurrent requests don't race
// ---------------------------------------------------------------------------

func TestHandleAPICall_ConcurrentRequests(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "svc",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	p := proxy.NewProxy(r, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.HandleAPICall(ctx, proxy.APICallRequest{
				Service: "svc",
				Method:  "GET",
				Path:    "/concurrent",
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Cache TTL — entry expires after 60 seconds (mocked with clock)
// ---------------------------------------------------------------------------

func TestCredentialCache_TTLExpiry(t *testing.T) {
	upstream := upstreamEchoServer(t)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "svc",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "tok")

	// Use a proxy with a very short TTL for testing.
	p := proxy.NewProxyWithTTL(r, nil, 50*time.Millisecond)
	ctx := context.Background()

	if _, err := p.HandleAPICall(ctx, proxy.APICallRequest{Service: "svc", Method: "GET", Path: "/a"}); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Wait for TTL to expire.
	time.Sleep(100 * time.Millisecond)

	if _, err := p.HandleAPICall(ctx, proxy.APICallRequest{Service: "svc", Method: "GET", Path: "/b"}); err != nil {
		t.Fatalf("second call after TTL: %v", err)
	}

	// After TTL expiry, GetCredential should have been called twice.
	if count := r.credCallCount("svc"); count < 2 {
		t.Errorf("expected GetCredential called >= 2 times after TTL, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Benchmark: proxy overhead
// ---------------------------------------------------------------------------

func BenchmarkHandleAPICall(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	b.Cleanup(upstream.Close)

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "bench",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.secret}}",
	}, "bench-token")

	p := proxy.NewProxy(r, nil)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := p.HandleAPICall(ctx, proxy.APICallRequest{
			Service: "bench",
			Method:  "GET",
			Path:    "/bench",
		})
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
