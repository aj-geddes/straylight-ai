package proxy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Audit mock
// ---------------------------------------------------------------------------

// captureEmitter records all emitted audit events for assertion.
type captureEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureEmitter) Emit(ev audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *captureEmitter) Events() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

// Verify captureEmitter satisfies audit.Emitter.
var _ audit.Emitter = (*captureEmitter)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newAuditProxy creates a Proxy wired with a captureEmitter and a fake upstream
// server that responds with status and body.
func newAuditProxy(t *testing.T, cap *captureEmitter, upstreamStatus int, upstreamBody string) (*proxy.Proxy, *httptest.Server, *captureEmitter) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(upstreamStatus)
		_, _ = w.Write([]byte(upstreamBody))
	}))
	t.Cleanup(upstream.Close)

	resolver := &auditMockResolver{
		svc: services.Service{
			Name:   "testsvc",
			Type:   "http_proxy",
			Target: upstream.URL,
			Inject: "header",
		},
		cred: "test-token",
	}

	p := proxy.NewProxy(resolver, nil)
	p.SetAudit(cap)
	return p, upstream, cap
}

// auditMockResolver satisfies proxy.ServiceResolver for audit tests.
type auditMockResolver struct {
	svc  services.Service
	cred string
}

func (r *auditMockResolver) Get(_ string) (services.Service, error) {
	return r.svc, nil
}

func (r *auditMockResolver) GetCredential(_ string) (string, error) {
	return r.cred, nil
}

func (r *auditMockResolver) ReadCredentials(_ string) (string, map[string]string, error) {
	return "legacy", map[string]string{"value": r.cred}, nil
}

// ---------------------------------------------------------------------------
// Tests: audit events emitted on successful API call
// ---------------------------------------------------------------------------

func TestProxy_Audit_EmitsCredentialAccessedOnSuccess(t *testing.T) {
	cap := &captureEmitter{}
	p, _, _ := newAuditProxy(t, cap, http.StatusOK, `{"ok":true}`)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "testsvc",
		Method:  "GET",
		Path:    "/v1/test",
	})
	if err != nil {
		t.Fatalf("HandleAPICall returned error: %v", err)
	}

	// Give the emitter a moment (it is synchronous in proxy, but be safe).
	time.Sleep(10 * time.Millisecond)

	events := cap.Events()
	if len(events) == 0 {
		t.Fatal("expected at least one audit event, got none")
	}

	var found bool
	for _, ev := range events {
		if ev.Type == audit.EventCredentialAccessed {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a %q event, got: %v", audit.EventCredentialAccessed, events)
	}
}

func TestProxy_Audit_CredentialAccessedContainsServiceName(t *testing.T) {
	cap := &captureEmitter{}
	p, _, _ := newAuditProxy(t, cap, http.StatusOK, `{}`)

	_, _ = p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "testsvc",
		Method:  "GET",
		Path:    "/v1/test",
	})

	events := cap.Events()
	for _, ev := range events {
		if ev.Type == audit.EventCredentialAccessed {
			if ev.Service != "testsvc" {
				t.Errorf("audit event service = %q, want %q", ev.Service, "testsvc")
			}
			return
		}
	}
	t.Error("no credential_accessed event found")
}

func TestProxy_Audit_CredentialAccessedContainsMethodAndPath(t *testing.T) {
	cap := &captureEmitter{}
	p, _, _ := newAuditProxy(t, cap, http.StatusOK, `{}`)

	_, _ = p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "testsvc",
		Method:  "POST",
		Path:    "/v1/charges",
	})

	events := cap.Events()
	for _, ev := range events {
		if ev.Type == audit.EventCredentialAccessed {
			if ev.Details["method"] != "POST" {
				t.Errorf("details[method] = %q, want POST", ev.Details["method"])
			}
			if ev.Details["path"] != "/v1/charges" {
				t.Errorf("details[path] = %q, want /v1/charges", ev.Details["path"])
			}
			return
		}
	}
	t.Error("no credential_accessed event found")
}

func TestProxy_Audit_CredentialAccessedContainsStatusCode(t *testing.T) {
	cap := &captureEmitter{}
	p, _, _ := newAuditProxy(t, cap, http.StatusCreated, `{}`)

	_, _ = p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "testsvc",
		Method:  "POST",
		Path:    "/v1/items",
	})

	events := cap.Events()
	for _, ev := range events {
		if ev.Type == audit.EventCredentialAccessed {
			if ev.Details["status"] != "201" {
				t.Errorf("details[status] = %q, want 201", ev.Details["status"])
			}
			return
		}
	}
	t.Error("no credential_accessed event found")
}

func TestProxy_Audit_NoCredentialValuesInDetails(t *testing.T) {
	cap := &captureEmitter{}
	p, _, _ := newAuditProxy(t, cap, http.StatusOK, `{}`)

	_, _ = p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "testsvc",
		Method:  "GET",
		Path:    "/v1/test",
	})

	events := cap.Events()
	for _, ev := range events {
		for k, v := range ev.Details {
			if v == "test-token" {
				t.Errorf("audit event detail[%q] contains credential value", k)
			}
		}
		if ev.Tool == "test-token" || ev.Service == "test-token" {
			t.Error("audit event contains credential value in a top-level field")
		}
	}
}

func TestProxy_Audit_NoAuditEmitterDoesNotPanic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	resolver := &auditMockResolver{
		svc: services.Service{
			Name:   "testsvc",
			Type:   "http_proxy",
			Target: upstream.URL,
			Inject: "header",
		},
		cred: "test-token",
	}

	// Proxy created without audit — SetAudit never called.
	p := proxy.NewProxy(resolver, nil)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "testsvc",
		Method:  "GET",
		Path:    "/v1/test",
	})
	if err != nil {
		t.Fatalf("expected no error without audit emitter, got: %v", err)
	}
}

func TestProxy_Audit_Emit4xxStatus(t *testing.T) {
	cap := &captureEmitter{}
	p, _, _ := newAuditProxy(t, cap, http.StatusUnauthorized, `{"error":"unauthorized"}`)

	_, _ = p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "testsvc",
		Method:  "GET",
		Path:    "/v1/protected",
	})

	events := cap.Events()
	for _, ev := range events {
		if ev.Type == audit.EventCredentialAccessed {
			if ev.Details["status"] != "401" {
				t.Errorf("4xx: details[status] = %q, want 401", ev.Details["status"])
			}
			return
		}
	}
	t.Error("no credential_accessed event found for 4xx upstream")
}
