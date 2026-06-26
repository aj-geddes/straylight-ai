// Package proxy_test — QA-review RED tests for wave-0 security findings.
// These must FAIL before the fixes are applied.
package proxy_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Finding 1: EgressPolicy.AllowHosts must be honored in the proxy DialContext.
//
// The DialContext currently calls guard.CheckIP(ip, policy) only, which checks
// AllowCIDRs and AllowLoopback but NOT AllowHosts. Only guard.CheckHost checks
// AllowHosts, and CheckHost is never called by DialContext.
//
// Required fix: thread the original request hostname into the DialContext via
// context so it can check AllowHosts before running the IP denylist.
// ---------------------------------------------------------------------------

// TestProxy_EgressGuard_AllowHosts_PermitsAllowlistedHost verifies that a
// service with EgressPolicy.AllowHosts=["127.0.0.1"] can reach a target
// on 127.0.0.1 even when AllowLoopback=false.
//
// BEFORE FIX: fails because DialContext calls CheckIP which ignores AllowHosts.
// AFTER FIX: passes because DialContext checks AllowHosts for the original host.
func TestProxy_EgressGuard_AllowHosts_PermitsAllowlistedHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	// Determine loopback host from upstream URL.
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if host == "" {
		host = "127.0.0.1"
	}

	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "internal-svc",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.Secret}}",
		// AllowHosts explicitly permits this loopback host;
		// AllowLoopback is deliberately off.
		Egress: &services.EgressPolicy{
			AllowHosts:    []string{host},
			AllowLoopback: false,
		},
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)

	resp, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "internal-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err != nil {
		t.Fatalf("AllowHosts-listed host should be reachable through the proxy; got error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestProxy_EgressGuard_AllowHosts_UnlistedPrivateHostDenied verifies that a
// service with AllowHosts=["other.example.com"] and AllowLoopback=false cannot
// reach a loopback target (the host is NOT in AllowHosts).
//
// This test should PASS even before the fix (it is the "still denied" case).
// Including it here to document the invariant that must not regress.
func TestProxy_EgressGuard_AllowHosts_UnlistedPrivateHostDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "svc-with-wrong-allowhosts",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.Secret}}",
		// AllowHosts points to a different host; loopback is NOT allowed.
		Egress: &services.EgressPolicy{
			AllowHosts:    []string{"other.example.com"},
			AllowLoopback: false,
		},
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "svc-with-wrong-allowhosts",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected egress denied error for loopback host not in AllowHosts")
	}
}

// ---------------------------------------------------------------------------
// Finding 4: EventEgressDenied must be emitted when DialContext denies a dial.
// ---------------------------------------------------------------------------

// TestProxy_Audit_EgressDenied_EmitsEgressDeniedEvent verifies that when the
// DialContext blocks a private IP, an egress_denied audit event is emitted.
//
// BEFORE FIX: no such event is emitted (EventEgressDenied doesn't exist yet).
// AFTER FIX: exactly one egress_denied event is emitted containing host + reason.
func TestProxy_Audit_EgressDenied_EmitsEgressDeniedEvent(t *testing.T) {
	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "blocked-svc",
		Type:           "http_proxy",
		Target:         "http://10.0.0.1",
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.Secret}}",
		// No egress policy → 10.0.0.1 is blocked by default.
	}, "tok")

	cap := &captureEmitter{}
	p := proxy.NewProxyWithGuard(r, nil, guard)
	p.SetAudit(cap)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "blocked-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected egress denied error, got nil")
	}

	events := cap.Events()
	var found bool
	for _, ev := range events {
		if ev.Type == audit.EventEgressDenied {
			found = true
			// Host must be present in Details (not a credential / full URL path).
			if ev.Details["host"] == "" && ev.Details["reason"] == "" {
				t.Error("egress_denied event must include 'host' or 'reason' in Details")
			}
			// Credential must never appear.
			for k, v := range ev.Details {
				if v == "tok" {
					t.Errorf("egress_denied event Details[%q] contains credential value", k)
				}
			}
		}
	}
	if !found {
		t.Errorf("expected an %q audit event on egress denial; got events: %v",
			audit.EventEgressDenied, events)
	}
}

// ---------------------------------------------------------------------------
// Finding 5: Redirect to a blocked host must be denied.
// The DialContext re-check must fire on every connection, including redirect
// re-dials. Verify by using a server that returns 302 → http://10.0.0.1/.
// ---------------------------------------------------------------------------

// TestProxy_EgressGuard_RedirectToBlockedHost_Denied verifies that an HTTP
// redirect leading to a private IP is blocked by the DialContext guard.
//
// The upstream server is on loopback (AllowLoopback=true so the first dial
// succeeds). Its only job is to return 302 → http://10.0.0.1/. The second
// dial (to 10.0.0.1) should be blocked because AllowCIDRs is empty.
//
// This test exercises the DNS-rebinding defense path: every DialContext call
// re-checks the resolved IP, including redirect-driven re-dials.
func TestProxy_EgressGuard_RedirectToBlockedHost_Denied(t *testing.T) {
	// Upstream that redirects to an RFC1918 address.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://10.0.0.1/")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	guard := egress.New()

	r := newFakeResolver()
	r.addService(services.Service{
		Name:           "redirect-svc",
		Type:           "http_proxy",
		Target:         upstream.URL,
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{.Secret}}",
		// AllowLoopback=true so the first dial to the httptest server succeeds;
		// AllowCIDRs is empty so 10.0.0.1 is still blocked on the redirect re-dial.
		Egress: &services.EgressPolicy{
			AllowLoopback: true,
		},
	}, "tok")

	p := proxy.NewProxyWithGuard(r, nil, guard)

	_, err := p.HandleAPICall(context.Background(), proxy.APICallRequest{
		Service: "redirect-svc",
		Method:  "GET",
		Path:    "/",
	})
	if err == nil {
		t.Fatal("expected egress denied error on redirect to 10.0.0.1, got nil")
	}
	errStr := strings.ToLower(err.Error())
	if !strings.Contains(errStr, "egress") && !strings.Contains(errStr, "denied") &&
		!strings.Contains(errStr, "unreachable") {
		t.Errorf("error should indicate egress/network denial; got: %v", err)
	}
}
