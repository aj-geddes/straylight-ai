// Package egress_test — QA-review RED tests for wave-0 security findings.
// These tests must FAIL before the fixes are applied.
package egress_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/egress"
)

// ---------------------------------------------------------------------------
// Finding 3: ::/128 (IPv6 unspecified) must be in the denylist.
// ---------------------------------------------------------------------------

// TestCheckIP_IPv6Unspecified_Denied asserts that the IPv6 unspecified address
// "::" is blocked by the default denylist. Before the fix, guard.go does not
// include ::/128, so this test fails (returns Allowed:true).
func TestCheckIP_IPv6Unspecified_Denied(t *testing.T) {
	guard := egress.New()
	pol := egress.Policy{}

	ip := net.ParseIP("::")
	if ip == nil {
		t.Fatal("failed to parse IPv6 unspecified ::")
	}
	d := guard.CheckIP(ip, pol)
	if d.Allowed {
		t.Errorf("CheckIP(::) = Allowed:true, want Allowed:false (IPv6 unspecified must be denied)")
	}
	if !d.Allowed && d.Reason == "" {
		t.Error("CheckIP(::) denied but Reason is empty")
	}
}

// ---------------------------------------------------------------------------
// Finding 1 (guard-layer): CheckHost AllowHosts path already works; this test
// verifies the semantics that the proxy DialContext fix must replicate.
// The proxy-level integration test is in proxy/proxy_qa_test.go.
// ---------------------------------------------------------------------------

// TestCheckHost_AllowHosts_PermitsPrivateIPLiteralHost verifies CheckHost allows
// a private IP literal when it appears in AllowHosts (guards pre-resolution).
// This is a sanity-check that the guard semantics are correct before the
// proxy DialContext integration test proves the plumbing works.
func TestCheckHost_AllowHosts_PermitsPrivateIPLiteralHost(t *testing.T) {
	guard := egress.New()
	ctx := context.Background()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	if host == "" {
		host = "127.0.0.1"
	}

	// Without AllowHosts: loopback is blocked.
	d := guard.CheckHost(ctx, host, egress.Policy{})
	if d.Allowed {
		t.Fatalf("host %q must be blocked without AllowHosts (baseline check)", host)
	}

	// With AllowHosts containing the exact host: allowed (short-circuits before IP check).
	d = guard.CheckHost(ctx, host, egress.Policy{AllowHosts: []string{host}})
	if !d.Allowed {
		t.Errorf("host %q in AllowHosts must be allowed; got reason: %s", host, d.Reason)
	}
}
