// Package cmdwrap_test — egress pre-flight tests.
// Tests verify that the cmdwrap exec pre-flight check blocks commands whose
// parsed URL arguments resolve to denied SSRF destinations, and allows those
// whose host is in the AllowHosts list.
//
// Per ADR-010: this is best-effort (pre-flight only). The child process's own
// socket-level egress is NOT mediated in v1 — that is documented residual risk.
package cmdwrap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newEgressWrapper(guard egress.Guard, svcEgress *services.EgressPolicy) *cmdwrap.Wrapper {
	resolver := &fakeResolver{
		credentials: map[string]string{"svc": "tok"},
		svcs: map[string]services.Service{
			"svc": {
				Name:            "svc",
				Type:            "http_proxy",
				Target:          "https://example.com",
				Inject:          "header",
				ExecEnabled:     true,
				AllowedCommands: []string{"curl", "echo"},
				Egress:          svcEgress,
			},
		},
	}
	return configureTestCredentials(cmdwrap.NewWrapperWithGuard(resolver, &fakeSanitizer{}, guard))
}

// ---------------------------------------------------------------------------
// Test: command with denied URL arg is blocked before exec
// ---------------------------------------------------------------------------

func TestWrapper_EgressPreflight_BlocksMetadataURL(t *testing.T) {
	guard := egress.New()
	w := newEgressWrapper(guard, nil)

	// curl with metadata endpoint as an argument — must be blocked pre-exec.
	_, err := w.Execute(context.Background(), cmdwrap.ExecRequest{
		Service: "svc",
		Command: "curl http://169.254.169.254/latest/meta-data/",
		EnvVar:  "API_TOKEN",
	})
	if err == nil {
		t.Fatal("expected egress preflight error for 169.254.169.254 URL arg, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "egress") {
		t.Errorf("error should mention 'egress'; got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: command with RFC1918 URL arg is blocked
// ---------------------------------------------------------------------------

func TestWrapper_EgressPreflight_BlocksRFC1918URL(t *testing.T) {
	guard := egress.New()
	w := newEgressWrapper(guard, nil)

	_, err := w.Execute(context.Background(), cmdwrap.ExecRequest{
		Service: "svc",
		Command: "curl http://10.0.0.1/secret",
		EnvVar:  "API_TOKEN",
	})
	if err == nil {
		t.Fatal("expected egress preflight error for RFC1918 URL arg, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test: command with allowlisted host in AllowHosts proceeds
// (process will still fail because the binary may not exist, but the egress
// check itself must not block it — we check the error is NOT an egress error)
// ---------------------------------------------------------------------------

func TestWrapper_EgressPreflight_AllowsAllowlistedHost(t *testing.T) {
	guard := egress.New()
	// AllowHosts includes the target host, so CheckHost returns allowed.
	policy := &services.EgressPolicy{AllowHosts: []string{"169.254.169.254"}}
	w := newEgressWrapper(guard, policy)

	// Use echo which exits instantly — we only care that the EGRESS check passes,
	// not that the command succeeds (echo doesn't connect anywhere).
	_, err := w.Execute(context.Background(), cmdwrap.ExecRequest{
		Service: "svc",
		Command: "echo http://169.254.169.254/",
		EnvVar:  "API_TOKEN",
	})
	// The egress check passes; any error must NOT be an egress error.
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "egress") {
		t.Errorf("allowlisted host should not produce an egress error; got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: command with no parseable URL host proceeds (documents residual risk)
// Per ADR-010 v1: no parseable host arg → no pre-flight check → allowed.
// ---------------------------------------------------------------------------

func TestWrapper_EgressPreflight_NoURLArgProceeds(t *testing.T) {
	guard := egress.New()
	w := newEgressWrapper(guard, nil)

	// "echo hello" has no URL argument — egress pre-flight must not block it.
	_, err := w.Execute(context.Background(), cmdwrap.ExecRequest{
		Service: "svc",
		Command: "echo hello",
		EnvVar:  "API_TOKEN",
	})
	// Any error here is NOT an egress error (may be "echo not in allowlist" etc.)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "egress") {
		t.Errorf("non-URL command should not produce egress error; got: %v", err)
	}
}
