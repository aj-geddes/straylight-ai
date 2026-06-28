package server_test

// Tests for buildRemoteServer wiring (ADR-015, issue #12).
//
// buildRemoteServer is exercised via the test seam in export_test.go:
//
//	var BuildRemoteServer = (*Server).buildRemoteServer
//
// Usage: httpSrv, err := server.BuildRemoteServer(s)
//
// Coverage targets:
//  1. Disjointness guard fires through real wiring — CRITICAL regression lock.
//  2. EgressGuard wired into SSRF-gated JWKSProvider when JWKSProvider is nil.
//  3. Middleware order: OriginValidate fires before rate-limit; returns 403.
//  4. PRM path /.well-known/oauth-protected-resource is exempt from OriginValidate.
//  5. Off by default: empty RemoteListenAddress → Run()+Stop() completes cleanly.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/mcpauth"
	"github.com/straylight-ai/straylight/internal/oidc"
	"github.com/straylight-ai/straylight/internal/server"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// minimalVCfg returns a ValidatorConfig that passes mcpauth.New for the given
// trustedIssuer. JWKSProvider uses the AllowAll egress guard so construction
// succeeds without a real JWKS endpoint.
func minimalVCfg(trustedIssuer string) *mcpauth.ValidatorConfig {
	return &mcpauth.ValidatorConfig{
		Resource:       "https://resource.example.com",
		TrustedIssuers: []string{trustedIssuer},
		JWKSProvider:   mcpauth.NewSSRFGatedJWKSProvider(server.NewEgressSSRFGuard(egress.AllowAll()), nil),
		AllowedAlgs:    []string{"RS256"},
		OwnIssuerURL:   "",
	}
}

// freeTCPAddr finds and returns an available loopback TCP address.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeTCPAddr: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// ---------------------------------------------------------------------------
// Test 1: Disjointness violation — CRITICAL regression lock.
// ---------------------------------------------------------------------------

// TestBuildRemoteServer_DisjointnessViolationErrors verifies that when
// MCPResourceServer.TrustedIssuers contains the same URL as
// OIDCDiscovery.IssuerURL (with OwnIssuerURL empty so buildRemoteServer
// injects the runtime issuer URL), mcpauth.New rejects the config and
// buildRemoteServer returns a non-nil error.
//
// This is the regression lock for the ADR-015 role-separation finding:
// the RS validator must never trust Straylight's own issuer.
func TestBuildRemoteServer_DisjointnessViolationErrors(t *testing.T) {
	const issuerURL = "https://idp.example.com"

	cfg := server.Config{
		RemoteListenAddress: "127.0.0.1:0",
		MCPResourceServer: &mcpauth.ValidatorConfig{
			Resource:       "https://resource.example.com",
			TrustedIssuers: []string{issuerURL},
			JWKSProvider:   mcpauth.NewSSRFGatedJWKSProvider(server.NewEgressSSRFGuard(egress.AllowAll()), nil),
			AllowedAlgs:    []string{"RS256"},
			OwnIssuerURL:   "", // empty: buildRemoteServer must inject IssuerURL here
		},
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL: issuerURL, // same as TrustedIssuers[0] — violation
		},
		EgressGuard:       egress.AllowAll(),
		MCPAllowedOrigins: []string{"https://claude.ai"},
	}

	s := server.New(cfg)
	httpSrv, err := server.BuildRemoteServer(s)

	if err == nil {
		t.Fatal("expected error when TrustedIssuers contains OIDCDiscovery.IssuerURL (disjointness violation), got nil")
	}
	if httpSrv != nil {
		t.Errorf("expected nil *http.Server on error, got non-nil")
	}
	if !strings.Contains(err.Error(), "disjointness") && !strings.Contains(err.Error(), "OwnIssuerURL") {
		t.Errorf("error %q does not mention 'disjointness' or 'OwnIssuerURL'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test 2: Disjoint issuers — construction succeeds.
// ---------------------------------------------------------------------------

// TestBuildRemoteServer_DisjointnessHappySucceeds verifies that when
// TrustedIssuers is disjoint from OIDCDiscovery.IssuerURL,
// buildRemoteServer returns a non-nil *http.Server with a non-nil Handler.
func TestBuildRemoteServer_DisjointnessHappySucceeds(t *testing.T) {
	cfg := server.Config{
		RemoteListenAddress: "127.0.0.1:0",
		MCPResourceServer:   minimalVCfg("https://external-idp.example.com"),
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL: "https://straylight.example.com", // different from TrustedIssuer
		},
		EgressGuard:       egress.AllowAll(),
		MCPAllowedOrigins: []string{"https://claude.ai"},
	}

	s := server.New(cfg)
	httpSrv, err := server.BuildRemoteServer(s)

	if err != nil {
		t.Fatalf("expected success with disjoint issuers, got error: %v", err)
	}
	if httpSrv == nil {
		t.Fatal("expected non-nil *http.Server")
	}
	if httpSrv.Handler == nil {
		t.Error("expected non-nil Handler on returned *http.Server")
	}
}

// ---------------------------------------------------------------------------
// Test 3: EgressGuard wired into SSRF-gated JWKSProvider.
// ---------------------------------------------------------------------------

// TestBuildRemoteServer_EgressGuardWired verifies that when EgressGuard is
// set and MCPResourceServer.JWKSProvider is nil, buildRemoteServer injects
// an SSRF-gated JWKSProvider that routes key fetches through the egress guard.
//
// Verified by: sending a POST /mcp with a valid-looking (but fake-signed)
// bearer token whose iss matches TrustedIssuers. mcpauth.Validate: parses
// header+claims → checks issuer (trusted) → calls JWKSProvider.KeyFor →
// which calls CheckHost on the trackingGuard before attempting a key lookup.
func TestBuildRemoteServer_EgressGuardWired(t *testing.T) {
	tg := &trackingGuard{inner: egress.AllowAll()}

	cfg := server.Config{
		RemoteListenAddress: "127.0.0.1:0",
		MCPResourceServer: &mcpauth.ValidatorConfig{
			Resource:       "https://resource.example.com",
			TrustedIssuers: []string{"https://external-idp.example.com"},
			JWKSProvider:   nil, // nil: buildRemoteServer must wire SSRF-gated provider
			AllowedAlgs:    []string{"RS256"},
			OwnIssuerURL:   "",
		},
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL: "https://straylight.example.com",
		},
		EgressGuard:       tg,
		MCPAllowedOrigins: []string{"https://claude.ai"},
	}

	s := server.New(cfg)
	httpSrv, err := server.BuildRemoteServer(s)
	if err != nil {
		t.Fatalf("expected success when EgressGuard is set and JWKSProvider is nil, got: %v", err)
	}
	if httpSrv == nil {
		t.Fatal("expected non-nil *http.Server")
	}

	// header={"alg":"RS256","kid":"key-1"}, claims with iss=TrustedIssuer, exp far future.
	// The fake third segment triggers "invalid signature encoding" — but not before
	// the SSRF guard is checked during JWKSProvider.KeyFor.
	const fakeToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0" +
		".eyJpc3MiOiJodHRwczovL2V4dGVybmFsLWlkcC5leGFtcGxlLmNvbSIsInN1YiI6InVzZXIxIiwiYXVkIjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLmNvbSIsImV4cCI6OTk5OTk5OTk5OX0" +
		".AAAA"

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"ping","id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", fakeToken))
	rec := httptest.NewRecorder()
	httpSrv.Handler.ServeHTTP(rec, req)

	// The request fails auth (fake sig), but the guard must have been called.
	if !tg.checked {
		t.Error("expected trackingGuard.CheckHost to be called during SSRF-gated JWKS key fetch, but it was not")
	}
}

// ---------------------------------------------------------------------------
// Test 4: Off by default.
// ---------------------------------------------------------------------------

// TestBuildRemoteServer_OffByDefault verifies that when RemoteListenAddress is
// empty and MCPResourceServer is nil, Run()+Stop() completes without error.
// buildRemoteServer is never invoked by Run() in this configuration.
func TestBuildRemoteServer_OffByDefault(t *testing.T) {
	addr := freeTCPAddr(t)

	cfg := server.Config{
		ListenAddress:       addr,
		RemoteListenAddress: "", // remote OFF
		Version:             "test",
		VaultStatus:         func() string { return "unsealed" },
	}

	s := server.New(cfg)

	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run()
	}()

	// Wait until the main server is accepting connections.
	client := &http.Client{Timeout: 200 * time.Millisecond}
	healthURL := fmt.Sprintf("http://%s/api/v1/health", addr)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop() returned error: %v", err)
	}

	select {
	case runErr := <-runDone:
		if runErr != nil {
			t.Errorf("Run() returned unexpected error: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run() did not return within 5 seconds after Stop()")
	}
}

// ---------------------------------------------------------------------------
// Test 5: Middleware order — OriginValidate before rate-limit; PRM exempt.
// ---------------------------------------------------------------------------

// TestBuildRemoteServer_MiddlewareChain drives HTTP requests through the
// assembled remote handler to prove middleware order:
//
//	a. GET /.well-known/oauth-protected-resource with no Origin → 200.
//	   (PRM is public per RFC 9728; exempt from OriginValidate.)
//	b. POST /mcp with a disallowed Origin → 403 from OriginValidate,
//	   before auth or rate-limiting is evaluated.
func TestBuildRemoteServer_MiddlewareChain(t *testing.T) {
	cfg := server.Config{
		RemoteListenAddress: "127.0.0.1:0",
		MCPResourceServer:   minimalVCfg("https://external-idp.example.com"),
		OIDCDiscovery: &oidc.Discovery{
			IssuerURL: "https://straylight.example.com",
		},
		EgressGuard:       egress.AllowAll(),
		MCPAllowedOrigins: []string{"https://claude.ai"},
	}

	s := server.New(cfg)
	httpSrv, err := server.BuildRemoteServer(s)
	if err != nil {
		t.Fatalf("BuildRemoteServer failed: %v", err)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		origin     string // empty = no Origin header
		wantStatus int
	}{
		{
			name:       "PRM_exempt_no_origin",
			method:     http.MethodGet,
			path:       "/.well-known/oauth-protected-resource",
			origin:     "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "mcp_disallowed_origin_returns_403",
			method:     http.MethodPost,
			path:       "/mcp",
			origin:     "https://evil.example.com", // not in MCPAllowedOrigins
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			httpSrv.Handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}
