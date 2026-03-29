package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/server"
)

// TestHealthEndpoint_ReturnsJSON verifies the health endpoint returns correct JSON structure.
// When no VaultStatus is configured, OpenBao is "unavailable" and the endpoint returns
// 503 with status=degraded (WP-2.5: degraded status when vault is unavailable).
func TestHealthEndpoint_ReturnsJSON(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	// Without VaultStatus, vault is "unavailable" → 503 degraded.
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 when vault unavailable, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", contentType)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}

	status, ok := body["status"].(string)
	if !ok {
		t.Fatal("expected 'status' field as string in response")
	}
	if status != "degraded" {
		t.Errorf("expected status=degraded when vault unavailable, got %q", status)
	}

	version, ok := body["version"].(string)
	if !ok {
		t.Fatal("expected 'version' field as string in response")
	}
	if version != "1.0.0" {
		t.Errorf("expected version=0.5.0, got %q", version)
	}

	// Verify the openbao field is present; without a VaultStatus func it should
	// report "unavailable".
	openbao, ok := body["openbao"].(string)
	if !ok {
		t.Fatal("expected 'openbao' field as string in response")
	}
	if openbao != "unavailable" {
		t.Errorf("expected openbao=unavailable when no VaultStatus func provided, got %q", openbao)
	}
}

// TestHealthEndpoint_OpenbaoStatus verifies that the health endpoint reports
// the vault status from the VaultStatus function.
func TestHealthEndpoint_OpenbaoStatus(t *testing.T) {
	cases := []struct {
		name           string
		vaultStatusFn  func() string
		expectedStatus string
	}{
		{"unsealed", func() string { return "unsealed" }, "unsealed"},
		{"sealed", func() string { return "sealed" }, "sealed"},
		{"unavailable_nil_fn", nil, "unavailable"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := server.New(server.Config{
				ListenAddress: "127.0.0.1:0",
				Version:       "1.0.0",
				VaultStatus:   tc.vaultStatusFn,
			})

			req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			var body map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode health response: %v", err)
			}

			openbao, ok := body["openbao"].(string)
			if !ok {
				t.Fatal("expected 'openbao' field as string in response")
			}
			if openbao != tc.expectedStatus {
				t.Errorf("expected openbao=%q, got %q", tc.expectedStatus, openbao)
			}
		})
	}
}

// TestHealthEndpoint_MethodNotAllowed verifies that POST to health returns 405.
func TestHealthEndpoint_MethodNotAllowed(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.0",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestWebUIRoute_ReturnsHTML verifies the root route returns the embedded web UI (index.html).
func TestWebUIRoute_ReturnsHTML(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("expected non-empty body for web UI")
	}
}

// TestUnknownRoute_ReturnsSPAFallback verifies that unknown non-API routes return the
// SPA index.html (200) so client-side routing can handle them.
func TestUnknownRoute_ReturnsSPAFallback(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/some/spa/route", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	// The SPA handler falls back to index.html for all unknown paths.
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 (SPA fallback), got %d", w.Code)
	}
}

// TestServerConfig_ListenAddress verifies the server exposes its listen address.
func TestServerConfig_ListenAddress(t *testing.T) {
	cfg := server.Config{
		ListenAddress: "0.0.0.0:9470",
		Version:       "1.0.0",
	}

	srv := server.New(cfg)
	if srv.ListenAddress() != "0.0.0.0:9470" {
		t.Errorf("expected ListenAddress=0.0.0.0:9470, got %q", srv.ListenAddress())
	}
}

// TestServicesPlaceholder_Returns501 verifies that the /api/v1/services/ stub returns 501.
func TestServicesPlaceholder_Returns501(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/services/", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if _, ok := body["error"]; !ok {
		t.Error("expected 'error' field in response body")
	}
}

// TestMCPPlaceholder_Returns501 verifies that the /api/v1/mcp/ stub returns 501.
func TestMCPPlaceholder_Returns501(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tool-list", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", w.Code)
	}
}

// TestOAuthPlaceholder_Returns501 verifies that the /api/v1/oauth/ stub returns 501.
func TestOAuthPlaceholder_Returns501(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/github/start", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", w.Code)
	}
}

// TestRun_StartsAndStops verifies that Run() starts a real HTTP server, serves
// the health endpoint, and shuts down cleanly when context is cancelled.
func TestRun_StartsAndStops(t *testing.T) {
	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	srv := server.New(server.Config{
		ListenAddress: addr,
		Version:       "1.0.0",
		// Provide a VaultStatus so the health endpoint returns 200 (unsealed).
		VaultStatus: func() string { return "unsealed" },
	})

	// Run in background
	runErr := make(chan error, 1)
	go func() {
		runErr <- srv.Run()
	}()

	// Wait for server to become ready (up to 2 seconds)
	url := fmt.Sprintf("http://%s/api/v1/health", addr)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server did not become ready within 2s: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from health endpoint, got %d", resp.StatusCode)
	}

	// Signal graceful shutdown via context cancellation on the server stop channel.
	// Since Run() blocks on signal, we send SIGINT programmatically via the stop method.
	if err := srv.Stop(context.Background()); err != nil {
		t.Errorf("Stop() returned error: %v", err)
	}

	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("Run() returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server did not stop within 5 seconds")
	}
}
