package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/vault"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mockBaoServer builds an httptest.Server that handles OpenBao-like API routes.
// The routes map maps URL path → handler func. Any unregistered path returns 404.
func mockBaoServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, handler := range routes {
		mux.HandleFunc(path, handler)
	}
	return httptest.NewServer(mux)
}

// jsonBody writes a JSON-encoded value as the response body with Content-Type set.
func jsonBody(t *testing.T, w http.ResponseWriter, code int, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("jsonBody: encode error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

// TestNewClient_SetsAddress verifies that NewClient stores the provided address.
func TestNewClient_SetsAddress(t *testing.T) {
	c := vault.NewClient("http://127.0.0.1:8200")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Address() != "http://127.0.0.1:8200" {
		t.Errorf("expected address http://127.0.0.1:8200, got %q", c.Address())
	}
}

// TestNewClient_NoToken verifies a freshly-created client has no token.
func TestNewClient_NoToken(t *testing.T) {
	c := vault.NewClient("http://127.0.0.1:8200")
	if c.Token() != "" {
		t.Errorf("expected empty token, got %q", c.Token())
	}
}

// TestSetToken verifies that SetToken stores the token and Token() returns it.
func TestSetToken_StoresToken(t *testing.T) {
	c := vault.NewClient("http://127.0.0.1:8200")
	c.SetToken("s.testtoken123")
	if c.Token() != "s.testtoken123" {
		t.Errorf("expected token s.testtoken123, got %q", c.Token())
	}
}

// ---------------------------------------------------------------------------
// IsHealthy
// ---------------------------------------------------------------------------

// TestIsHealthy_TrueWhenUnsealedAndActive verifies IsHealthy returns true when
// OpenBao /v1/sys/health returns 200 (initialized, unsealed, active).
func TestIsHealthy_TrueWhenUnsealedAndActive(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"initialized": true,
				"sealed":      false,
				"standby":     false,
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	if !c.IsHealthy() {
		t.Error("expected IsHealthy()=true for unsealed active node")
	}
}

// TestIsHealthy_FalseWhenServerDown verifies IsHealthy returns false when
// the OpenBao server is unreachable.
func TestIsHealthy_FalseWhenServerDown(t *testing.T) {
	c := vault.NewClient("http://127.0.0.1:19999") // nothing listening
	if c.IsHealthy() {
		t.Error("expected IsHealthy()=false when server is unreachable")
	}
}

// TestIsHealthy_FalseOnNon200 verifies IsHealthy returns false when the health
// endpoint returns a non-200 status (e.g., 429 = standby, 503 = sealed).
func TestIsHealthy_FalseOnNon200(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusServiceUnavailable, map[string]interface{}{
				"initialized": true,
				"sealed":      true,
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	if c.IsHealthy() {
		t.Error("expected IsHealthy()=false when health endpoint returns 503")
	}
}

// ---------------------------------------------------------------------------
// IsSealed
// ---------------------------------------------------------------------------

// TestIsSealed_TrueWhenSealed verifies IsSealed returns true when OpenBao reports
// the vault is sealed (HTTP 503 from health endpoint, sealed=true in body).
func TestIsSealed_TrueWhenSealed(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusServiceUnavailable, map[string]interface{}{
				"initialized": true,
				"sealed":      true,
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	sealed, err := c.IsSealed()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sealed {
		t.Error("expected IsSealed()=true")
	}
}

// TestIsSealed_FalseWhenUnsealed verifies IsSealed returns false when OpenBao is healthy.
func TestIsSealed_FalseWhenUnsealed(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/sys/health": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"initialized": true,
				"sealed":      false,
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	sealed, err := c.IsSealed()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sealed {
		t.Error("expected IsSealed()=false")
	}
}

// TestIsSealed_ErrorWhenUnreachable verifies IsSealed returns an error when the
// server is unreachable.
func TestIsSealed_ErrorWhenUnreachable(t *testing.T) {
	c := vault.NewClient("http://127.0.0.1:19999")
	_, err := c.IsSealed()
	if err == nil {
		t.Error("expected error when server is unreachable")
	}
}

// ---------------------------------------------------------------------------
// WriteSecret / ReadSecret
// ---------------------------------------------------------------------------

// TestWriteSecret_Success verifies that WriteSecret sends the correct payload
// and succeeds on a 200/204 response.
func TestWriteSecret_Success(t *testing.T) {
	var capturedBody map[string]interface{}

	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/data/services/myapp": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{"version": 1},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.testtoken")

	err := c.WriteSecret("services/myapp", map[string]interface{}{
		"api_key": "sk-1234",
	})
	if err != nil {
		t.Fatalf("WriteSecret returned unexpected error: %v", err)
	}

	// Verify payload wrapped in KV v2 "data" envelope
	if capturedBody["data"] == nil {
		t.Error("expected request body to have 'data' field (KV v2 format)")
	}
}

// TestWriteSecret_ReturnsErrorOnNon2xx verifies WriteSecret fails when the API
// returns an error status.
func TestWriteSecret_ReturnsErrorOnNon2xx(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/data/services/myapp": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusForbidden, map[string]interface{}{
				"errors": []string{"permission denied"},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.badtoken")

	err := c.WriteSecret("services/myapp", map[string]interface{}{"key": "val"})
	if err == nil {
		t.Fatal("expected error on 403 response, got nil")
	}
}

// TestReadSecret_Success verifies ReadSecret returns the secret data map.
func TestReadSecret_Success(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/data/services/myapp": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"api_key": "sk-1234",
					},
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.testtoken")

	data, err := c.ReadSecret("services/myapp")
	if err != nil {
		t.Fatalf("ReadSecret returned unexpected error: %v", err)
	}

	apiKey, ok := data["api_key"]
	if !ok {
		t.Fatal("expected 'api_key' in returned data")
	}
	if apiKey != "sk-1234" {
		t.Errorf("expected api_key=sk-1234, got %v", apiKey)
	}
}

// TestReadSecret_NotFound verifies ReadSecret returns an error on 404.
func TestReadSecret_NotFound(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/data/services/missing": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusNotFound, map[string]interface{}{
				"errors": []string{},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.testtoken")

	_, err := c.ReadSecret("services/missing")
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeleteSecret
// ---------------------------------------------------------------------------

// TestDeleteSecret_Success verifies DeleteSecret succeeds on 204.
func TestDeleteSecret_Success(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/data/services/myapp": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.testtoken")

	if err := c.DeleteSecret("services/myapp"); err != nil {
		t.Fatalf("DeleteSecret returned unexpected error: %v", err)
	}
}

// TestDeleteSecret_ReturnsErrorOnForbidden verifies DeleteSecret fails on 403.
func TestDeleteSecret_ReturnsErrorOnForbidden(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/data/services/myapp": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusForbidden, map[string]interface{}{
				"errors": []string{"permission denied"},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.badtoken")

	if err := c.DeleteSecret("services/myapp"); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListSecrets
// ---------------------------------------------------------------------------

// TestListSecrets_Success verifies ListSecrets returns the keys array.
func TestListSecrets_Success(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/metadata/services/": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("list") != "true" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			jsonBody(t, w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"github", "stripe", "openai"},
				},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.testtoken")

	keys, err := c.ListSecrets("services/")
	if err != nil {
		t.Fatalf("ListSecrets returned unexpected error: %v", err)
	}

	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	expected := map[string]bool{"github": true, "stripe": true, "openai": true}
	for _, k := range keys {
		if !expected[k] {
			t.Errorf("unexpected key %q in result", k)
		}
	}
}

// TestListSecrets_EmptyPrefix verifies ListSecrets handles an empty result gracefully.
func TestListSecrets_EmptyResult(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/secret/metadata/services/": func(w http.ResponseWriter, r *http.Request) {
			jsonBody(t, w, http.StatusNotFound, map[string]interface{}{
				"errors": []string{},
			})
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("s.testtoken")

	keys, err := c.ListSecrets("services/")
	if err != nil {
		t.Fatalf("ListSecrets returned unexpected error for empty path: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for 404 (empty path), got %d", len(keys))
	}
}
