package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/vault"
)

func TestConfigureIdentityIssuer_EmptyURL(t *testing.T) {
	addr := "http://127.0.0.1:8200"
	c := vault.NewClient(addr)
	c.SetToken("root-token")

	err := c.ConfigureIdentityIssuer("")
	if err == nil || !strings.Contains(err.Error(), "issuer URL must not be empty") {
		t.Fatalf("expected 'issuer URL must not be empty', got %v", err)
	}
}

func TestConfigureIdentityIssuer_Success(t *testing.T) {
	var receivedBody map[string]any
	server := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/config": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer server.Close()

	c := vault.NewClient(server.URL)
	c.SetToken("root-token")

	err := c.ConfigureIdentityIssuer("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Handler was called (verified by receivedBody being non-nil) and no error.
	if receivedBody == nil {
		t.Error("expected handler to receive a body")
	}
}

func TestConfigureIdentityIssuer_HTTPError(t *testing.T) {
	server := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/config": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	defer server.Close()

	c := vault.NewClient(server.URL)
	c.SetToken("root-token")

	err := c.ConfigureIdentityIssuer("https://example.com")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected '500', got %v", err)
	}
}

func TestCreateIdentityRole_EmptyName(t *testing.T) {
	addr := "http://127.0.0.1:8200"
	c := vault.NewClient(addr)
	c.SetToken("root-token")

	err := c.CreateIdentityRole("", nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "role name must not be empty") {
		t.Fatalf("expected 'role name must not be empty', got %v", err)
	}
}

func TestCreateIdentityRole_Success(t *testing.T) {
	var receivedBody map[string]any
	server := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/role/straylight": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer server.Close()

	c := vault.NewClient(server.URL)
	c.SetToken("root-token")

	err := c.CreateIdentityRole("straylight", []string{"sts.amazonaws.com"}, "1h", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody["ttl"] != "1h" {
		t.Errorf("expected ttl='1h', got %v", receivedBody["ttl"])
	}
}

func TestCreateIdentityRole_HTTPError(t *testing.T) {
	server := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/role/straylight": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		},
	})
	defer server.Close()

	c := vault.NewClient(server.URL)
	c.SetToken("root-token")

	err := c.CreateIdentityRole("straylight", nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected '400', got %v", err)
	}
}

func TestGenerateIdentityToken_EmptyRole(t *testing.T) {
	addr := "http://127.0.0.1:8200"
	c := vault.NewClient(addr)
	c.SetToken("root-token")

	_, _, err := c.GenerateIdentityToken("", "sts.amazonaws.com")
	if err == nil || !strings.Contains(err.Error(), "role must not be empty") {
		t.Fatalf("expected 'role must not be empty', got %v", err)
	}
}

func TestGenerateIdentityToken_Success(t *testing.T) {
	var receivedBody map[string]any
	server := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/token/straylight": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			json.NewDecoder(r.Body).Decode(&receivedBody)
			jsonBody(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{
					"token":       "eyJhbGc.e30.sig",
					"expire_time": "2099-01-01T00:00:00Z",
				},
			})
		},
	})
	defer server.Close()

	c := vault.NewClient(server.URL)
	c.SetToken("root-token")

	token, expiresAt, err := c.GenerateIdentityToken("straylight", "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "eyJhbGc.e30.sig" {
		t.Errorf("expected token='eyJhbGc.e30.sig', got %v", token)
	}
	if expiresAt.Year() != 2099 {
		t.Errorf("expected expiresAt.Year()=2099, got %d", expiresAt.Year())
	}
	if receivedBody["audience"] != "sts.amazonaws.com" {
		t.Errorf("expected audience='sts.amazonaws.com', got %v", receivedBody["audience"])
	}
}

func TestGenerateIdentityToken_HTTPError(t *testing.T) {
	server := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/token/straylight": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		},
	})
	defer server.Close()

	c := vault.NewClient(server.URL)
	c.SetToken("root-token")

	_, _, err := c.GenerateIdentityToken("straylight", "sts.amazonaws.com")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected '403', got %v", err)
	}
}

func TestFetchPublicJWKS_Success(t *testing.T) {
	server := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/.well-known/keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			jsonBody(t, w, http.StatusOK, map[string]any{
				"keys": []map[string]any{
					{"kty": "RSA", "kid": "k1"},
				},
			})
		},
	})
	defer server.Close()

	c := vault.NewClient(server.URL)
	c.SetToken("root-token")

	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kty != "RSA" {
		t.Errorf("expected Kty='RSA', got %v", jwks.Keys[0].Kty)
	}
}

func TestFetchPublicJWKS_HTTPError(t *testing.T) {
	server := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/.well-known/keys": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
	})
	defer server.Close()

	c := vault.NewClient(server.URL)
	c.SetToken("root-token")

	_, err := c.FetchPublicJWKS()
	if err == nil {
		t.Fatalf("expected non-nil error")
	}
}

func TestFetchPublicJWKS_NeverSendsVaultToken(t *testing.T) {
	var gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Vault-Token")
		if r.URL.Path == "/v1/identity/oidc/.well-known/keys" {
			jsonBody(t, w, http.StatusOK, map[string]any{
				"keys": []map[string]any{
					{"kty": "RSA", "kid": "k1"},
				},
			})
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := vault.NewClient(server.URL)
	// Intentionally NOT calling SetToken

	_, err := c.FetchPublicJWKS()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotHeader != "" {
		t.Errorf("expected X-Vault-Token header to be empty, got %q", gotHeader)
	}
}

// TestFetchPublicJWKS_BadJSON verifies that malformed JSON in the JWKS response
// propagates as a non-nil error.
func TestFetchPublicJWKS_BadJSON(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/.well-known/keys": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{not-valid-json"))
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	_, err := c.FetchPublicJWKS()
	if err == nil {
		t.Fatal("expected error for bad JSON, got nil")
	}
}

// TestGenerateIdentityToken_BadJSON verifies that malformed JSON in the token
// response propagates as a non-nil error.
func TestGenerateIdentityToken_BadJSON(t *testing.T) {
	srv := mockBaoServer(t, map[string]http.HandlerFunc{
		"/v1/identity/oidc/token/straylight": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{invalid"))
		},
	})
	defer srv.Close()

	c := vault.NewClient(srv.URL)
	c.SetToken("root")
	_, _, err := c.GenerateIdentityToken("straylight", "aud")
	if err == nil {
		t.Fatal("expected error for bad JSON, got nil")
	}
}
