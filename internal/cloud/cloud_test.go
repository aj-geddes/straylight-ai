// Package cloud_test contains tests for the cloud provider temporary credentials feature.
// All cloud API calls are mocked — no real cloud accounts are required.
package cloud_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/cloud"
)

// ---------------------------------------------------------------------------
// Provider interface compliance tests
// ---------------------------------------------------------------------------

// TestAWSProviderImplementsProvider verifies that AWSProvider satisfies the Provider interface.
func TestAWSProviderImplementsProvider(t *testing.T) {
	var _ cloud.Provider = (*cloud.AWSProvider)(nil)
}

// TestGCPProviderImplementsProvider verifies that GCPProvider satisfies the Provider interface.
func TestGCPProviderImplementsProvider(t *testing.T) {
	var _ cloud.Provider = (*cloud.GCPProvider)(nil)
}

// TestAzureProviderImplementsProvider verifies that AzureProvider satisfies the Provider interface.
func TestAzureProviderImplementsProvider(t *testing.T) {
	var _ cloud.Provider = (*cloud.AzureProvider)(nil)
}

// ---------------------------------------------------------------------------
// AWS provider tests
// ---------------------------------------------------------------------------

// TestAWSProviderCloudType verifies the provider reports "aws".
func TestAWSProviderCloudType(t *testing.T) {
	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: &mockSTSClient{},
	})
	if p.CloudType() != "aws" {
		t.Errorf("CloudType() = %q, want %q", p.CloudType(), "aws")
	}
}

// TestAWSProviderGeneratesCredentials verifies STS AssumeRole output maps
// correctly to env vars.
func TestAWSProviderGeneratesCredentials(t *testing.T) {
	mockSTS := &mockSTSClient{
		accessKeyID:     "ASIA1234567890ABCDEF",
		secretAccessKey: "mockSecretKey",
		sessionToken:    "mockSessionToken",
		expiration:      time.Now().Add(15 * time.Minute),
	}
	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: mockSTS,
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN:             "arn:aws:iam::123456789012:role/TestRole",
			Region:              "us-east-1",
			SessionDurationSecs: 900,
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	checkEnvVar(t, creds.EnvVars, "AWS_ACCESS_KEY_ID", "ASIA1234567890ABCDEF")
	checkEnvVar(t, creds.EnvVars, "AWS_SECRET_ACCESS_KEY", "mockSecretKey")
	checkEnvVar(t, creds.EnvVars, "AWS_SESSION_TOKEN", "mockSessionToken")
	checkEnvVar(t, creds.EnvVars, "AWS_DEFAULT_REGION", "us-east-1")

	if creds.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
	if creds.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", creds.Provider, "aws")
	}
}

// TestAWSProviderSTSError verifies that STS failures are surfaced as errors.
func TestAWSProviderSTSError(t *testing.T) {
	mockSTS := &mockSTSClient{
		err: errors.New("STS: access denied"),
	}
	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: mockSTS,
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN: "arn:aws:iam::123456789012:role/TestRole",
			Region:  "us-east-1",
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from STS failure, got nil")
	}
}

// TestAWSProviderMissingConfig verifies that missing AWS config returns an error.
func TestAWSProviderMissingConfig(t *testing.T) {
	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: &mockSTSClient{},
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		// AWS field is nil
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for missing AWS config, got nil")
	}
}

// TestAWSProviderRootCredentialsNeverInOutput verifies that the admin access key
// (AKIA*) format never appears in the temp credential env vars.
func TestAWSProviderRootCredentialsNeverInOutput(t *testing.T) {
	rootKey := "AKIAIOSFODNN7EXAMPLE"
	mockSTS := &mockSTSClient{
		accessKeyID:     "ASIA1234567890ABCDEF", // temp creds use ASIA prefix
		secretAccessKey: "tempSecretValue",
		sessionToken:    "tempSessionToken",
		expiration:      time.Now().Add(15 * time.Minute),
	}
	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: mockSTS,
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN: "arn:aws:iam::123456789012:role/TestRole",
			Region:  "us-east-1",
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	for k, v := range creds.EnvVars {
		if v == rootKey {
			t.Errorf("env var %q contains root credential value %q — root creds must never appear in output", k, rootKey)
		}
	}
}

// TestAWSProviderDefaultSessionDuration verifies that zero TTL defaults to 900s.
func TestAWSProviderDefaultSessionDuration(t *testing.T) {
	mockSTS := &mockSTSClient{
		accessKeyID:     "ASIA1234567890ABCDEF",
		secretAccessKey: "secret",
		sessionToken:    "token",
		expiration:      time.Now().Add(15 * time.Minute),
	}
	p := cloud.NewAWSProvider(cloud.AWSProviderConfig{
		STSClient: mockSTS,
	})

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN: "arn:aws:iam::123456789012:role/TestRole",
			Region:  "us-east-1",
			// SessionDurationSecs is 0 — should default to 900
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	if mockSTS.lastDurationSecs != 900 {
		t.Errorf("duration = %d, want 900 (default)", mockSTS.lastDurationSecs)
	}
}

// ---------------------------------------------------------------------------
// GCP provider tests
// ---------------------------------------------------------------------------

// TestGCPProviderCloudType verifies the provider reports "gcp".
func TestGCPProviderCloudType(t *testing.T) {
	srv := gcpTokenServer(t, "ya29.testtoken", 3600)
	defer srv.Close()

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{
		TokenEndpointOverride: srv.URL,
	})
	if p.CloudType() != "gcp" {
		t.Errorf("CloudType() = %q, want %q", p.CloudType(), "gcp")
	}
}

// TestGCPProviderGeneratesAccessToken verifies that the GCP provider returns a
// CLOUDSDK_AUTH_ACCESS_TOKEN env var and a non-zero expiry.
func TestGCPProviderGeneratesAccessToken(t *testing.T) {
	srv := gcpTokenServer(t, "ya29.testGCPAccessToken", 3600)
	defer srv.Close()

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{
		TokenEndpointOverride: srv.URL,
	})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: validServiceAccountJSON(t, srv.URL),
			ProjectID:          "my-project",
			Scopes:             []string{"https://www.googleapis.com/auth/cloud-platform"},
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	checkEnvVar(t, creds.EnvVars, "CLOUDSDK_AUTH_ACCESS_TOKEN", "ya29.testGCPAccessToken")
	checkEnvVar(t, creds.EnvVars, "CLOUDSDK_CORE_PROJECT", "my-project")

	if creds.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
	if creds.Provider != "gcp" {
		t.Errorf("Provider = %q, want %q", creds.Provider, "gcp")
	}
}

// TestGCPProviderServiceAccountJSONNeverInOutput verifies that the service
// account JSON private key never appears in the credential env vars.
func TestGCPProviderServiceAccountJSONNeverInOutput(t *testing.T) {
	srv := gcpTokenServer(t, "ya29.testToken", 3600)
	defer srv.Close()

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{
		TokenEndpointOverride: srv.URL,
	})

	saJSON := validServiceAccountJSON(t, srv.URL)
	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: saJSON,
			ProjectID:          "my-project",
			Scopes:             []string{"https://www.googleapis.com/auth/cloud-platform"},
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	for k, v := range creds.EnvVars {
		if v == saJSON {
			t.Errorf("env var %q contains raw service account JSON — it must never appear in output", k)
		}
	}
}

// TestGCPProviderMissingConfig verifies that missing GCP config returns an error.
func TestGCPProviderMissingConfig(t *testing.T) {
	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		// GCP field is nil
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for missing GCP config, got nil")
	}
}

// TestGCPProviderTokenEndpointError verifies that token endpoint failures surface as errors.
func TestGCPProviderTokenEndpointError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := cloud.NewGCPProvider(cloud.GCPProviderConfig{
		TokenEndpointOverride: srv.URL,
	})

	cfg := cloud.ServiceConfig{
		Engine: "gcp",
		GCP: &cloud.GCPConfig{
			ServiceAccountJSON: validServiceAccountJSON(t, srv.URL),
			ProjectID:          "my-project",
			Scopes:             []string{"https://www.googleapis.com/auth/cloud-platform"},
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from token endpoint failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Azure provider tests
// ---------------------------------------------------------------------------

// TestAzureProviderCloudType verifies the provider reports "azure".
func TestAzureProviderCloudType(t *testing.T) {
	srv := azureTokenServer(t, "azure_access_token_value")
	defer srv.Close()

	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{
		TokenEndpointOverride: srv.URL,
	})
	if p.CloudType() != "azure" {
		t.Errorf("CloudType() = %q, want %q", p.CloudType(), "azure")
	}
}

// TestAzureProviderGeneratesToken verifies that the Azure provider returns
// credential env vars and a non-zero expiry.
func TestAzureProviderGeneratesToken(t *testing.T) {
	srv := azureTokenServer(t, "azure_access_token_value")
	defer srv.Close()

	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{
		TokenEndpointOverride: srv.URL,
	})

	cfg := cloud.ServiceConfig{
		Engine: "azure",
		Azure: &cloud.AzureConfig{
			TenantID:       "test-tenant-id",
			ClientID:       "test-client-id",
			ClientSecret:   "test-client-secret",
			SubscriptionID: "test-subscription-id",
			Scope:          "https://management.azure.com/.default",
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	// Access token should be injected.
	if _, ok := creds.EnvVars["AZURE_ACCESS_TOKEN"]; !ok {
		t.Error("AZURE_ACCESS_TOKEN env var not set")
	}
	checkEnvVar(t, creds.EnvVars, "AZURE_TENANT_ID", "test-tenant-id")
	checkEnvVar(t, creds.EnvVars, "AZURE_SUBSCRIPTION_ID", "test-subscription-id")

	if creds.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero")
	}
	if creds.Provider != "azure" {
		t.Errorf("Provider = %q, want %q", creds.Provider, "azure")
	}
}

// TestAzureProviderClientSecretNeverInOutput verifies that the service principal
// client secret never appears in the returned env vars.
func TestAzureProviderClientSecretNeverInOutput(t *testing.T) {
	srv := azureTokenServer(t, "azure_token")
	defer srv.Close()

	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{
		TokenEndpointOverride: srv.URL,
	})

	secretValue := "super-secret-client-secret-value"
	cfg := cloud.ServiceConfig{
		Engine: "azure",
		Azure: &cloud.AzureConfig{
			TenantID:     "test-tenant",
			ClientID:     "test-client",
			ClientSecret: secretValue,
			Scope:        "https://management.azure.com/.default",
		},
	}

	creds, err := p.GenerateCredentials(context.Background(), cfg)
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}

	for k, v := range creds.EnvVars {
		if v == secretValue {
			t.Errorf("env var %q contains client secret — it must never appear in output", k)
		}
	}
}

// TestAzureProviderMissingConfig verifies that missing Azure config returns an error.
func TestAzureProviderMissingConfig(t *testing.T) {
	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{})

	cfg := cloud.ServiceConfig{
		Engine: "azure",
		// Azure field is nil
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for missing Azure config, got nil")
	}
}

// TestAzureProviderTokenEndpointError verifies that token endpoint failures surface as errors.
func TestAzureProviderTokenEndpointError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := cloud.NewAzureProvider(cloud.AzureProviderConfig{
		TokenEndpointOverride: srv.URL,
	})

	cfg := cloud.ServiceConfig{
		Engine: "azure",
		Azure: &cloud.AzureConfig{
			TenantID:     "test-tenant",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Scope:        "https://management.azure.com/.default",
		},
	}

	_, err := p.GenerateCredentials(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from token endpoint failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// Manager tests
// ---------------------------------------------------------------------------

// TestManagerGetFromCacheOnHit verifies that a second call within TTL reuses
// the cached credentials and does NOT call the provider again.
func TestManagerGetFromCacheOnHit(t *testing.T) {
	callCount := 0
	mockProvider := &countingProvider{
		creds: &cloud.Credentials{
			EnvVars:   map[string]string{"AWS_ACCESS_KEY_ID": "ASIA111"},
			ExpiresAt: time.Now().Add(15 * time.Minute),
			Provider:  "aws",
		},
		onCall: func() { callCount++ },
	}

	mgr := cloud.NewManager(map[string]cloud.Provider{"aws": mockProvider})

	cfg := cloud.ServiceConfig{Engine: "aws", AWS: &cloud.AWSConfig{RoleARN: "arn:aws:iam::123456789012:role/R"}}

	_, err := mgr.GetCredentials(context.Background(), "my-aws-svc", cfg)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	_, err = mgr.GetCredentials(context.Background(), "my-aws-svc", cfg)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("provider called %d times, want 1 (second call should hit cache)", callCount)
	}
}

// TestManagerRefreshesExpiredCredentials verifies that expired cached credentials
// trigger a new provider call.
func TestManagerRefreshesExpiredCredentials(t *testing.T) {
	callCount := 0
	mockProvider := &countingProvider{
		creds: &cloud.Credentials{
			EnvVars:   map[string]string{"AWS_ACCESS_KEY_ID": "ASIA111"},
			ExpiresAt: time.Now().Add(-1 * time.Second), // already expired
			Provider:  "aws",
		},
		onCall: func() { callCount++ },
	}

	mgr := cloud.NewManager(map[string]cloud.Provider{"aws": mockProvider})
	cfg := cloud.ServiceConfig{Engine: "aws", AWS: &cloud.AWSConfig{RoleARN: "arn:aws:iam::123456789012:role/R"}}

	_, err := mgr.GetCredentials(context.Background(), "my-aws-svc", cfg)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	_, err = mgr.GetCredentials(context.Background(), "my-aws-svc", cfg)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("provider called %d times, want 2 (expired creds should trigger refresh)", callCount)
	}
}

// TestManagerUnknownEngine verifies that an unsupported engine returns an error.
func TestManagerUnknownEngine(t *testing.T) {
	mgr := cloud.NewManager(map[string]cloud.Provider{})

	cfg := cloud.ServiceConfig{Engine: "oracle-cloud"}
	_, err := mgr.GetCredentials(context.Background(), "my-svc", cfg)
	if err == nil {
		t.Fatal("expected error for unknown engine, got nil")
	}
}

// ---------------------------------------------------------------------------
// Helper: mock STS client
// ---------------------------------------------------------------------------

// STSAssumeRoleInput mirrors the essential fields from the AWS SDK input.
type STSAssumeRoleInput struct {
	RoleARN         string
	SessionName     string
	DurationSeconds int32
	Policy          *string
}

// mockSTSClient is the mock for the STSClient interface.
type mockSTSClient struct {
	accessKeyID      string
	secretAccessKey  string
	sessionToken     string
	expiration       time.Time
	err              error
	lastDurationSecs int32
}

func (m *mockSTSClient) AssumeRole(_ context.Context, input cloud.STSAssumeRoleInput) (*cloud.STSCredentials, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.lastDurationSecs = input.DurationSeconds
	return &cloud.STSCredentials{
		AccessKeyID:     m.accessKeyID,
		SecretAccessKey: m.secretAccessKey,
		SessionToken:    m.sessionToken,
		Expiration:      m.expiration,
	}, nil
}

// ---------------------------------------------------------------------------
// Helper: counting provider
// ---------------------------------------------------------------------------

type countingProvider struct {
	creds  *cloud.Credentials
	err    error
	onCall func()
}

func (p *countingProvider) GenerateCredentials(_ context.Context, _ cloud.ServiceConfig) (*cloud.Credentials, error) {
	if p.onCall != nil {
		p.onCall()
	}
	if p.err != nil {
		return nil, p.err
	}
	return p.creds, nil
}

func (p *countingProvider) CloudType() string { return "aws" }

// ---------------------------------------------------------------------------
// Helper: GCP mock token server
// ---------------------------------------------------------------------------

func gcpTokenServer(t *testing.T, token string, expiresIn int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// validServiceAccountJSON returns a minimal service account JSON that points
// its token_uri at the given server URL.
func validServiceAccountJSON(t *testing.T, tokenURI string) string {
	t.Helper()
	sa := map[string]interface{}{
		"type":                        "service_account",
		"project_id":                  "test-project",
		"private_key_id":              "key123",
		"private_key":                 testRSAKey,
		"client_email":                "test@test-project.iam.gserviceaccount.com",
		"client_id":                   "123456789",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   tokenURI,
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/test",
	}
	b, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal service account JSON: %v", err)
	}
	return string(b)
}

// testRSAKey is a 2048-bit RSA private key for testing only (not used for real crypto).
const testRSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29Xi9V0gzTzpRI
y3WiEgBZVMsCo3LQEt5VWxPAbkbX4GQFQV3WbNPKAUDTRPa4g1kSjBvAHN6aSEp
v6PH8uaHBPFvV8aeANBdBq3kHEj2AAAA17JNHV7mJz+bpCNsupQzfxQxO5tOHYl
RTl3hfnP6G7MstI2ADi4RXh5gqkW9SKzeMsR5bO9IEWqAyNTY9FP2vBuNnvEK4cM
LNdFnFI1WxfpMw6jvkzADwlJ9gDHT+JYALB/X4w1TNqtOkPvTOV0vZ2V5G7cFoJ
sEjnDNy+NZ47b5bV2PPPU7TlYdJBwUdYUL5D5wIDAQABAoIBAHi4kE3gABBVl2EX
wt2/d1QHPGV3xSYm+oR1AhRN3OZbHMKKqNaOdHE7J+MBV0E7VQqb3dD4Q7VPQKP
MTHWgceFzAp1J9/F1BPBN1pVnHflU+sGkFEy0Z5gkV3ViD0sQ1UhFPlvNj6DBJHB
K/8xK2hGhI+8FVzqCnkMZ5oXQFEWv3s8YuSWx6f+t3uo6kST4j1Q9wFJB22Z2J6i
8D4oIxVj9X9V8c3OZ7BqT9Y9Ek0Cq6F+xvh1kfxCCi3+7R6PFMZ1J8QHDF/J6hn
WqKbQ7X5EuvmFMV9s5bBFvVNxe8P0HA4bk7vB7Ns7JJJ+QOoFT4E+VaHwAOcV6sC
gYEA7TqE2RHBb/zl9eOnijBHsPuAvxn4XC11nefU53rMH/eM+Nd8N7t0TQIV5wPx
VQNpkTd2V1PPWJ8/CxXQGOlgDl0EZ1VrXOcBWP7W7j3D7nL/AoGBAOsupxI6JaAb
6bI0wHRNZ+H0oqpx9o1N6xSdGvTrm9q1WFDPCPMxkqzpE9RNHiF1Sxs9L/MhRNkj
KGzXJ0WV7Z0jME5qoNAhO0n0N9KA5LYRR/RL8g6HH+N8CNPN7YmqNvMrO0RMLSL
y1qE4O9yCnXlB0fCAoGBAJCOQfqIOhGBV4r1T4uQSfXE/+FY7j2d3pHN1wfO+VTO
n9RYD7pPr5BFbFV3JZJNh4Yk9H2/nO5L5k8zO0X6tHN4r2a1F4WB+q3K+4Z7kVLM
oM8+rF8N7Y/e3dVj2lJLs6/cCx7Y4mWJ5c3hN0uCBNnp6wk5g6Ax3KtAoGBALsxb
PfWgT7H9aKhDlZ4pQ3j9Lw+FZmKNf7cH3DP1P4z+P2gBa3MjJ2PCNA0P7V1K0Fkx
wqVLHHX6U+xJ/0qQ7ZDMMT0iqVs5i0P8VQHH9mXs+F1K4t5g3W3hD4+lUlPn+4g
OFcLgP2GHhBjH0m1U6m1ZRL/oZJt5J8AoGBALNXfXqiF2P4lW5jB/FkSjKXF1JZe
K/gA1h0PL3NSTM3kInBKFjJU1iqcNz4k6t3VR4E7G4lmVGnXYYq3PLKXV6fJxEKP
kkAZiCL1KHi1VNaV7HBjn5Nf6Xb2ZJ0TGjEj9CyGl6HJTkpyPJpJeKwlAhFJPlhP
kCWc0i1Y
-----END RSA PRIVATE KEY-----`

// ---------------------------------------------------------------------------
// Helper: Azure mock token server
// ---------------------------------------------------------------------------

func azureTokenServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   "3600",
			"ext_expires_in": "3600",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// ---------------------------------------------------------------------------
// Assert helpers
// ---------------------------------------------------------------------------

func checkEnvVar(t *testing.T, envVars map[string]string, key, want string) {
	t.Helper()
	got, ok := envVars[key]
	if !ok {
		t.Errorf("env var %q not present in credentials", key)
		return
	}
	if got != want {
		t.Errorf("env var %q = %q, want %q", key, got, want)
	}
}
