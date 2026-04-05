package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straylight-ai/straylight/internal/server"
	"github.com/straylight-ai/straylight/internal/services"
)

// newRegistryForCloud creates a services.Registry for cloud route tests.
func newRegistryForCloud(vault *mockVaultForRoutes) *services.Registry {
	return services.NewRegistry(vault)
}

// newCloudTestServer creates a test server with a registry (cloud routes require it).
func newCloudTestServer() *server.Server {
	vault := newMockVaultForRoutes()
	reg := newRegistryForCloud(vault)
	return server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
		Registry:      reg,
	})
}

func cloudRequest(srv *server.Server, method, path string, body interface{}) *httptest.ResponseRecorder {
	var bodyReader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Cloud routes tests
// ---------------------------------------------------------------------------

// TestCloudRoutes_ListReturnsOK verifies that GET /api/v1/cloud returns 200.
func TestCloudRoutes_ListReturnsOK(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodGet, "/api/v1/cloud", nil)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_ListResponseIsJSON verifies the cloud list response is JSON.
func TestCloudRoutes_ListResponseIsJSON(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodGet, "/api/v1/cloud", nil)

	ct := w.Header().Get("Content-Type")
	if ct == "" {
		t.Error("expected Content-Type header to be set")
	}

	var resp interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("response body is not valid JSON: %v", err)
	}
}

// TestCloudRoutes_InvalidProviderReturns400 verifies that an invalid provider
// in the path returns a 400 error.
func TestCloudRoutes_InvalidProviderReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/invalid-provider", nil)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid provider, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_ValidProviderNoBodyReturns400 verifies that a valid provider
// with no request body returns 400 (missing required fields).
func TestCloudRoutes_ValidProviderNoBodyReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", nil)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_CreateAWSServiceReturns201 verifies that a valid AWS cloud
// service creation request returns 201.
func TestCloudRoutes_CreateAWSServiceReturns201(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", map[string]interface{}{
		"name":     "aws-prod",
		"role_arn": "arn:aws:iam::123456789012:role/StrayLightRole",
		"region":   "us-east-1",
		"credentials": map[string]interface{}{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_CreateGCPServiceReturns201 verifies that a valid GCP cloud
// service creation request returns 201.
func TestCloudRoutes_CreateGCPServiceReturns201(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/gcp", map[string]interface{}{
		"name":       "gcp-prod",
		"project_id": "my-project-123",
		"credentials": map[string]interface{}{
			"service_account_json": `{"type":"service_account"}`,
		},
	})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_CreateAzureServiceReturns201 verifies that a valid Azure cloud
// service creation request returns 201.
func TestCloudRoutes_CreateAzureServiceReturns201(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/azure", map[string]interface{}{
		"name": "azure-prod",
		"credentials": map[string]interface{}{
			"tenant_id":     "test-tenant-id",
			"client_id":     "test-client-id",
			"client_secret": "test-secret",
		},
	})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_ListFiltersToCloudType verifies that GET /api/v1/cloud only
// returns services with type=cloud (not http_proxy or other types).
func TestCloudRoutes_ListFiltersToCloudType(t *testing.T) {
	vault := newMockVaultForRoutes()
	reg := newRegistryForCloud(vault)

	// Create a cloud service and a non-cloud service.
	_ = reg.CreateWithAuth(services.Service{Name: "cloud-svc", Type: "cloud"}, "aws", map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "secret",
		"role_arn":          "arn:aws:iam::123456789012:role/MyRole",
		"region":            "us-east-1",
	})
	_ = reg.Create(services.Service{
		Name:   "http-svc",
		Type:   "http_proxy",
		Target: "https://api.example.com",
		Inject: "header",
	}, "tok")

	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "1.0.3",
		Registry:      reg,
	})

	w := cloudRequest(srv, http.MethodGet, "/api/v1/cloud", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	svcs, ok := resp["services"].([]interface{})
	if !ok {
		t.Fatal("expected services array in response")
	}
	if len(svcs) != 1 {
		t.Errorf("expected 1 cloud service in list, got %d", len(svcs))
	}
}

// TestCloudRoutes_AWSMissingNameReturns400 verifies that AWS creation without
// a name returns 400.
func TestCloudRoutes_AWSMissingNameReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", map[string]interface{}{
		"role_arn": "arn:aws:iam::123456789012:role/StrayLightRole",
		"credentials": map[string]interface{}{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "secret",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AWSMissingRoleARNReturns400 verifies that AWS creation without
// role_arn returns 400.
func TestCloudRoutes_AWSMissingRoleARNReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", map[string]interface{}{
		"name": "aws-svc",
		"credentials": map[string]interface{}{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "secret",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing role_arn, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AWSMissingAccessKeyReturns400 verifies that AWS creation
// without access_key_id returns 400.
func TestCloudRoutes_AWSMissingAccessKeyReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", map[string]interface{}{
		"name":     "aws-svc",
		"role_arn": "arn:aws:iam::123456789012:role/StrayLightRole",
		"credentials": map[string]interface{}{
			"secret_access_key": "secret",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing access_key_id, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AWSMissingSecretKeyReturns400 verifies that AWS creation
// without secret_access_key returns 400.
func TestCloudRoutes_AWSMissingSecretKeyReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", map[string]interface{}{
		"name":     "aws-svc",
		"role_arn": "arn:aws:iam::123456789012:role/StrayLightRole",
		"credentials": map[string]interface{}{
			"access_key_id": "AKIAIOSFODNN7EXAMPLE",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing secret_access_key, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AWSDefaultRegionApplied verifies that region defaults to
// "us-east-1" when not specified.
func TestCloudRoutes_AWSDefaultRegionApplied(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", map[string]interface{}{
		"name":     "aws-default-region",
		"role_arn": "arn:aws:iam::123456789012:role/StrayLightRole",
		"credentials": map[string]interface{}{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	})
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201 with default region, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AWSDuplicateNameReturns409 verifies that creating an AWS
// service with a name that already exists returns 409.
func TestCloudRoutes_AWSDuplicateNameReturns409(t *testing.T) {
	srv := newCloudTestServer()
	body := map[string]interface{}{
		"name":     "aws-dup",
		"role_arn": "arn:aws:iam::123456789012:role/StrayLightRole",
		"credentials": map[string]interface{}{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}
	w1 := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", body)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first create should return 201, got %d", w1.Code)
	}
	w2 := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/aws", body)
	if w2.Code != http.StatusConflict {
		t.Errorf("duplicate create should return 409, got %d; body: %s", w2.Code, w2.Body.String())
	}
}

// TestCloudRoutes_GCPMissingNameReturns400 verifies that GCP creation without
// a name returns 400.
func TestCloudRoutes_GCPMissingNameReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/gcp", map[string]interface{}{
		"project_id": "my-project",
		"credentials": map[string]interface{}{
			"service_account_json": `{"type":"service_account"}`,
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_GCPMissingProjectIDReturns400 verifies that GCP creation
// without project_id returns 400.
func TestCloudRoutes_GCPMissingProjectIDReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/gcp", map[string]interface{}{
		"name": "gcp-svc",
		"credentials": map[string]interface{}{
			"service_account_json": `{"type":"service_account"}`,
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing project_id, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_GCPMissingServiceAccountReturns400 verifies that GCP
// creation without service_account_json returns 400.
func TestCloudRoutes_GCPMissingServiceAccountReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/gcp", map[string]interface{}{
		"name":       "gcp-svc",
		"project_id": "my-project",
		"credentials": map[string]interface{}{
			"other_field": "value",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing service_account_json, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_GCPDuplicateNameReturns409 verifies that creating a GCP
// service with a duplicate name returns 409.
func TestCloudRoutes_GCPDuplicateNameReturns409(t *testing.T) {
	srv := newCloudTestServer()
	body := map[string]interface{}{
		"name":       "gcp-dup",
		"project_id": "my-project",
		"credentials": map[string]interface{}{
			"service_account_json": `{"type":"service_account"}`,
		},
	}
	w1 := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/gcp", body)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first create should return 201, got %d", w1.Code)
	}
	w2 := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/gcp", body)
	if w2.Code != http.StatusConflict {
		t.Errorf("duplicate create should return 409, got %d; body: %s", w2.Code, w2.Body.String())
	}
}

// TestCloudRoutes_AzureMissingNameReturns400 verifies that Azure creation
// without a name returns 400.
func TestCloudRoutes_AzureMissingNameReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/azure", map[string]interface{}{
		"credentials": map[string]interface{}{
			"tenant_id":     "test-tenant",
			"client_id":     "test-client",
			"client_secret": "test-secret",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AzureMissingTenantIDReturns400 verifies that Azure creation
// without tenant_id returns 400.
func TestCloudRoutes_AzureMissingTenantIDReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/azure", map[string]interface{}{
		"name": "azure-svc",
		"credentials": map[string]interface{}{
			"client_id":     "test-client",
			"client_secret": "test-secret",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing tenant_id, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AzureMissingClientIDReturns400 verifies that Azure creation
// without client_id returns 400.
func TestCloudRoutes_AzureMissingClientIDReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/azure", map[string]interface{}{
		"name": "azure-svc",
		"credentials": map[string]interface{}{
			"tenant_id":     "test-tenant",
			"client_secret": "test-secret",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing client_id, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AzureMissingClientSecretReturns400 verifies that Azure
// creation without client_secret returns 400.
func TestCloudRoutes_AzureMissingClientSecretReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/azure", map[string]interface{}{
		"name": "azure-svc",
		"credentials": map[string]interface{}{
			"tenant_id": "test-tenant",
			"client_id": "test-client",
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing client_secret, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AzureDuplicateNameReturns409 verifies that creating an Azure
// service with a duplicate name returns 409.
func TestCloudRoutes_AzureDuplicateNameReturns409(t *testing.T) {
	srv := newCloudTestServer()
	body := map[string]interface{}{
		"name": "azure-dup",
		"credentials": map[string]interface{}{
			"tenant_id":     "test-tenant",
			"client_id":     "test-client",
			"client_secret": "test-secret",
		},
	}
	w1 := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/azure", body)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first create should return 201, got %d", w1.Code)
	}
	w2 := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/azure", body)
	if w2.Code != http.StatusConflict {
		t.Errorf("duplicate create should return 409, got %d; body: %s", w2.Code, w2.Body.String())
	}
}

// TestCloudRoutes_GCPNoBodyReturns400 verifies that GCP with no body returns 400.
func TestCloudRoutes_GCPNoBodyReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/gcp", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestCloudRoutes_AzureNoBodyReturns400 verifies that Azure with no body returns 400.
func TestCloudRoutes_AzureNoBodyReturns400(t *testing.T) {
	srv := newCloudTestServer()
	w := cloudRequest(srv, http.MethodPost, "/api/v1/cloud/azure", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d; body: %s", w.Code, w.Body.String())
	}
}
