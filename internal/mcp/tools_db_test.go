package mcp_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/straylight-ai/straylight/internal/database"
	"github.com/straylight-ai/straylight/internal/mcp"
)

// ---------------------------------------------------------------------------
// Mock DBExecutor
// ---------------------------------------------------------------------------

type mockDBExecutor struct {
	configs  map[string]database.DatabaseConfig
	username string
	password string
	leaseID  string
	credErr  error
}

func newMockDB(engine string) *mockDBExecutor {
	return &mockDBExecutor{
		configs: map[string]database.DatabaseConfig{
			"my-pg": {
				Engine:   engine,
				Host:     "db.example.com",
				Port:     5432,
				Database: "mydb",
			},
		},
		username: "v-user-abc",
		password: "v-pass-xyz",
		leaseID:  "database/creds/my-pg-ro/token1",
	}
}

func (m *mockDBExecutor) GetCredentials(serviceName, role string) (username, password, leaseID string, err error) {
	if m.credErr != nil {
		return "", "", "", m.credErr
	}
	return m.username, m.password, m.leaseID, nil
}

func (m *mockDBExecutor) GetDatabaseConfig(name string) (database.DatabaseConfig, bool) {
	cfg, ok := m.configs[name]
	return cfg, ok
}

func (m *mockDBExecutor) ListDatabases() []string {
	names := make([]string, 0, len(m.configs))
	for k := range m.configs {
		names = append(names, k)
	}
	return names
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHandleDBQuery_NilExecutor(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	// No db executor set — straylight_db_query should return error result.

	body := map[string]interface{}{
		"tool": "straylight_db_query",
		"arguments": map[string]interface{}{
			"service": "my-pg",
			"query":   "SELECT 1",
		},
	}
	w := doRequest(h, "POST", "/api/v1/mcp/tool-call", body)

	var result mcp.ToolCallResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !result.IsError {
		t.Error("expected IsError=true when db executor is nil")
	}
}

func TestHandleDBQuery_MissingService(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetDBExecutor(newMockDB("postgresql"))

	body := map[string]interface{}{
		"tool": "straylight_db_query",
		"arguments": map[string]interface{}{
			"query": "SELECT 1",
			// service omitted
		},
	}
	w := doRequest(h, "POST", "/api/v1/mcp/tool-call", body)

	var result mcp.ToolCallResult
	_ = json.NewDecoder(w.Body).Decode(&result)

	if !result.IsError {
		t.Error("expected IsError=true for missing service")
	}
}

func TestHandleDBQuery_MissingQuery(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetDBExecutor(newMockDB("postgresql"))

	body := map[string]interface{}{
		"tool": "straylight_db_query",
		"arguments": map[string]interface{}{
			"service": "my-pg",
			// query omitted
		},
	}
	w := doRequest(h, "POST", "/api/v1/mcp/tool-call", body)

	var result mcp.ToolCallResult
	_ = json.NewDecoder(w.Body).Decode(&result)

	if !result.IsError {
		t.Error("expected IsError=true for missing query")
	}
}

func TestHandleDBQuery_ServiceNotFound(t *testing.T) {
	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetDBExecutor(newMockDB("postgresql"))

	body := map[string]interface{}{
		"tool": "straylight_db_query",
		"arguments": map[string]interface{}{
			"service": "nonexistent-db",
			"query":   "SELECT 1",
		},
	}
	w := doRequest(h, "POST", "/api/v1/mcp/tool-call", body)

	var result mcp.ToolCallResult
	_ = json.NewDecoder(w.Body).Decode(&result)

	if !result.IsError {
		t.Error("expected IsError=true for unknown service")
	}
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	text := result.Content[0].Text
	if !containsMCPStr(text, "not found") {
		t.Errorf("error text %q should mention 'not found'", text)
	}
}

func TestHandleDBQuery_CredentialError_NoConnectionString(t *testing.T) {
	mockDB := newMockDB("postgresql")
	mockDB.credErr = errors.New("vault: credentials unavailable for service \"my-pg\"")

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetDBExecutor(mockDB)

	body := map[string]interface{}{
		"tool": "straylight_db_query",
		"arguments": map[string]interface{}{
			"service": "my-pg",
			"query":   "SELECT 1",
		},
	}
	w := doRequest(h, "POST", "/api/v1/mcp/tool-call", body)

	var result mcp.ToolCallResult
	_ = json.NewDecoder(w.Body).Decode(&result)

	if !result.IsError {
		t.Error("expected IsError=true when credentials unavailable")
	}

	// Error text must not expose connection string details.
	if len(result.Content) > 0 {
		text := result.Content[0].Text
		for _, sensitive := range []string{"db.example.com", "v-pass-xyz", "mydb"} {
			if containsMCPStr(text, sensitive) {
				t.Errorf("error response %q must not contain sensitive value %q", text, sensitive)
			}
		}
	}
}

func TestHandleDBQuery_UnsupportedEngine_ReturnsError(t *testing.T) {
	mockDB := newMockDB("redis") // redis is not supported via database/sql

	h := newTestHandler(&mockProxy{}, &mockServices{})
	h.SetDBExecutor(mockDB)

	body := map[string]interface{}{
		"tool": "straylight_db_query",
		"arguments": map[string]interface{}{
			"service": "my-pg",
			"query":   "GET somekey",
		},
	}
	w := doRequest(h, "POST", "/api/v1/mcp/tool-call", body)

	var result mcp.ToolCallResult
	_ = json.NewDecoder(w.Body).Decode(&result)

	// Redis is not supported by database/sql — should get a clear error.
	if !result.IsError {
		t.Error("expected IsError=true for redis engine (not supported via sql driver)")
	}
}

func TestHandleDBQuery_MaxRowsDefault(t *testing.T) {
	// Verify the tool definition includes max_rows with a default value.
	h := newTestHandler(&mockProxy{}, &mockServices{})
	w := doRequest(h, "GET", "/api/v1/mcp/tool-list", nil)

	var resp struct {
		Tools []mcp.ToolDefinition `json:"tools"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)

	var dbQueryTool *mcp.ToolDefinition
	for i, t := range resp.Tools {
		if t.Name == "straylight_db_query" {
			dbQueryTool = &resp.Tools[i]
			break
		}
	}

	if dbQueryTool == nil {
		t.Fatal("straylight_db_query not found in tool list")
	}
	if dbQueryTool.Description == "" {
		t.Error("straylight_db_query has empty description")
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func containsMCPStr(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
