// Package mcp (white-box test): verifies that dbQueryResponse does not
// include vault lease identifiers in its JSON serialization.
//
// Issue 3 (HIGH): LeaseID and LeaseTTLSeconds were included in the JSON
// response returned to the AI, revealing vault mount names and role names.
package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDBQueryResponse_LeaseIDNotInJSON verifies that the dbQueryResponse
// struct does not serialise "lease_id" or "lease_ttl_seconds" into JSON.
//
// These are vault infrastructure identifiers that reveal mount names and
// role names and have no legitimate use for AI callers.
func TestDBQueryResponse_LeaseIDNotInJSON(t *testing.T) {
	// After the fix, dbQueryResponse no longer has LeaseID or LeaseTTLSeconds
	// fields — verify the remaining fields serialize correctly and that the
	// forbidden field names are absent.
	resp := dbQueryResponse{
		Columns:    []string{"id", "name"},
		Rows:       [][]interface{}{{1, "alice"}},
		RowCount:   1,
		DurationMS: 5,
		Engine:     "postgresql",
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	body := string(b)

	if strings.Contains(body, "lease_id") {
		t.Errorf("JSON response contains 'lease_id' — this field must not be in dbQueryResponse; got: %s", body)
	}
	if strings.Contains(body, "lease_ttl_seconds") {
		t.Errorf("JSON response contains 'lease_ttl_seconds' — this field must not be in dbQueryResponse; got: %s", body)
	}

	// Verify the expected fields are present.
	if !strings.Contains(body, `"columns"`) {
		t.Errorf("JSON response missing 'columns' field; got: %s", body)
	}
	if !strings.Contains(body, `"engine"`) {
		t.Errorf("JSON response missing 'engine' field; got: %s", body)
	}
}
