package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/server"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// captureHandler records the log records emitted during an HTTP exchange.
type captureHandler struct {
	mu      *mutexLock
	records []slog.Record
}

type mutexLock struct{}

func newCaptureHandler() *captureHandler {
	return &captureHandler{mu: &mutexLock{}}
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler         { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler              { return h }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

// attrValue searches the record's attributes for the named key and returns its value.
func attrValue(r slog.Record, key string) (slog.Value, bool) {
	var found slog.Value
	var ok bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			found = a.Value
			ok = true
			return false
		}
		return true
	})
	return found, ok
}

// ---------------------------------------------------------------------------
// RequestLogging middleware
// ---------------------------------------------------------------------------

// TestRequestLogging_PassesRequestToNextHandler verifies the middleware calls next.
func TestRequestLogging_PassesRequestToNextHandler(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	cap := newCaptureHandler()
	logger := slog.New(cap)
	mw := server.RequestLogging(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called")
	}
}

// TestRequestLogging_LogsMethod verifies the middleware logs the HTTP method.
func TestRequestLogging_LogsMethod(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cap := newCaptureHandler()
	logger := slog.New(cap)
	mw := server.RequestLogging(logger, next)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if len(cap.records) == 0 {
		t.Fatal("expected at least one log record")
	}
	rec := cap.records[len(cap.records)-1]
	val, ok := attrValue(rec, "method")
	if !ok {
		t.Error("expected 'method' attribute in log record")
	}
	if val.String() != "POST" {
		t.Errorf("expected method=POST, got %q", val.String())
	}
}

// TestRequestLogging_LogsPath verifies the middleware logs the request path.
func TestRequestLogging_LogsPath(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cap := newCaptureHandler()
	logger := slog.New(cap)
	mw := server.RequestLogging(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/services/stripe", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if len(cap.records) == 0 {
		t.Fatal("expected at least one log record")
	}
	rec := cap.records[len(cap.records)-1]
	val, ok := attrValue(rec, "path")
	if !ok {
		t.Error("expected 'path' attribute in log record")
	}
	if val.String() != "/api/v1/services/stripe" {
		t.Errorf("expected path=/api/v1/services/stripe, got %q", val.String())
	}
}

// TestRequestLogging_LogsStatusCode verifies the middleware logs the response status code.
func TestRequestLogging_LogsStatusCode(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	cap := newCaptureHandler()
	logger := slog.New(cap)
	mw := server.RequestLogging(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/services/missing", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if len(cap.records) == 0 {
		t.Fatal("expected at least one log record")
	}
	rec := cap.records[len(cap.records)-1]
	val, ok := attrValue(rec, "status")
	if !ok {
		t.Error("expected 'status' attribute in log record")
	}
	if val.Int64() != http.StatusNotFound {
		t.Errorf("expected status=404, got %d", val.Int64())
	}
}

// TestRequestLogging_LogsDuration verifies the middleware logs the request duration.
func TestRequestLogging_LogsDuration(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cap := newCaptureHandler()
	logger := slog.New(cap)
	mw := server.RequestLogging(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if len(cap.records) == 0 {
		t.Fatal("expected at least one log record")
	}
	rec := cap.records[len(cap.records)-1]
	_, ok := attrValue(rec, "duration_ms")
	if !ok {
		t.Error("expected 'duration_ms' attribute in log record")
	}
}

// TestRequestLogging_LogsRequestID verifies the middleware generates and logs a request ID.
func TestRequestLogging_LogsRequestID(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cap := newCaptureHandler()
	logger := slog.New(cap)
	mw := server.RequestLogging(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if len(cap.records) == 0 {
		t.Fatal("expected at least one log record")
	}
	rec := cap.records[len(cap.records)-1]
	val, ok := attrValue(rec, "request_id")
	if !ok {
		t.Error("expected 'request_id' attribute in log record")
	}
	if val.String() == "" {
		t.Error("expected non-empty request_id")
	}
}

// TestRequestLogging_UniqueRequestIDs verifies each request gets a distinct request ID.
func TestRequestLogging_UniqueRequestIDs(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cap := newCaptureHandler()
	logger := slog.New(cap)
	mw := server.RequestLogging(logger, next)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, req)
	}

	if len(cap.records) < 3 {
		t.Fatalf("expected 3 log records, got %d", len(cap.records))
	}

	ids := make(map[string]bool)
	for _, rec := range cap.records {
		val, ok := attrValue(rec, "request_id")
		if !ok {
			t.Fatal("expected request_id in all log records")
		}
		ids[val.String()] = true
	}
	if len(ids) < 3 {
		t.Errorf("expected 3 unique request IDs, got %d", len(ids))
	}
}

// TestRequestLogging_SetsRequestIDOnContext verifies the request ID is available in the context.
func TestRequestLogging_SetsRequestIDOnContext(t *testing.T) {
	var capturedID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = server.RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	cap := newCaptureHandler()
	logger := slog.New(cap)
	mw := server.RequestLogging(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if capturedID == "" {
		t.Error("expected request ID to be set in context")
	}
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

// TestAuditLog_LogsAuditField verifies AuditLog emits a record with audit=true.
func TestAuditLog_LogsAuditField(t *testing.T) {
	cap := newCaptureHandler()
	logger := slog.New(cap)

	server.AuditLog(logger, "credential_accessed", "stripe", "straylight_api_call", "req-001")

	if len(cap.records) == 0 {
		t.Fatal("expected at least one log record from AuditLog")
	}
	rec := cap.records[0]
	val, ok := attrValue(rec, "audit")
	if !ok {
		t.Error("expected 'audit' attribute in audit log record")
	}
	if !val.Bool() {
		t.Error("expected audit=true in audit log record")
	}
}

// TestAuditLog_LogsEventField verifies AuditLog records the event name.
func TestAuditLog_LogsEventField(t *testing.T) {
	cap := newCaptureHandler()
	logger := slog.New(cap)

	server.AuditLog(logger, "credential_stored", "github", "straylight_api_call", "req-002")

	if len(cap.records) == 0 {
		t.Fatal("expected at least one log record")
	}
	rec := cap.records[0]
	val, ok := attrValue(rec, "event")
	if !ok {
		t.Error("expected 'event' attribute in audit log record")
	}
	if val.String() != "credential_stored" {
		t.Errorf("expected event=credential_stored, got %q", val.String())
	}
}

// TestAuditLog_LogsServiceName verifies AuditLog records the service name.
func TestAuditLog_LogsServiceName(t *testing.T) {
	cap := newCaptureHandler()
	logger := slog.New(cap)

	server.AuditLog(logger, "credential_deleted", "openai", "straylight_api_call", "req-003")

	rec := cap.records[0]
	val, ok := attrValue(rec, "service")
	if !ok {
		t.Error("expected 'service' attribute in audit log record")
	}
	if val.String() != "openai" {
		t.Errorf("expected service=openai, got %q", val.String())
	}
}

// TestAuditLog_LogsToolField verifies AuditLog records the tool name.
func TestAuditLog_LogsToolField(t *testing.T) {
	cap := newCaptureHandler()
	logger := slog.New(cap)

	server.AuditLog(logger, "credential_refreshed", "stripe", "straylight_exec", "req-004")

	rec := cap.records[0]
	val, ok := attrValue(rec, "tool")
	if !ok {
		t.Error("expected 'tool' attribute in audit log record")
	}
	if val.String() != "straylight_exec" {
		t.Errorf("expected tool=straylight_exec, got %q", val.String())
	}
}

// TestAuditLog_LogsRequestID verifies AuditLog records the request ID.
func TestAuditLog_LogsRequestID(t *testing.T) {
	cap := newCaptureHandler()
	logger := slog.New(cap)

	server.AuditLog(logger, "credential_accessed", "stripe", "straylight_api_call", "req-xyz-123")

	rec := cap.records[0]
	val, ok := attrValue(rec, "request_id")
	if !ok {
		t.Error("expected 'request_id' attribute in audit log record")
	}
	if val.String() != "req-xyz-123" {
		t.Errorf("expected request_id=req-xyz-123, got %q", val.String())
	}
}

// TestAuditLog_AllValidEvents verifies all specified audit event types are accepted.
func TestAuditLog_AllValidEvents(t *testing.T) {
	events := []string{
		"credential_accessed",
		"credential_stored",
		"credential_deleted",
		"credential_refreshed",
	}

	for _, evt := range events {
		t.Run(evt, func(t *testing.T) {
			cap := newCaptureHandler()
			logger := slog.New(cap)
			// Should not panic.
			server.AuditLog(logger, evt, "svc", "tool", "rid")
			if len(cap.records) == 0 {
				t.Errorf("expected log record for event %q", evt)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JSON log format integration
// ---------------------------------------------------------------------------

// TestRequestLogging_JSONOutput verifies the middleware can log in JSON format.
func TestRequestLogging_JSONOutput(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	mw := server.RequestLogging(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	output := buf.String()
	if output == "" {
		t.Fatal("expected JSON log output")
	}

	// Each log line should be valid JSON.
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("log line is not valid JSON: %s", line)
		}
	}
}
