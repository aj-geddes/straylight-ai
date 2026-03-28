package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/server"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newAuditLogger creates a real audit.Logger backed by a temp directory.
func newAuditLogger(t *testing.T) *audit.Logger {
	t.Helper()
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// newServerWithAudit creates a server with an audit logger in its config.
func newServerWithAudit(t *testing.T, auditLogger *audit.Logger) *server.Server {
	t.Helper()
	return server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "test",
		AuditLogger:   auditLogger,
	})
}

// emitAndFlush emits events and sleeps briefly to let the write goroutine flush.
func emitAndFlush(l *audit.Logger, events []audit.Event) {
	for _, ev := range events {
		l.Emit(ev)
	}
	time.Sleep(30 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit/events — route registration
// ---------------------------------------------------------------------------

func TestAuditEventsRoute_IsRegistered(t *testing.T) {
	l := newAuditLogger(t)
	srv := newServerWithAudit(t, l)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code == http.StatusNotFound {
		t.Fatalf("GET /api/v1/audit/events returned 404 — route not registered")
	}
	if w.Code == http.StatusNotImplemented {
		t.Fatalf("GET /api/v1/audit/events returned 501 — not yet wired")
	}
}

func TestAuditEventsRoute_ReturnsJSON(t *testing.T) {
	l := newAuditLogger(t)
	srv := newServerWithAudit(t, l)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct == "" {
		t.Error("expected Content-Type header")
	}
}

func TestAuditEventsRoute_ReturnsEventArray(t *testing.T) {
	l := newAuditLogger(t)
	emitAndFlush(l, []audit.Event{
		{Type: audit.EventToolCall, Service: "stripe", Tool: "straylight_api_call"},
		{Type: audit.EventCredentialAccessed, Service: "github"},
	})

	srv := newServerWithAudit(t, l)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp struct {
		Events []audit.Event `json:"events"`
		Total  int           `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, w.Body.String())
	}
	if len(resp.Events) < 2 {
		t.Errorf("expected at least 2 events, got %d", len(resp.Events))
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit/events — filter by service
// ---------------------------------------------------------------------------

func TestAuditEventsRoute_FilterByService(t *testing.T) {
	l := newAuditLogger(t)
	emitAndFlush(l, []audit.Event{
		{Type: audit.EventToolCall, Service: "stripe", Tool: "straylight_api_call"},
		{Type: audit.EventToolCall, Service: "github", Tool: "straylight_api_call"},
		{Type: audit.EventToolCall, Service: "stripe", Tool: "straylight_check"},
	})

	srv := newServerWithAudit(t, l)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?service=stripe", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, ev := range resp.Events {
		if ev.Service != "stripe" {
			t.Errorf("filter by service=stripe returned event with service=%q", ev.Service)
		}
	}

	if len(resp.Events) < 2 {
		t.Errorf("expected at least 2 stripe events, got %d", len(resp.Events))
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit/events — filter by event_type
// ---------------------------------------------------------------------------

func TestAuditEventsRoute_FilterByEventType(t *testing.T) {
	l := newAuditLogger(t)
	emitAndFlush(l, []audit.Event{
		{Type: audit.EventToolCall, Service: "stripe"},
		{Type: audit.EventCredentialAccessed, Service: "stripe"},
		{Type: audit.EventToolCall, Service: "github"},
	})

	srv := newServerWithAudit(t, l)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?event_type=tool_call", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, ev := range resp.Events {
		if ev.Type != audit.EventToolCall {
			t.Errorf("filter by event_type=tool_call returned event type=%q", ev.Type)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit/events — limit parameter
// ---------------------------------------------------------------------------

func TestAuditEventsRoute_LimitParameter(t *testing.T) {
	l := newAuditLogger(t)
	events := make([]audit.Event, 20)
	for i := range events {
		events[i] = audit.Event{Type: audit.EventToolCall, Service: "stripe"}
	}
	emitAndFlush(l, events)

	srv := newServerWithAudit(t, l)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?limit=5", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Events) > 5 {
		t.Errorf("limit=5 returned %d events, expected at most 5", len(resp.Events))
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit/stats — route registration
// ---------------------------------------------------------------------------

func TestAuditStatsRoute_IsRegistered(t *testing.T) {
	l := newAuditLogger(t)
	srv := newServerWithAudit(t, l)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/stats", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code == http.StatusNotFound {
		t.Fatalf("GET /api/v1/audit/stats returned 404 — route not registered")
	}
	if w.Code == http.StatusNotImplemented {
		t.Fatalf("GET /api/v1/audit/stats returned 501 — not yet wired")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestAuditStatsRoute_ReturnsAggregatesByType(t *testing.T) {
	l := newAuditLogger(t)
	emitAndFlush(l, []audit.Event{
		{Type: audit.EventToolCall, Service: "stripe"},
		{Type: audit.EventToolCall, Service: "github"},
		{Type: audit.EventCredentialAccessed, Service: "stripe"},
	})

	srv := newServerWithAudit(t, l)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/stats", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp struct {
		ByType    map[string]int `json:"by_type"`
		ByService map[string]int `json:"by_service"`
		Total     int            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode stats: %v (body: %s)", err, w.Body.String())
	}

	if resp.Total < 3 {
		t.Errorf("expected total >= 3, got %d", resp.Total)
	}
	if resp.ByType == nil {
		t.Error("by_type should not be nil")
	}
	if resp.ByService == nil {
		t.Error("by_service should not be nil")
	}
}

func TestAuditStatsRoute_ByTypeCountsCorrect(t *testing.T) {
	l := newAuditLogger(t)
	emitAndFlush(l, []audit.Event{
		{Type: audit.EventToolCall, Service: "stripe"},
		{Type: audit.EventToolCall, Service: "github"},
		{Type: audit.EventCredentialAccessed, Service: "stripe"},
	})

	srv := newServerWithAudit(t, l)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/stats", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp struct {
		ByType map[string]int `json:"by_type"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.ByType["tool_call"] < 2 {
		t.Errorf("by_type[tool_call] = %d, want >= 2", resp.ByType["tool_call"])
	}
	if resp.ByType["credential_accessed"] < 1 {
		t.Errorf("by_type[credential_accessed] = %d, want >= 1", resp.ByType["credential_accessed"])
	}
}

// ---------------------------------------------------------------------------
// Without audit logger — routes return 501
// ---------------------------------------------------------------------------

func TestAuditEventsRoute_WithoutLogger_Returns501(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "test",
		// AuditLogger intentionally nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 when AuditLogger is nil, got %d", w.Code)
	}
}

func TestAuditStatsRoute_WithoutLogger_Returns501(t *testing.T) {
	srv := server.New(server.Config{
		ListenAddress: "127.0.0.1:0",
		Version:       "test",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/stats", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 when AuditLogger is nil, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Filter by tool name
// ---------------------------------------------------------------------------

func TestAuditEventsRoute_FilterByTool(t *testing.T) {
	l := newAuditLogger(t)
	emitAndFlush(l, []audit.Event{
		{Type: audit.EventToolCall, Tool: "straylight_api_call", Service: "stripe"},
		{Type: audit.EventToolCall, Tool: "straylight_check", Service: "github"},
		{Type: audit.EventToolCall, Tool: "straylight_api_call", Service: "openai"},
	})

	srv := newServerWithAudit(t, l)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?tool=straylight_api_call", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, ev := range resp.Events {
		if ev.Tool != "straylight_api_call" {
			t.Errorf("filter by tool=straylight_api_call returned event tool=%q", ev.Tool)
		}
	}
	if len(resp.Events) < 2 {
		t.Errorf("expected >= 2 straylight_api_call events, got %d", len(resp.Events))
	}
}
