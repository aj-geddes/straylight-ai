package server_test

import (
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/server"
)

// ---------------------------------------------------------------------------
// ActivityLog unit tests
// ---------------------------------------------------------------------------

func TestActivityLog_NewReturnsEmptyLog(t *testing.T) {
	log := server.NewActivityLog()
	stats := log.Stats()
	if stats.TotalAPICalls != 0 {
		t.Errorf("expected 0 api calls, got %d", stats.TotalAPICalls)
	}
	if stats.TotalExecCalls != 0 {
		t.Errorf("expected 0 exec calls, got %d", stats.TotalExecCalls)
	}
	if len(stats.RecentActivity) != 0 {
		t.Errorf("expected 0 recent activities, got %d", len(stats.RecentActivity))
	}
}

func TestActivityLog_RecordAPICall_IncreasesCount(t *testing.T) {
	log := server.NewActivityLog()
	log.Record(server.ActivityEntry{
		Timestamp: time.Now(),
		Service:   "github",
		Tool:      "api_call",
		Method:    "GET",
		Path:      "/user/repos",
		Status:    200,
	})
	stats := log.Stats()
	if stats.TotalAPICalls != 1 {
		t.Errorf("expected 1 api call, got %d", stats.TotalAPICalls)
	}
	if stats.TotalExecCalls != 0 {
		t.Errorf("expected 0 exec calls, got %d", stats.TotalExecCalls)
	}
}

func TestActivityLog_RecordExecCall_IncreasesCount(t *testing.T) {
	log := server.NewActivityLog()
	log.Record(server.ActivityEntry{
		Timestamp: time.Now(),
		Service:   "github",
		Tool:      "exec",
		Status:    200,
	})
	stats := log.Stats()
	if stats.TotalExecCalls != 1 {
		t.Errorf("expected 1 exec call, got %d", stats.TotalExecCalls)
	}
	if stats.TotalAPICalls != 0 {
		t.Errorf("expected 0 api calls, got %d", stats.TotalAPICalls)
	}
}

func TestActivityLog_Recent_ReturnsLastN(t *testing.T) {
	log := server.NewActivityLog()
	for i := 0; i < 20; i++ {
		log.Record(server.ActivityEntry{
			Timestamp: time.Now(),
			Service:   "github",
			Tool:      "api_call",
			Status:    200,
		})
	}
	recent := log.Recent(10)
	if len(recent) != 10 {
		t.Errorf("expected 10 recent entries, got %d", len(recent))
	}
}

func TestActivityLog_CircularBuffer_Max100Entries(t *testing.T) {
	log := server.NewActivityLog()
	for i := 0; i < 150; i++ {
		log.Record(server.ActivityEntry{
			Timestamp: time.Now(),
			Service:   "github",
			Tool:      "api_call",
			Status:    200,
		})
	}
	all := log.Recent(200)
	if len(all) > 100 {
		t.Errorf("expected at most 100 entries in circular buffer, got %d", len(all))
	}
}

func TestActivityLog_Stats_IncludesUptimeSeconds(t *testing.T) {
	log := server.NewActivityLog()
	stats := log.Stats()
	if stats.UptimeSeconds < 0 {
		t.Error("expected non-negative uptime")
	}
}

func TestActivityLog_Stats_RecentActivityCappedAt10(t *testing.T) {
	log := server.NewActivityLog()
	for i := 0; i < 50; i++ {
		log.Record(server.ActivityEntry{
			Timestamp: time.Now(),
			Service:   "github",
			Tool:      "api_call",
			Status:    200,
		})
	}
	stats := log.Stats()
	if len(stats.RecentActivity) > 10 {
		t.Errorf("expected at most 10 recent activities in stats, got %d", len(stats.RecentActivity))
	}
}

func TestActivityLog_MultipleTools_CountedSeparately(t *testing.T) {
	log := server.NewActivityLog()
	log.Record(server.ActivityEntry{Tool: "api_call", Status: 200})
	log.Record(server.ActivityEntry{Tool: "api_call", Status: 200})
	log.Record(server.ActivityEntry{Tool: "exec", Status: 200})
	log.Record(server.ActivityEntry{Tool: "check", Status: 200})

	stats := log.Stats()
	if stats.TotalAPICalls != 2 {
		t.Errorf("expected 2 api calls, got %d", stats.TotalAPICalls)
	}
	if stats.TotalExecCalls != 1 {
		t.Errorf("expected 1 exec call, got %d", stats.TotalExecCalls)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/stats endpoint tests
// ---------------------------------------------------------------------------

func TestStatsEndpoint_Returns200(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/stats")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStatsEndpoint_HasRequiredFields(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/stats")
	body := decodeJSON(t, w)

	for _, field := range []string{"total_services", "total_api_calls", "total_exec_calls", "uptime_seconds", "recent_activity"} {
		if _, ok := body[field]; !ok {
			t.Errorf("expected field %q in stats response", field)
		}
	}
}

func TestStatsEndpoint_RecentActivityIsArray(t *testing.T) {
	srv, _ := newTestServer()
	w := getPath(srv, "/api/v1/stats")
	body := decodeJSON(t, w)

	activities, ok := body["recent_activity"].([]interface{})
	if !ok {
		t.Fatalf("expected recent_activity to be an array, got %T", body["recent_activity"])
	}
	// Should start empty
	if len(activities) != 0 {
		t.Errorf("expected empty recent_activity on fresh server, got %d entries", len(activities))
	}
}

func TestStatsEndpoint_TotalServicesReflectsRegistry(t *testing.T) {
	srv, _ := newTestServer()

	// Add a service via the API
	postJSON(srv, "/api/v1/services", map[string]interface{}{
		"name":       "myservice",
		"type":       "http_proxy",
		"target":     "https://api.example.com",
		"inject":     "header",
		"credential": "token123",
	})

	w := getPath(srv, "/api/v1/stats")
	body := decodeJSON(t, w)

	totalServices, ok := body["total_services"].(float64)
	if !ok {
		t.Fatalf("expected total_services to be a number, got %T", body["total_services"])
	}
	if int(totalServices) != 1 {
		t.Errorf("expected total_services=1, got %v", totalServices)
	}
}
