package server

import (
	"net/http"
	"strconv"

	"github.com/straylight-ai/straylight/internal/audit"
)

// defaultAuditLimit is the default number of audit events returned per query.
const defaultAuditLimit = 100

// maxAuditLimit is the maximum number of events the audit query endpoint returns.
const maxAuditLimit = 1000

// auditEventsResponse is the JSON payload returned by GET /api/v1/audit/events.
type auditEventsResponse struct {
	Events []audit.Event `json:"events"`
	Total  int           `json:"total"`
}

// auditStatsResponse is the JSON payload returned by GET /api/v1/audit/stats.
type auditStatsResponse struct {
	ByType    map[string]int `json:"by_type"`
	ByService map[string]int `json:"by_service"`
	Total     int            `json:"total"`
}

// handleAuditEvents responds to GET /api/v1/audit/events.
//
// Query parameters:
//   - service     — filter by service name (exact match)
//   - tool        — filter by tool name (exact match)
//   - event_type  — filter by event type string (e.g. "tool_call")
//   - limit       — max results to return (default 100, max 1000)
//
// Events are read from the in-memory ring buffer. The most recent events are
// returned, oldest-first within the result set.
func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	service := q.Get("service")
	tool := q.Get("tool")
	eventType := audit.EventType(q.Get("event_type"))

	limit := defaultAuditLimit
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}

	// Fetch recent events from the ring buffer (up to maxAuditLimit to apply filters).
	all := s.cfg.AuditLogger.Recent(maxAuditLimit)

	// Apply filters.
	filtered := make([]audit.Event, 0, len(all))
	for _, ev := range all {
		if service != "" && ev.Service != service {
			continue
		}
		if tool != "" && ev.Tool != tool {
			continue
		}
		if eventType != "" && ev.Type != eventType {
			continue
		}
		filtered = append(filtered, ev)
	}

	// Apply limit (take the most recent N after filtering).
	if len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}

	writeJSON(w, http.StatusOK, auditEventsResponse{
		Events: filtered,
		Total:  len(filtered),
	})
}

// handleAuditStats responds to GET /api/v1/audit/stats.
//
// Returns aggregate counts from the in-memory ring buffer:
//   - by_type:    map of event type → count
//   - by_service: map of service name → count
//   - total:      total events in the ring buffer
func (s *Server) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	all := s.cfg.AuditLogger.Recent(maxAuditLimit)

	byType := make(map[string]int)
	byService := make(map[string]int)

	for _, ev := range all {
		byType[string(ev.Type)]++
		if ev.Service != "" {
			byService[ev.Service]++
		}
	}

	writeJSON(w, http.StatusOK, auditStatsResponse{
		ByType:    byType,
		ByService: byService,
		Total:     len(all),
	})
}
