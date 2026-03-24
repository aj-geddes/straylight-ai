package server

import (
	"sync"
	"time"
)

const maxActivityEntries = 100
const statsRecentActivityCount = 10

// ActivityEntry records a single tool call or service interaction.
type ActivityEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Service   string    `json:"service"`
	Tool      string    `json:"tool"`   // "api_call", "exec", "check", "services"
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	Status    int       `json:"status"`
}

// StatsResponse is the JSON payload for GET /api/v1/stats.
type StatsResponse struct {
	TotalServices  int             `json:"total_services"`
	TotalAPICalls  int64           `json:"total_api_calls"`
	TotalExecCalls int64           `json:"total_exec_calls"`
	UptimeSeconds  int64           `json:"uptime_seconds"`
	RecentActivity []ActivityEntry `json:"recent_activity"`
}

// ActivityLog is a thread-safe circular buffer for recording tool call activity.
// It holds at most maxActivityEntries entries and tracks aggregate counters.
type ActivityLog struct {
	mu       sync.RWMutex
	entries  []ActivityEntry
	apiCalls int64
	execCalls int64
	startTime time.Time
}

// NewActivityLog creates a new ActivityLog with the current time as its start.
func NewActivityLog() *ActivityLog {
	return &ActivityLog{
		startTime: time.Now(),
	}
}

// Record adds an entry to the circular buffer and updates the relevant counter.
func (a *ActivityLog) Record(entry ActivityEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Circular buffer: drop oldest entry when at capacity.
	if len(a.entries) >= maxActivityEntries {
		a.entries = a.entries[1:]
	}
	a.entries = append(a.entries, entry)

	switch entry.Tool {
	case "api_call":
		a.apiCalls++
	case "exec":
		a.execCalls++
	}
}

// Recent returns the last n entries in chronological order (newest last).
// If n >= len(entries), all entries are returned.
func (a *ActivityLog) Recent(n int) []ActivityEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	total := len(a.entries)
	if n >= total {
		result := make([]ActivityEntry, total)
		copy(result, a.entries)
		return result
	}
	result := make([]ActivityEntry, n)
	copy(result, a.entries[total-n:])
	return result
}

// Stats returns a snapshot of aggregate counts and recent activity.
func (a *ActivityLog) Stats() StatsResponse {
	a.mu.RLock()
	defer a.mu.RUnlock()

	uptime := int64(time.Since(a.startTime).Seconds())

	recentCount := statsRecentActivityCount
	if len(a.entries) < recentCount {
		recentCount = len(a.entries)
	}

	recent := make([]ActivityEntry, recentCount)
	if recentCount > 0 {
		copy(recent, a.entries[len(a.entries)-recentCount:])
	}

	return StatsResponse{
		TotalAPICalls:  a.apiCalls,
		TotalExecCalls: a.execCalls,
		UptimeSeconds:  uptime,
		RecentActivity: recent,
	}
}
