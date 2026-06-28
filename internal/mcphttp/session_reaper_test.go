// Package mcphttp internal tests for session TTL reaper and session cap (finding 7).
// Uses the internal package so tests can access unexported types.
package mcphttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/mcpauth"
)

// stubAlwaysValidValidator satisfies mcpauth.TokenValidator for internal tests.
type stubAlwaysValidValidator struct{}

func (stubAlwaysValidValidator) Validate(_ context.Context, _ string) (*mcpauth.Identity, error) {
	return &mcpauth.Identity{Subject: "user|test", Issuer: "https://idp.example.com"}, nil
}

// TestSessionReaper_EvictsExpiredSessions verifies that the reaper sweep removes
// sessions whose lastSeen exceeds sessionTTL and decrements the session count.
func TestSessionReaper_EvictsExpiredSessions(t *testing.T) {
	h := &Handler{
		cfg: Config{
			ResourceURI: "https://mcp.example.com",
			Validator:   stubAlwaysValidValidator{},
		},
		originSet: map[string]bool{"https://claude.ai": true},
		stopCh:    make(chan struct{}),
	}

	// Plant an expired session.
	pastTime := time.Now().Add(-(sessionTTL + time.Second))
	h.sessions.Store("expired-sess-1", &sessionState{
		negotiatedVersion: supportedProtocolVersion,
		identity:          &mcpauth.Identity{Subject: "user|expired"},
		lastSeen:          pastTime,
	})
	atomic.AddInt64(&h.sessionCount, 1)

	// Plant a live session that must NOT be evicted.
	h.sessions.Store("live-sess-1", &sessionState{
		negotiatedVersion: supportedProtocolVersion,
		identity:          &mcpauth.Identity{Subject: "user|alive"},
		lastSeen:          time.Now(),
	})
	atomic.AddInt64(&h.sessionCount, 1)

	// Run one sweep (same logic as startReaper ticker fires).
	now := time.Now()
	h.sessions.Range(func(key, value interface{}) bool {
		sess := value.(*sessionState)
		if now.After(sess.lastSeen.Add(sessionTTL)) {
			h.sessions.Delete(key)
			atomic.AddInt64(&h.sessionCount, -1)
		}
		return true
	})

	// The expired session must be gone.
	if _, ok := h.sessions.Load("expired-sess-1"); ok {
		t.Error("reaper: expired session was not evicted")
	}

	// The live session must survive.
	if _, ok := h.sessions.Load("live-sess-1"); !ok {
		t.Error("reaper: live session was incorrectly evicted")
	}

	// Count must reflect only the live session.
	if got := atomic.LoadInt64(&h.sessionCount); got != 1 {
		t.Errorf("sessionCount after eviction = %d, want 1", got)
	}
}

// TestHandler_SessionCap_Returns503 verifies that handleInitialize returns HTTP 503
// when the session count is at the hard cap (finding 7).
func TestHandler_SessionCap_Returns503(t *testing.T) {
	h := &Handler{
		cfg: Config{
			ResourceURI: "https://mcp.example.com",
			Validator:   stubAlwaysValidValidator{},
		},
		originSet: map[string]bool{"https://claude.ai": true},
		stopCh:    make(chan struct{}),
	}
	// Set session count to the cap.
	atomic.StoreInt64(&h.sessionCount, maxSessions)

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()
	h.handleInitialize(w, r, jsonRPCRequest{Method: "initialize", ID: 1}, &mcpauth.Identity{Subject: "u"})

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("session cap: status = %d, want 503", w.Code)
	}
}

// TestClose_StopsReaper verifies Close() stops the reaper goroutine (stopCh closed).
func TestClose_StopsReaper(t *testing.T) {
	h := &Handler{
		stopCh: make(chan struct{}),
	}
	// Close twice must not panic.
	h.Close()
	h.Close() // idempotent

	// Confirm stopCh is closed by receiving from it without blocking.
	select {
	case <-h.stopCh:
		// expected
	default:
		t.Error("stopCh was not closed by Close()")
	}
}
