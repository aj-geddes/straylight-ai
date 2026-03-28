// Package audit_test contains tests for the audit event bus and log writer.
package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/audit"
)

// ---------------------------------------------------------------------------
// Event construction helpers
// ---------------------------------------------------------------------------

func makeEvent(t EventType, svc, tool string) audit.Event {
	return audit.Event{
		Type:    t,
		Service: svc,
		Tool:    tool,
		Details: map[string]string{"test": "value"},
	}
}

// Alias for test clarity.
type EventType = audit.EventType

// ---------------------------------------------------------------------------
// TestEventConstants verifies all expected EventType constants are exported.
// ---------------------------------------------------------------------------

func TestEventConstants(t *testing.T) {
	tests := []struct {
		name string
		val  audit.EventType
		want string
	}{
		{"CredentialAccessed", audit.EventCredentialAccessed, "credential_accessed"},
		{"CredentialStored", audit.EventCredentialStored, "credential_stored"},
		{"CredentialDeleted", audit.EventCredentialDeleted, "credential_deleted"},
		{"CredentialRotated", audit.EventCredentialRotated, "credential_rotated"},
		{"ToolCall", audit.EventToolCall, "tool_call"},
		{"DBQuery", audit.EventDBQuery, "db_query"},
		{"CloudExec", audit.EventCloudExec, "cloud_exec"},
		{"FileScan", audit.EventFileScan, "file_scan"},
		{"FileRead", audit.EventFileRead, "file_read"},
		{"LeaseCreated", audit.EventLeaseCreated, "lease_created"},
		{"LeaseRevoked", audit.EventLeaseRevoked, "lease_revoked"},
		{"LeaseRenewed", audit.EventLeaseRenewed, "lease_renewed"},
		{"LeaseExpired", audit.EventLeaseExpired, "lease_expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.val) != tt.want {
				t.Errorf("EventType %s = %q, want %q", tt.name, tt.val, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestNewLogger_CreatesDirectory verifies NewLogger creates the audit dir.
// ---------------------------------------------------------------------------

func TestNewLogger_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")

	l, err := audit.NewLogger(auditDir, 90)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if _, err := os.Stat(auditDir); os.IsNotExist(err) {
		t.Errorf("audit directory %q was not created", auditDir)
	}
}

// ---------------------------------------------------------------------------
// TestEmit_WritesEventToFile verifies Emit writes a JSON line to the log file.
// ---------------------------------------------------------------------------

func TestEmit_WritesEventToFile(t *testing.T) {
	dir := t.TempDir()

	l, err := audit.NewLogger(dir, 90)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	l.Emit(audit.Event{
		Type:    audit.EventCredentialAccessed,
		Service: "github",
		Tool:    "straylight_api_call",
		Details: map[string]string{"method": "GET", "path": "/repos"},
	})

	// Close flushes all pending events.
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Find the written log file.
	files, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no audit log files found in %q", dir)
	}

	f, err := os.Open(files[0])
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected at least one line in audit log, got none")
	}
	line := scanner.Text()

	var ev audit.Event
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("unmarshal audit event: %v", err)
	}
	if ev.Type != audit.EventCredentialAccessed {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventCredentialAccessed)
	}
	if ev.Service != "github" {
		t.Errorf("event service = %q, want %q", ev.Service, "github")
	}
	if ev.ID == "" {
		t.Error("event ID should be set automatically, got empty string")
	}
	if ev.Timestamp.IsZero() {
		t.Error("event Timestamp should be set automatically, got zero")
	}
}

// ---------------------------------------------------------------------------
// TestEmit_IsNonBlocking verifies Emit does not block when channel is full.
// ---------------------------------------------------------------------------

func TestEmit_IsNonBlocking(t *testing.T) {
	// Use a very small channel to trigger the overflow path quickly.
	dir := t.TempDir()
	l, err := audit.NewLoggerWithOptions(dir, 0, audit.Options{ChannelSize: 2})
	if err != nil {
		t.Fatalf("NewLoggerWithOptions: %v", err)
	}
	defer l.Close()

	// Emit more events than the channel can hold without consuming them.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			l.Emit(audit.Event{Type: audit.EventToolCall})
		}
		close(done)
	}()

	select {
	case <-done:
		// Good: Emit returned without blocking.
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked — should be non-blocking")
	}
}

// ---------------------------------------------------------------------------
// TestEmit_SetsIDAndTimestamp verifies auto-population of ID and Timestamp.
// ---------------------------------------------------------------------------

func TestEmit_SetsIDAndTimestamp(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	before := time.Now().UTC()
	l.Emit(audit.Event{Type: audit.EventToolCall, Service: "test"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	after := time.Now().UTC()

	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no audit files found")
	}
	f, _ := os.Open(files[0])
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("no lines in log file")
	}

	var ev audit.Event
	if err := json.Unmarshal([]byte(sc.Text()), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.ID == "" {
		t.Error("ID should be auto-set")
	}
	if ev.Timestamp.Before(before) || ev.Timestamp.After(after) {
		t.Errorf("Timestamp %v not in range [%v, %v]", ev.Timestamp, before, after)
	}
}

// ---------------------------------------------------------------------------
// TestRecent_ReturnsRecentEvents verifies the ring buffer via Recent().
// ---------------------------------------------------------------------------

func TestRecent_ReturnsRecentEvents(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// Emit 5 events; use a small pause to let the writer goroutine pick them up.
	for i := 0; i < 5; i++ {
		l.Emit(audit.Event{Type: audit.EventToolCall, Service: "svc"})
	}

	// Give the writer goroutine time to process events into the ring buffer.
	time.Sleep(50 * time.Millisecond)

	recent := l.Recent(10)
	if len(recent) != 5 {
		t.Errorf("Recent(10) returned %d events, want 5", len(recent))
	}
}

// ---------------------------------------------------------------------------
// TestRecent_LimitedByN verifies Recent respects the n limit.
// ---------------------------------------------------------------------------

func TestRecent_LimitedByN(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	for i := 0; i < 10; i++ {
		l.Emit(audit.Event{Type: audit.EventToolCall})
	}
	time.Sleep(50 * time.Millisecond)

	recent := l.Recent(3)
	if len(recent) > 3 {
		t.Errorf("Recent(3) returned %d events, want at most 3", len(recent))
	}
}

// ---------------------------------------------------------------------------
// TestClose_Idempotent verifies calling Close multiple times does not panic.
// ---------------------------------------------------------------------------

func TestClose_Idempotent(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close should not panic or error.
	if err := l.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestEmit_ConcurrentSafety verifies concurrent Emit calls do not race.
// ---------------------------------------------------------------------------

func TestEmit_ConcurrentSafety(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	const goroutines = 20
	const eventsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				l.Emit(audit.Event{Type: audit.EventToolCall})
			}
		}()
	}
	wg.Wait()
	// If the race detector is running it will catch unsafe accesses.
}

// ---------------------------------------------------------------------------
// TestFileNameFormat verifies the log file uses the expected date-based name.
// ---------------------------------------------------------------------------

func TestFileNameFormat(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	l.Emit(audit.Event{Type: audit.EventToolCall})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	today := time.Now().UTC().Format("2006-01-02")
	expected := filepath.Join(dir, "audit-"+today+".jsonl")
	if _, err := os.Stat(expected); os.IsNotExist(err) {
		t.Errorf("expected log file %q not found", expected)
	}
}

// ---------------------------------------------------------------------------
// TestFilePermissions verifies the log file has mode 0600.
// ---------------------------------------------------------------------------

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	l.Emit(audit.Event{Type: audit.EventToolCall})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no audit files found")
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode(); mode != 0o600 {
		t.Errorf("file mode = %o, want 0600", mode)
	}
}

// ---------------------------------------------------------------------------
// TestDroppedCounter verifies dropped events are counted when channel is full.
// ---------------------------------------------------------------------------

func TestDroppedCounter(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLoggerWithOptions(dir, 0, audit.Options{ChannelSize: 1})
	if err != nil {
		t.Fatalf("NewLoggerWithOptions: %v", err)
	}
	defer l.Close()

	// Saturate the channel — the writer goroutine is not consuming events yet
	// because we haven't given it time to run. A channel of size 1 means the
	// second and subsequent non-blocking sends will be dropped.
	for i := 0; i < 20; i++ {
		l.Emit(audit.Event{Type: audit.EventToolCall})
	}

	dropped := l.DroppedCount()
	if dropped == 0 {
		t.Error("expected some dropped events, got 0")
	}
}

// ---------------------------------------------------------------------------
// TestEmitter_Interface verifies Logger satisfies the Emitter interface.
// ---------------------------------------------------------------------------

func TestEmitter_Interface(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger(dir, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	var _ audit.Emitter = l
}
