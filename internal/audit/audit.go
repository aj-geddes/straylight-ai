// Package audit provides an event bus and append-only JSON Lines log writer
// for recording all credential accesses, tool calls, and lease lifecycle events.
//
// Usage:
//
//	logger, err := audit.NewLogger("/data/audit", 90)
//	defer logger.Close()
//	logger.Emit(audit.Event{Type: audit.EventCredentialAccessed, Service: "github"})
package audit

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// EventType identifies the kind of auditable event.
type EventType string

const (
	// EventCredentialAccessed is emitted when a credential is read by the proxy.
	EventCredentialAccessed EventType = "credential_accessed"
	// EventCredentialStored is emitted when a credential is written to vault.
	EventCredentialStored EventType = "credential_stored"
	// EventCredentialDeleted is emitted when a credential is deleted from vault.
	EventCredentialDeleted EventType = "credential_deleted"
	// EventCredentialRotated is emitted when a credential is rotated.
	EventCredentialRotated EventType = "credential_rotated"
	// EventToolCall is emitted on every MCP tool invocation.
	EventToolCall EventType = "tool_call"
	// EventDBQuery is emitted when a database query is executed.
	EventDBQuery EventType = "db_query"
	// EventCloudExec is emitted when a cloud exec with temp credentials runs.
	EventCloudExec EventType = "cloud_exec"
	// EventFileScan is emitted when a project directory is scanned for secrets.
	EventFileScan EventType = "file_scan"
	// EventFileRead is emitted when the firewall reads a file.
	EventFileRead EventType = "file_read"
	// EventLeaseCreated is emitted when a vault lease is created.
	EventLeaseCreated EventType = "lease_created"
	// EventLeaseRevoked is emitted when a vault lease is explicitly revoked.
	EventLeaseRevoked EventType = "lease_revoked"
	// EventLeaseRenewed is emitted when a vault lease is renewed.
	EventLeaseRenewed EventType = "lease_renewed"
	// EventLeaseExpired is emitted when a vault lease expires without renewal.
	EventLeaseExpired EventType = "lease_expired"
)

// Event is a single audit log entry. ID and Timestamp are set automatically
// by Emit if not already populated.
type Event struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      EventType         `json:"type"`
	Service   string            `json:"service,omitempty"`
	Tool      string            `json:"tool,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
}

// Emitter is the interface implemented by Logger for use as a dependency.
// Consumers call Emit and the Logger handles persistence asynchronously.
type Emitter interface {
	Emit(event Event)
}

// Options holds optional tuning parameters for the Logger.
type Options struct {
	// ChannelSize is the capacity of the internal event channel.
	// Default: 10000.
	ChannelSize int

	// RingSize is the maximum number of events kept in the in-memory ring buffer.
	// Default: 1000.
	RingSize int
}

const (
	defaultChannelSize = 10_000
	defaultRingSize    = 1_000
)

// Logger is the audit event bus and storage engine. It is safe for concurrent use.
//
// Emit is non-blocking: if the channel is full, the oldest event is dropped
// and a dropped counter is incremented.
type Logger struct {
	dir      string
	opts     Options
	eventCh  chan Event
	dropped  atomic.Int64

	ring     []Event
	ringMu   sync.RWMutex
	ringHead int // index of next write position

	stopOnce sync.Once
	stopCh   chan struct{}
	done     chan struct{}
}

// NewLogger creates a Logger that writes to dir with the given retention days.
// retention=0 means no automatic deletion of old files.
func NewLogger(dir string, retention int) (*Logger, error) {
	return NewLoggerWithOptions(dir, retention, Options{})
}

// NewLoggerWithOptions creates a Logger with custom tuning options.
func NewLoggerWithOptions(dir string, retention int, opts Options) (*Logger, error) {
	if opts.ChannelSize <= 0 {
		opts.ChannelSize = defaultChannelSize
	}
	if opts.RingSize <= 0 {
		opts.RingSize = defaultRingSize
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir %q: %w", dir, err)
	}

	l := &Logger{
		dir:     dir,
		opts:    opts,
		eventCh: make(chan Event, opts.ChannelSize),
		ring:    make([]Event, opts.RingSize),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
	}

	go l.writeLoop(retention)
	return l, nil
}

// Emit sends an event to the audit bus. It is non-blocking.
// If the internal channel is full, the event is dropped and the dropped
// counter is incremented. ID and Timestamp are set automatically if empty.
func (l *Logger) Emit(event Event) {
	if event.ID == "" {
		event.ID = newUUID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	select {
	case l.eventCh <- event:
	default:
		l.dropped.Add(1)
	}
}

// Recent returns the last n events from the in-memory ring buffer,
// ordered from oldest to newest. Returns fewer events if fewer have been emitted.
func (l *Logger) Recent(n int) []Event {
	l.ringMu.RLock()
	defer l.ringMu.RUnlock()

	size := len(l.ring)
	if n > size {
		n = size
	}

	out := make([]Event, 0, n)
	// Walk backwards from ringHead to collect the most recent events.
	for i := 1; i <= size; i++ {
		idx := (l.ringHead - i + size) % size
		ev := l.ring[idx]
		if ev.ID == "" {
			// Slot not yet filled.
			break
		}
		out = append(out, ev)
		if len(out) == n {
			break
		}
	}

	// Reverse so order is oldest-to-newest.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// DroppedCount returns the number of events dropped due to channel overflow.
func (l *Logger) DroppedCount() int64 {
	return l.dropped.Load()
}

// Close flushes all pending events and closes the log file.
// It is safe to call Close multiple times.
func (l *Logger) Close() error {
	l.stopOnce.Do(func() {
		close(l.stopCh)
	})
	<-l.done
	return nil
}

// ---------------------------------------------------------------------------
// Write loop
// ---------------------------------------------------------------------------

// writeLoop reads events from the channel and writes them to the current day's
// log file. It runs in its own goroutine until Close is called.
func (l *Logger) writeLoop(retention int) {
	defer close(l.done)

	var (
		currentDate string
		file        *os.File
	)

	openFile := func(date string) error {
		if file != nil {
			file.Close()
		}
		path := l.filePath(date)
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return fmt.Errorf("audit: open log %q: %w", path, err)
		}
		file = f
		currentDate = date
		return nil
	}

	ensureFile := func() {
		today := time.Now().UTC().Format("2006-01-02")
		if file == nil || currentDate != today {
			if err := openFile(today); err != nil {
				l.dropped.Add(1)
				return
			}
			if retention > 0 {
				go l.deleteOldFiles(retention)
			}
		}
	}

	for {
		select {
		case ev := <-l.eventCh:
			ensureFile()
			l.writeEvent(file, ev)
			l.appendToRing(ev)

		case <-l.stopCh:
			// Drain all remaining events from the channel before exiting.
			for {
				select {
				case ev := <-l.eventCh:
					ensureFile()
					l.writeEvent(file, ev)
					l.appendToRing(ev)
				default:
					if file != nil {
						file.Close()
					}
					return
				}
			}
		}
	}
}

// writeEvent serializes ev as a JSON line and appends it to file.
func (l *Logger) writeEvent(file *os.File, ev Event) {
	if file == nil {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = file.Write(b)
}

// appendToRing adds ev to the in-memory ring buffer.
func (l *Logger) appendToRing(ev Event) {
	l.ringMu.Lock()
	defer l.ringMu.Unlock()
	l.ring[l.ringHead] = ev
	l.ringHead = (l.ringHead + 1) % len(l.ring)
}

// filePath returns the full path for the log file for the given date string
// (format "2006-01-02").
func (l *Logger) filePath(date string) string {
	return l.dir + "/audit-" + date + ".jsonl"
}

// deleteOldFiles removes log files older than retention days.
func (l *Logger) deleteOldFiles(retention int) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retention)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Parse the date from audit-YYYY-MM-DD.jsonl
		if len(name) < 17 || name[:6] != "audit-" || name[len(name)-6:] != ".jsonl" {
			continue
		}
		dateStr := name[6 : len(name)-6]
		t, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			_ = os.Remove(l.filePath(dateStr))
		}
	}
}

// ---------------------------------------------------------------------------
// UUID generation (time-ordered v7-like, stdlib only)
// ---------------------------------------------------------------------------

// newUUID generates a time-ordered UUID suitable for use as an event ID.
// It uses a 48-bit millisecond timestamp in the high bits followed by
// cryptographically random bytes, approximating UUID v7 without any external
// dependency.  crypto/rand is used instead of math/rand so that audit event
// IDs cannot be predicted by an attacker who knows the timestamp.
func newUUID() string {
	now := time.Now().UTC().UnixMilli()
	var b [16]byte

	// Bytes 0-5: 48-bit big-endian millisecond timestamp.
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)

	// Bytes 6-15: cryptographically random bytes with version/variant bits set.
	var rnd [10]byte
	if _, err := crand.Read(rnd[:]); err != nil {
		// crypto/rand failure is extremely rare; fall back to timestamp-only UUID
		// rather than panicking or using a predictable source.
		rnd = [10]byte{}
	}

	// Bytes 6-7: version (7) in high nibble of byte 6, random low bits.
	b[6] = 0x70 | (rnd[0] & 0x0f)
	b[7] = rnd[1]

	// Bytes 8-15: variant bits (10xx) in high bits of byte 8, rest random.
	b[8] = 0x80 | (rnd[2] & 0x3f)
	b[9] = rnd[3]
	b[10] = rnd[4]
	b[11] = rnd[5]
	b[12] = rnd[6]
	b[13] = rnd[7]
	b[14] = rnd[8]
	b[15] = rnd[9]

	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
