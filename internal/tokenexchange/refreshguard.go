package tokenexchange

import (
	"context"
	"sync"
)

// RefreshGuard serializes refreshes per credential key and collapses concurrent
// calls into a single flight, then releases all waiters with the same result.
// Errors are NOT cached; a subsequent call will invoke fn again.
type RefreshGuard struct {
	mu       sync.Mutex
	inflight map[string]*guardCall
}

// guardCall holds the state of an in-flight Do invocation.
type guardCall struct {
	done   chan struct{}
	result map[string]string
	err    error
}

// NewRefreshGuard returns a new RefreshGuard.
func NewRefreshGuard() *RefreshGuard {
	return &RefreshGuard{
		inflight: make(map[string]*guardCall),
	}
}

// Do runs fn under a per-key single-flight guard. If a call for key is already
// in-flight, Do blocks until it completes and returns that call's result.
// fn is invoked at most once per concurrent group. Errors suppress caching so
// the next call retries.
func (g *RefreshGuard) Do(ctx context.Context, key string, fn func(ctx context.Context) (map[string]string, error)) (map[string]string, error) {
	g.mu.Lock()
	if call, ok := g.inflight[key]; ok {
		// Another goroutine is already running fn for this key — wait for it.
		g.mu.Unlock()
		<-call.done
		return call.result, call.err
	}

	// First caller: register as the flight leader.
	call := &guardCall{done: make(chan struct{})}
	g.inflight[key] = call
	g.mu.Unlock()

	// Execute fn outside any lock.
	result, err := fn(ctx)

	// Publish result, then release waiters.
	g.mu.Lock()
	call.result = result
	call.err = err
	delete(g.inflight, key) // remove before close so next call retries on error
	close(call.done)
	g.mu.Unlock()

	return result, err
}
