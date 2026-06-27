// Package tokenexchange_test tests the RefreshGuard single-flight mechanism.
package tokenexchange_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// ---------------------------------------------------------------------------
// TestRefreshGuard_ConcurrentSameKey_FnCalledOnce — 50 concurrent Do calls
// with the same key result in fn being called exactly once; all callers receive
// the same result.
// ---------------------------------------------------------------------------

func TestRefreshGuard_ConcurrentSameKey_FnCalledOnce(t *testing.T) {
	rg := tokenexchange.NewRefreshGuard()

	var callCount int32
	var mu sync.Mutex
	var results []map[string]string

	fn := func(_ context.Context) (map[string]string, error) {
		atomic.AddInt32(&callCount, 1)
		time.Sleep(10 * time.Millisecond)
		return map[string]string{"token": "test-token", "expiry": "9999999999"}, nil
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			result, err := rg.Do(context.Background(), "same-key", fn)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if count := atomic.LoadInt32(&callCount); count != 1 {
		t.Errorf("fn called %d times, want 1 (single-flight)", count)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(results) != n {
		t.Errorf("collected %d results, want %d", len(results), n)
	}
	expected := map[string]string{"token": "test-token", "expiry": "9999999999"}
	for i, r := range results {
		for k, v := range expected {
			if r[k] != v {
				t.Errorf("result[%d][%q] = %q, want %q", i, k, r[k], v)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// TestRefreshGuard_DifferentKeys_RunConcurrently — different keys do not
// serialize against each other; both run concurrently.
// ---------------------------------------------------------------------------

func TestRefreshGuard_DifferentKeys_RunConcurrently(t *testing.T) {
	rg := tokenexchange.NewRefreshGuard()

	var count1, count2 int32

	fn1 := func(_ context.Context) (map[string]string, error) {
		atomic.AddInt32(&count1, 1)
		time.Sleep(5 * time.Millisecond)
		return map[string]string{"key": "value1"}, nil
	}
	fn2 := func(_ context.Context) (map[string]string, error) {
		atomic.AddInt32(&count2, 1)
		time.Sleep(5 * time.Millisecond)
		return map[string]string{"key": "value2"}, nil
	}

	var (
		result1, result2 map[string]string
		err1, err2       error
		wg               sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		result1, err1 = rg.Do(context.Background(), "key1", fn1)
	}()
	go func() {
		defer wg.Done()
		result2, err2 = rg.Do(context.Background(), "key2", fn2)
	}()
	wg.Wait()

	if err1 != nil {
		t.Errorf("key1 error: %v", err1)
	}
	if err2 != nil {
		t.Errorf("key2 error: %v", err2)
	}
	if atomic.LoadInt32(&count1) != 1 {
		t.Errorf("fn1 called %d times, want 1", count1)
	}
	if atomic.LoadInt32(&count2) != 1 {
		t.Errorf("fn2 called %d times, want 1", count2)
	}
	if result1["key"] != "value1" {
		t.Errorf("result1[key] = %q, want %q", result1["key"], "value1")
	}
	if result2["key"] != "value2" {
		t.Errorf("result2[key] = %q, want %q", result2["key"], "value2")
	}
}

// ---------------------------------------------------------------------------
// TestRefreshGuard_FnError_ResultNotCached — when fn returns an error, the
// result is NOT cached; a subsequent Do call runs fn again.
// ---------------------------------------------------------------------------

func TestRefreshGuard_FnError_ResultNotCached(t *testing.T) {
	rg := tokenexchange.NewRefreshGuard()

	var callCount int32

	// First call: fn returns error.
	_, err := rg.Do(context.Background(), "error-key", func(_ context.Context) (map[string]string, error) {
		atomic.AddInt32(&callCount, 1)
		return nil, errors.New("simulated failure")
	})
	if err == nil {
		t.Fatal("expected error on first Do, got nil")
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Fatalf("fn called %d times on first Do, want 1", callCount)
	}

	// Second call with same key: fn must be called again (error not cached).
	result, err := rg.Do(context.Background(), "error-key", func(_ context.Context) (map[string]string, error) {
		atomic.AddInt32(&callCount, 1)
		return map[string]string{"token": "recovered-token"}, nil
	})
	if err != nil {
		t.Fatalf("second Do: %v", err)
	}
	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("fn called %d times total, want 2 (second call must not be cached)", callCount)
	}
	if result["token"] != "recovered-token" {
		t.Errorf("result[token] = %q, want %q", result["token"], "recovered-token")
	}
}
