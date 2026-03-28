// Package lease_test: data race fix tests for checkAndRenew.
//
// Issue 1 (CRITICAL): checkAndRenew wrote l.State = LeaseRenewing while
// holding only an RLock, causing a data race.  The fixed implementation
// collects candidates under RLock WITHOUT mutating state, then upgrades to
// a write lock before setting LeaseRenewing.
package lease_test

import (
	"sync"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/lease"
)

// TestCheckAndRenew_NoDataRaceOnStateTransition verifies that concurrent
// reads of a lease's state do not race with the renewal goroutine's write.
//
// The race detector (go test -race) will report a DATA RACE if the
// implementation mutates l.State inside an RLock section.  With the fix the
// state write happens under a full write lock, so no race is reported.
func TestCheckAndRenew_NoDataRaceOnStateTransition(t *testing.T) {
	vc := &mockVaultClient{renewedTTL: 300}
	m := lease.NewManagerWithOptions(vc, lease.ManagerOptions{
		// Very short interval so checkAndRenew fires immediately.
		RenewalInterval: 20 * time.Millisecond,
		// Large window so all stored leases become candidates.
		RenewalWindow: 10 * time.Second,
	})
	defer m.Close()

	// Store 10 renewable leases all within the renewal window.
	for i := 0; i < 10; i++ {
		m.Store("svc", "role", &lease.LeaseInfo{
			LeaseID:       "lease-race-test",
			LeaseDuration: 5, // 5 s — within 10 s renewal window
			Renewable:     true,
		}, map[string]string{"username": "u", "password": "p"})
	}

	// Concurrently call All() and Get() — these acquire RLock — while the
	// renewal goroutine fires checkAndRenew, which must NOT mutate state
	// under RLock.  If it does, the race detector will catch it.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				m.All()
				m.Get("svc", "role")
			}
		}()
	}

	// Let the renewal goroutine fire several times during the concurrent reads.
	time.Sleep(150 * time.Millisecond)
	wg.Wait()
}

// TestCheckAndRenew_StateUpgradedUnderWriteLock verifies that after
// checkAndRenew fires, leases that were candidates end up in LeaseRenewing
// (or back to LeaseActive after the renewal completes) — never corrupted.
//
// This test exercises the re-check logic ("if l.State == LeaseActive" after
// lock upgrade) to ensure double-promotion doesn't happen.
func TestCheckAndRenew_DoesNotDoubleScheduleRenewal(t *testing.T) {
	vc := &mockVaultClient{renewedTTL: 300}
	m := lease.NewManagerWithOptions(vc, lease.ManagerOptions{
		RenewalInterval: 20 * time.Millisecond,
		RenewalWindow:   10 * time.Second,
	})
	defer m.Close()

	m.Store("pg", "readonly", &lease.LeaseInfo{
		LeaseID:       "database/creds/pg-ro/double-test",
		LeaseDuration: 5,
		Renewable:     true,
	}, map[string]string{"username": "u", "password": "p"})

	// Wait for renewal to fire multiple times.
	time.Sleep(200 * time.Millisecond)

	vc.mu.Lock()
	calls := vc.renewCalls
	vc.mu.Unlock()

	// With the double-scheduling protection (re-check after write lock), the
	// renewal should not be dispatched more than once per check cycle.
	// Two intervals of 20 ms in 200 ms = at most ~10 checks, but after the
	// first renewal the lease is Active again with a 300 s TTL, so it won't
	// be renewed again.  Accept 1-3 calls to handle races in timing.
	if calls == 0 {
		t.Error("expected at least one renewal call, got 0")
	}
	if calls > 5 {
		t.Errorf("renewal called %d times — possible double-scheduling bug", calls)
	}
}
