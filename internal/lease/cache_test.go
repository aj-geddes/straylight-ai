// Package lease_test contains tests for the lease-aware credential cache.
package lease_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/lease"
)

// ---------------------------------------------------------------------------
// Mock vault client
// ---------------------------------------------------------------------------

type mockVaultClient struct {
	mu            sync.Mutex
	renewCalls    int
	revokeCalls   int
	revokePrefixCalls int
	renewErr      error
	revokeErr     error
	renewedTTL    int
}

func (m *mockVaultClient) RenewLease(leaseID string, increment int) (*lease.LeaseInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renewCalls++
	if m.renewErr != nil {
		return nil, m.renewErr
	}
	ttl := m.renewedTTL
	if ttl == 0 {
		ttl = increment
	}
	return &lease.LeaseInfo{
		LeaseID:       leaseID,
		LeaseDuration: ttl,
		Renewable:     true,
	}, nil
}

func (m *mockVaultClient) RevokeLease(leaseID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeCalls++
	return m.revokeErr
}

func (m *mockVaultClient) RevokeLeasePrefix(prefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokePrefixCalls++
	return nil
}

// ---------------------------------------------------------------------------
// Mock audit emitter
// ---------------------------------------------------------------------------

type mockEmitter struct {
	mu     sync.Mutex
	events []string // event type strings
}

func (m *mockEmitter) EmitLeaseEvent(eventType, leaseID, service, role string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, eventType)
}

func (m *mockEmitter) count(eventType string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.events {
		if e == eventType {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// TestNewManager_Empty verifies a new manager has no leases.
// ---------------------------------------------------------------------------

func TestNewManager_Empty(t *testing.T) {
	vc := &mockVaultClient{}
	m := lease.NewManager(vc)
	defer m.Close()

	leases := m.All()
	if len(leases) != 0 {
		t.Errorf("expected 0 leases, got %d", len(leases))
	}
}

// ---------------------------------------------------------------------------
// TestStore_AddsLease verifies Store adds a lease and it is retrievable.
// ---------------------------------------------------------------------------

func TestStore_AddsLease(t *testing.T) {
	vc := &mockVaultClient{}
	m := lease.NewManager(vc)
	defer m.Close()

	info := &lease.LeaseInfo{
		LeaseID:       "database/creds/pg-ro/abc123",
		LeaseDuration: 300,
		Renewable:     true,
	}
	creds := map[string]string{"username": "v-pg-user", "password": "s3cr3t"}

	m.Store("pg", "readonly", info, creds)

	l, ok := m.Get("pg", "readonly")
	if !ok {
		t.Fatal("expected lease to be stored, got not found")
	}
	if l.ID != info.LeaseID {
		t.Errorf("lease ID = %q, want %q", l.ID, info.LeaseID)
	}
}

// ---------------------------------------------------------------------------
// TestGet_ReturnsNotFoundForMissing verifies Get returns false for unknown key.
// ---------------------------------------------------------------------------

func TestGet_ReturnsNotFoundForMissing(t *testing.T) {
	vc := &mockVaultClient{}
	m := lease.NewManager(vc)
	defer m.Close()

	_, ok := m.Get("unknown", "role")
	if ok {
		t.Error("expected not found for unknown service/role, got found")
	}
}

// ---------------------------------------------------------------------------
// TestGet_ReturnsNotFoundForExpiredLease verifies expired leases are not returned.
// ---------------------------------------------------------------------------

func TestGet_ReturnsNotFoundForExpiredLease(t *testing.T) {
	vc := &mockVaultClient{}
	m := lease.NewManager(vc)
	defer m.Close()

	// Store a lease with a TTL already in the past.
	info := &lease.LeaseInfo{
		LeaseID:       "database/creds/pg-ro/expired",
		LeaseDuration: 1, // 1 second
		Renewable:     false,
	}
	m.Store("pg", "readonly", info, map[string]string{"username": "u", "password": "p"})

	// Manually expire by sleeping past the TTL.
	time.Sleep(1100 * time.Millisecond)

	_, ok := m.Get("pg", "readonly")
	if ok {
		t.Error("expected expired lease to not be returned, got found")
	}
}

// ---------------------------------------------------------------------------
// TestRevoke_RemovesLease verifies Revoke removes a lease and calls vault.
// ---------------------------------------------------------------------------

func TestRevoke_RemovesLease(t *testing.T) {
	vc := &mockVaultClient{}
	m := lease.NewManager(vc)
	defer m.Close()

	info := &lease.LeaseInfo{
		LeaseID:       "database/creds/pg-ro/abc",
		LeaseDuration: 300,
		Renewable:     true,
	}
	m.Store("pg", "readonly", info, map[string]string{"username": "u", "password": "p"})

	if err := m.Revoke("pg", "readonly"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, ok := m.Get("pg", "readonly")
	if ok {
		t.Error("expected lease to be removed after revoke, got found")
	}

	vc.mu.Lock()
	calls := vc.revokeCalls
	vc.mu.Unlock()
	if calls != 1 {
		t.Errorf("expected 1 vault RevokeLease call, got %d", calls)
	}
}

// ---------------------------------------------------------------------------
// TestRevokeAll_RemovesAllLeases verifies RevokeAll clears all leases.
// ---------------------------------------------------------------------------

func TestRevokeAll_RemovesAllLeases(t *testing.T) {
	vc := &mockVaultClient{}
	m := lease.NewManager(vc)
	defer m.Close()

	for _, svc := range []string{"pg", "mysql", "redis"} {
		m.Store(svc, "readonly", &lease.LeaseInfo{
			LeaseID:       "database/creds/" + svc + "/abc",
			LeaseDuration: 300,
			Renewable:     true,
		}, map[string]string{"username": "u", "password": "p"})
	}

	m.RevokeAll()

	leases := m.All()
	if len(leases) != 0 {
		t.Errorf("expected 0 leases after RevokeAll, got %d", len(leases))
	}

	vc.mu.Lock()
	calls := vc.revokeCalls
	vc.mu.Unlock()
	if calls != 3 {
		t.Errorf("expected 3 RevokeLease calls, got %d", calls)
	}
}

// ---------------------------------------------------------------------------
// TestRenewalTriggered verifies that a lease near expiry triggers renewal.
// ---------------------------------------------------------------------------

func TestRenewalTriggered(t *testing.T) {
	vc := &mockVaultClient{renewedTTL: 300}
	// Use a short renewal check interval so we don't wait long.
	m := lease.NewManagerWithOptions(vc, lease.ManagerOptions{
		RenewalInterval: 50 * time.Millisecond,
		RenewalWindow:   5 * time.Second,
	})
	defer m.Close()

	// Store a lease that will expire in 3 seconds (within the 5s renewal window).
	info := &lease.LeaseInfo{
		LeaseID:       "database/creds/pg-ro/near-expiry",
		LeaseDuration: 3,
		Renewable:     true,
	}
	m.Store("pg", "readonly", info, map[string]string{"username": "u", "password": "p"})

	// Wait for the renewal goroutine to fire.
	time.Sleep(200 * time.Millisecond)

	vc.mu.Lock()
	calls := vc.renewCalls
	vc.mu.Unlock()

	if calls == 0 {
		t.Error("expected at least one RenewLease call for near-expiry lease, got 0")
	}
}

// ---------------------------------------------------------------------------
// TestRenewalFailed_RemovesLease verifies a failed renewal removes the lease.
// ---------------------------------------------------------------------------

func TestRenewalFailed_RemovesLease(t *testing.T) {
	vc := &mockVaultClient{renewErr: errors.New("vault unavailable")}
	m := lease.NewManagerWithOptions(vc, lease.ManagerOptions{
		RenewalInterval: 50 * time.Millisecond,
		RenewalWindow:   10 * time.Second,
	})
	defer m.Close()

	// Lease expires in 5 seconds — within the 10s renewal window.
	info := &lease.LeaseInfo{
		LeaseID:       "database/creds/pg-ro/will-fail",
		LeaseDuration: 5,
		Renewable:     true,
	}
	m.Store("pg", "readonly", info, map[string]string{"username": "u", "password": "p"})

	// Wait for renewal to attempt and fail.
	time.Sleep(200 * time.Millisecond)

	_, ok := m.Get("pg", "readonly")
	if ok {
		t.Error("expected lease to be removed after failed renewal, got found")
	}
}

// ---------------------------------------------------------------------------
// TestConcurrentStoreGet verifies thread-safety of Store and Get.
// ---------------------------------------------------------------------------

func TestConcurrentStoreGet(t *testing.T) {
	vc := &mockVaultClient{}
	m := lease.NewManager(vc)
	defer m.Close()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			svc := "svc"
			role := "role"
			info := &lease.LeaseInfo{
				LeaseID:       "lease-id",
				LeaseDuration: 300,
				Renewable:     true,
			}
			m.Store(svc, role, info, map[string]string{"k": "v"})
			m.Get(svc, role)
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TestLeaseInfo_FieldsExposed verifies LeaseInfo has expected exported fields.
// ---------------------------------------------------------------------------

func TestLeaseInfo_FieldsExposed(t *testing.T) {
	info := lease.LeaseInfo{
		LeaseID:       "test-id",
		LeaseDuration: 60,
		Renewable:     true,
	}
	if info.LeaseID != "test-id" {
		t.Errorf("LeaseID = %q, want %q", info.LeaseID, "test-id")
	}
	if info.LeaseDuration != 60 {
		t.Errorf("LeaseDuration = %d, want 60", info.LeaseDuration)
	}
	if !info.Renewable {
		t.Error("expected Renewable = true")
	}
}
