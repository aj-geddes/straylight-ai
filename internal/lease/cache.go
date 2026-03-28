// Package lease provides a lease-aware credential cache for vault dynamic secrets.
//
// The Manager handles lease tracking, automatic renewal, and revocation for
// database and cloud service credentials. HTTP proxy services with static
// credentials continue using the fixed-TTL cache in proxy.go.
//
// Usage:
//
//	manager := lease.NewManager(vaultClient)
//	defer manager.Close()
//
//	// Store a lease after getting credentials from vault.
//	manager.Store(serviceName, role, leaseInfo, credentials)
//
//	// Retrieve a valid (non-expired) lease.
//	l, ok := manager.Get(serviceName, role)
//
//	// On shutdown: revoke all active leases.
//	manager.RevokeAll()
package lease

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// renewalCheckInterval is the default tick interval for the renewal goroutine.
const renewalCheckInterval = 10 * time.Second

// renewalWindow is the default time before expiry at which renewal is attempted.
const renewalWindow = 30 * time.Second

// LeaseState represents the lifecycle state of a lease.
type LeaseState int

const (
	// LeaseActive indicates the lease is valid and has been claimed.
	LeaseActive LeaseState = iota
	// LeaseRenewing indicates the lease is currently being renewed.
	LeaseRenewing
	// LeaseExpired indicates the lease has expired and should be removed.
	LeaseExpired
)

// LeaseInfo holds the metadata returned by vault for a dynamic secret.
// It mirrors vault.LeaseInfo to avoid a circular import; the caller converts.
type LeaseInfo struct {
	// LeaseID is the vault lease identifier.
	LeaseID string
	// LeaseDuration is the TTL in seconds.
	LeaseDuration int
	// Renewable indicates whether the lease can be renewed.
	Renewable bool
}

// Lease tracks a single credential lease from vault.
type Lease struct {
	// ID is the vault lease ID.
	ID string
	// Service is the service this lease belongs to.
	Service string
	// Role is the vault role that generated this lease.
	Role string
	// Credentials holds the credential data (varies by engine type).
	Credentials map[string]string
	// IssuedAt is when the lease was issued.
	IssuedAt time.Time
	// ExpiresAt is the computed expiry time.
	ExpiresAt time.Time
	// TTL is the lease duration.
	TTL time.Duration
	// Renewable indicates whether this lease can be renewed.
	Renewable bool
	// State is the current lifecycle state.
	State LeaseState
}

// VaultClient is the subset of vault.Client needed for lease operations.
type VaultClient interface {
	RenewLease(leaseID string, increment int) (*LeaseInfo, error)
	RevokeLease(leaseID string) error
	RevokeLeasePrefix(prefix string) error
}

// ManagerOptions holds optional tuning parameters for the Manager.
type ManagerOptions struct {
	// RenewalInterval is how often the renewal goroutine checks leases.
	// Default: 10 seconds.
	RenewalInterval time.Duration

	// RenewalWindow is the time before expiry at which renewal is triggered.
	// Default: 30 seconds.
	RenewalWindow time.Duration
}

// Manager is a thread-safe lease-aware credential cache.
// It tracks vault leases, renews them before they expire, and revokes
// them on demand or shutdown.
type Manager struct {
	mu      sync.RWMutex
	leases  map[string]*Lease // key: "{service}/{role}"
	vault   VaultClient
	opts    ManagerOptions
	logger  *slog.Logger
	stopCh  chan struct{}
	stopped chan struct{}
}

// NewManager creates a Manager with default renewal options.
func NewManager(vc VaultClient) *Manager {
	return NewManagerWithOptions(vc, ManagerOptions{})
}

// NewManagerWithOptions creates a Manager with custom renewal options.
func NewManagerWithOptions(vc VaultClient, opts ManagerOptions) *Manager {
	if opts.RenewalInterval <= 0 {
		opts.RenewalInterval = renewalCheckInterval
	}
	if opts.RenewalWindow <= 0 {
		opts.RenewalWindow = renewalWindow
	}

	m := &Manager{
		leases:  make(map[string]*Lease),
		vault:   vc,
		opts:    opts,
		logger:  slog.Default(),
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go m.renewalLoop()
	return m
}

// cacheKey returns the map key for a service/role pair.
func cacheKey(service, role string) string {
	return service + "/" + role
}

// Store adds or replaces a lease in the cache.
// info comes from vault's dynamic credential response.
// creds holds the credential fields (e.g., username, password).
func (m *Manager) Store(service, role string, info *LeaseInfo, creds map[string]string) {
	ttl := time.Duration(info.LeaseDuration) * time.Second
	now := time.Now()

	l := &Lease{
		ID:          info.LeaseID,
		Service:     service,
		Role:        role,
		Credentials: creds,
		IssuedAt:    now,
		ExpiresAt:   now.Add(ttl),
		TTL:         ttl,
		Renewable:   info.Renewable,
		State:       LeaseActive,
	}

	m.mu.Lock()
	m.leases[cacheKey(service, role)] = l
	m.mu.Unlock()
}

// Get returns the active lease for the given service and role.
// Returns (nil, false) if no lease exists or the lease has expired.
// Expired leases are pruned from the cache on access.
func (m *Manager) Get(service, role string) (*Lease, bool) {
	key := cacheKey(service, role)

	// Read l.ExpiresAt under the RLock to avoid a data race with renewLease,
	// which writes l.ExpiresAt under a write lock.
	m.mu.RLock()
	l, ok := m.leases[key]
	var expired bool
	if ok {
		expired = time.Now().After(l.ExpiresAt)
	}
	m.mu.RUnlock()

	if !ok {
		return nil, false
	}

	if expired {
		// Expired — remove from cache.
		m.mu.Lock()
		delete(m.leases, key)
		m.mu.Unlock()
		return nil, false
	}

	return l, true
}

// All returns a snapshot of all currently cached leases.
// Expired leases are excluded.
func (m *Manager) All() []*Lease {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	out := make([]*Lease, 0, len(m.leases))
	for _, l := range m.leases {
		if !now.After(l.ExpiresAt) {
			out = append(out, l)
		}
	}
	return out
}

// Revoke revokes the lease for the given service and role, both in the cache
// and in vault. Returns an error if vault revocation fails; the cache entry
// is removed regardless.
func (m *Manager) Revoke(service, role string) error {
	key := cacheKey(service, role)

	m.mu.Lock()
	l, ok := m.leases[key]
	delete(m.leases, key)
	m.mu.Unlock()

	if !ok {
		return nil
	}

	if err := m.vault.RevokeLease(l.ID); err != nil {
		return fmt.Errorf("lease: revoke %q: %w", l.ID, err)
	}
	return nil
}

// RevokeAll revokes all active leases. This is called during server shutdown.
// Errors are logged but do not stop revocation of remaining leases.
func (m *Manager) RevokeAll() {
	m.mu.Lock()
	leases := make([]*Lease, 0, len(m.leases))
	for _, l := range m.leases {
		leases = append(leases, l)
	}
	m.leases = make(map[string]*Lease)
	m.mu.Unlock()

	for _, l := range leases {
		if err := m.vault.RevokeLease(l.ID); err != nil {
			m.logger.Warn("lease: revoke on shutdown failed",
				"lease_id", l.ID,
				"service", l.Service,
				"error", err,
			)
		}
	}
}

// Close stops the renewal goroutine. It does not revoke leases; call RevokeAll
// before Close for clean shutdown.
func (m *Manager) Close() {
	select {
	case <-m.stopCh:
		// Already closed.
	default:
		close(m.stopCh)
	}
	<-m.stopped
}

// ---------------------------------------------------------------------------
// Renewal goroutine
// ---------------------------------------------------------------------------

// renewalLoop checks all leases at each tick and renews those that are within
// the renewal window of expiry.
func (m *Manager) renewalLoop() {
	defer close(m.stopped)

	ticker := time.NewTicker(m.opts.RenewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAndRenew()
		case <-m.stopCh:
			return
		}
	}
}

// checkAndRenew iterates all active leases and triggers renewal for those
// within the renewal window.
//
// The implementation uses a two-phase locking strategy to avoid a data race:
//  1. Collect candidates under RLock WITHOUT mutating any lease state.
//  2. Upgrade to a write lock and set State = LeaseRenewing (re-checking
//     State == LeaseActive to guard against double-scheduling).
//  3. Dispatch goroutines outside the lock.
func (m *Manager) checkAndRenew() {
	now := time.Now()

	m.mu.RLock()
	candidates := make([]*Lease, 0)
	for _, l := range m.leases {
		if l.State == LeaseActive && l.Renewable {
			remaining := l.ExpiresAt.Sub(now)
			if remaining < m.opts.RenewalWindow {
				candidates = append(candidates, l)
			}
		}
	}
	m.mu.RUnlock()

	if len(candidates) > 0 {
		m.mu.Lock()
		for _, l := range candidates {
			// Re-check state after acquiring the write lock: another goroutine
			// may have already set it to LeaseRenewing or LeaseExpired.
			if l.State == LeaseActive {
				l.State = LeaseRenewing
			}
		}
		m.mu.Unlock()
	}

	for _, l := range candidates {
		if l.State == LeaseRenewing {
			go m.renewLease(l)
		}
	}
}

// renewLease attempts to renew a single lease. On success, the expiry is
// extended. On failure, the lease is removed from the cache.
func (m *Manager) renewLease(l *Lease) {
	incrementSeconds := int(l.TTL.Seconds())
	info, err := m.vault.RenewLease(l.ID, incrementSeconds)
	if err != nil {
		m.logger.Warn("lease: renewal failed, removing from cache",
			"lease_id", l.ID,
			"service", l.Service,
			"error", err,
		)
		key := cacheKey(l.Service, l.Role)
		m.mu.Lock()
		delete(m.leases, key)
		m.mu.Unlock()
		return
	}

	newTTL := time.Duration(info.LeaseDuration) * time.Second
	m.mu.Lock()
	l.ExpiresAt = time.Now().Add(newTTL)
	l.TTL = newTTL
	l.State = LeaseActive
	m.mu.Unlock()

	m.logger.Debug("lease: renewed",
		"lease_id", l.ID,
		"service", l.Service,
		"new_ttl_seconds", info.LeaseDuration,
	)
}
