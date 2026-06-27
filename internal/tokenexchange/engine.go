package tokenexchange

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// entryState describes the lifecycle state of a cache entry.
type entryState int

const (
	// entryActive means the credential is valid and can be served.
	entryActive entryState = iota
	// entryRefreshing means a background refresh is in progress.
	entryRefreshing
)

// defaultRefreshWindow is how far ahead of expiry the engine proactively
// refreshes a credential (mirrors PRODUCT-STRATEGY.md §3.2).
const defaultRefreshWindow = 5 * time.Minute

// defaultCheckInterval is the period of the background refresh ticker.
const defaultCheckInterval = 30 * time.Second

// cacheEntry holds a cached credential and the metadata needed to re-exchange.
type cacheEntry struct {
	cred     *ExchangedCredential
	provider string
	input    ExchangeInput // stored so the refresh loop can re-issue the exchange
	state    entryState
}

// inflightCall represents a synchronous exchange that is in progress, so that
// concurrent callers for the same key can join without stampeding the provider.
type inflightCall struct {
	done chan struct{}
	cred *ExchangedCredential
	err  error
}

// EngineConfig wires the Engine.
type EngineConfig struct {
	// Source is the identity-proof provider used to mint the subject_token.
	Source IdentitySource
	// Adapters maps ProviderType to its ExchangeAdapter. At least one is
	// required; Credential returns an error for unknown providers.
	Adapters map[string]ExchangeAdapter
	// RefreshWindow is how far ahead of expiry a proactive refresh fires.
	// Default: 5 minutes.
	RefreshWindow time.Duration
	// CheckInterval controls how often the refresh ticker runs.
	// Default: 30 seconds.
	CheckInterval time.Duration
}

// Engine ties an IdentitySource to a set of ExchangeAdapters and a cache with
// proactive refresh. It is safe for concurrent use.
type Engine struct {
	source        IdentitySource
	adapters      map[string]ExchangeAdapter
	refreshWindow time.Duration
	checkInterval time.Duration

	cacheMu sync.RWMutex
	cache   map[string]*cacheEntry

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall

	stopCh  chan struct{}
	stopped chan struct{}
}

// NewEngine constructs an Engine and starts the background refresh goroutine.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.RefreshWindow <= 0 {
		cfg.RefreshWindow = defaultRefreshWindow
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = defaultCheckInterval
	}

	e := &Engine{
		source:        cfg.Source,
		adapters:      cfg.Adapters,
		refreshWindow: cfg.RefreshWindow,
		checkInterval: cfg.CheckInterval,
		cache:         make(map[string]*cacheEntry),
		inflight:      make(map[string]*inflightCall),
		stopCh:        make(chan struct{}),
		stopped:       make(chan struct{}),
	}
	go e.refreshLoop()
	return e
}

// Credential returns a valid (cached or freshly exchanged) credential for the
// given cache key and provider. cacheKey is typically the service name.
//
// The Audience field of in must be non-empty; an empty audience is rejected
// to enforce the MCP no-passthrough rule: the engine cannot relay an inbound
// token, and every minted credential must be audience-scoped.
func (e *Engine) Credential(ctx context.Context, cacheKey, provider string, in ExchangeInput) (*ExchangedCredential, error) {
	// ── 1. Validate audience (MCP no-passthrough) ──────────────────────────
	if in.Audience == "" {
		return nil, fmt.Errorf("tokenexchange: audience is required (MCP no-passthrough enforcement)")
	}

	// ── 2. Validate provider ───────────────────────────────────────────────
	if _, ok := e.adapters[provider]; !ok {
		return nil, fmt.Errorf("tokenexchange: no adapter registered for provider %q", provider)
	}

	// ── 3. Cache lookup ────────────────────────────────────────────────────
	e.cacheMu.RLock()
	entry, hit := e.cache[cacheKey]
	if hit && !time.Now().After(entry.cred.ExpiresAt) {
		cred := entry.cred
		e.cacheMu.RUnlock()
		// Proactively refresh when within the refresh window but don't block.
		if time.Until(cred.ExpiresAt) < e.refreshWindow {
			e.triggerBackgroundRefresh(cacheKey, entry)
		}
		return cred, nil
	}
	e.cacheMu.RUnlock()

	// ── 4. Single-flight: join an in-flight exchange or start a new one ────
	e.inflightMu.Lock()
	if call, ok := e.inflight[cacheKey]; ok {
		e.inflightMu.Unlock()
		<-call.done
		return call.cred, call.err
	}
	call := &inflightCall{done: make(chan struct{})}
	e.inflight[cacheKey] = call
	e.inflightMu.Unlock()

	// ── 5. Perform the exchange ────────────────────────────────────────────
	cred, err := e.doExchange(ctx, cacheKey, provider, in)

	// ── 6. Signal waiters and store result ────────────────────────────────
	call.cred = cred
	call.err = err

	e.inflightMu.Lock()
	delete(e.inflight, cacheKey)
	close(call.done)
	e.inflightMu.Unlock()

	if err != nil {
		return nil, err
	}

	// Store in cache.
	e.cacheMu.Lock()
	e.cache[cacheKey] = &cacheEntry{
		cred:     cred,
		provider: provider,
		input:    in,
		state:    entryActive,
	}
	e.cacheMu.Unlock()

	return cred, nil
}

// doExchange obtains an identity proof and calls the adapter.
func (e *Engine) doExchange(ctx context.Context, cacheKey, provider string, in ExchangeInput) (*ExchangedCredential, error) {
	proof, err := e.source.Identity(ctx, IdentityRequest{
		Audience: in.Audience,
	})
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: identity source error for %q: %w", cacheKey, err)
	}
	in.Proof = proof

	cred, err := e.adapters[provider].Exchange(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: adapter %q exchange error for %q: %w", provider, cacheKey, err)
	}
	return cred, nil
}

// triggerBackgroundRefresh starts a goroutine to refresh the entry if not
// already refreshing. It does not block the caller.
func (e *Engine) triggerBackgroundRefresh(cacheKey string, entry *cacheEntry) {
	e.cacheMu.Lock()
	if entry.state != entryActive {
		e.cacheMu.Unlock()
		return
	}
	entry.state = entryRefreshing
	e.cacheMu.Unlock()

	go e.backgroundRefresh(cacheKey, entry.provider, entry.input)
}

// backgroundRefresh performs a single re-exchange and writes the new credential
// into the cache. On error, the entry is removed so the next Credential() call
// performs a fresh synchronous exchange.
func (e *Engine) backgroundRefresh(cacheKey, provider string, in ExchangeInput) {
	cred, err := e.doExchange(context.Background(), cacheKey, provider, in)

	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()

	if err != nil {
		delete(e.cache, cacheKey)
		return
	}

	// Only update if we are the refresh in progress (state may have changed).
	if existing, ok := e.cache[cacheKey]; ok && existing.state == entryRefreshing {
		e.cache[cacheKey] = &cacheEntry{
			cred:     cred,
			provider: provider,
			input:    in,
			state:    entryActive,
		}
	} else if !ok {
		// Entry was Invalidated while we were refreshing; write the fresh cred.
		e.cache[cacheKey] = &cacheEntry{
			cred:     cred,
			provider: provider,
			input:    in,
			state:    entryActive,
		}
	}
}

// Invalidate drops the cached credential for cacheKey, forcing a fresh exchange
// on the next Credential() call.
func (e *Engine) Invalidate(cacheKey string) {
	e.cacheMu.Lock()
	delete(e.cache, cacheKey)
	e.cacheMu.Unlock()
}

// Close stops the background refresh goroutine. It waits until the goroutine
// has exited before returning.
func (e *Engine) Close() {
	close(e.stopCh)
	<-e.stopped
}

// ---------------------------------------------------------------------------
// Background refresh loop (mirrors internal/lease/cache.go)
// ---------------------------------------------------------------------------

// refreshLoop runs the periodic proactive-refresh ticker. It mirrors the
// two-phase locking discipline of internal/lease/cache.go:
//
//  1. Collect candidates under RLock without mutating state.
//  2. Upgrade to write lock, re-check state, mark entryRefreshing.
//  3. Dispatch goroutines outside the lock.
func (e *Engine) refreshLoop() {
	defer close(e.stopped)

	ticker := time.NewTicker(e.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.checkAndRefresh()
		case <-e.stopCh:
			return
		}
	}
}

// checkAndRefresh scans the cache for entries within the refresh window and
// launches background refresh goroutines for eligible entries.
func (e *Engine) checkAndRefresh() {
	now := time.Now()

	// Phase 1: collect candidates under RLock.
	e.cacheMu.RLock()
	type candidate struct {
		key      string
		entry    *cacheEntry
		provider string
		input    ExchangeInput
	}
	var candidates []candidate
	for k, ent := range e.cache {
		if ent.state == entryActive && time.Until(ent.cred.ExpiresAt) < e.refreshWindow {
			candidates = append(candidates, candidate{k, ent, ent.provider, ent.input})
		}
	}
	e.cacheMu.RUnlock()

	if len(candidates) == 0 {
		return
	}

	// Phase 2: mark candidates as refreshing under write lock, re-checking state.
	e.cacheMu.Lock()
	var toRefresh []candidate
	for _, c := range candidates {
		ent, ok := e.cache[c.key]
		if ok && ent.state == entryActive && now.Before(ent.cred.ExpiresAt) {
			ent.state = entryRefreshing
			toRefresh = append(toRefresh, candidate{c.key, ent, ent.provider, ent.input})
		}
	}
	e.cacheMu.Unlock()

	// Phase 3: dispatch goroutines.
	for _, c := range toRefresh {
		go e.backgroundRefresh(c.key, c.provider, c.input)
	}
}
