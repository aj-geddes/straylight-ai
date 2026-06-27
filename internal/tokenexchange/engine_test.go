// Package tokenexchange_test tests the RFC 8693 token-exchange engine.
package tokenexchange_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// ---------------------------------------------------------------------------
// In-package fakes
// ---------------------------------------------------------------------------

// fakeIdentitySource always returns a valid proof scoped to the requested audience.
type fakeIdentitySource struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeIdentitySource) Identity(_ context.Context, _ tokenexchange.IdentityRequest) (*tokenexchange.IdentityProof, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &tokenexchange.IdentityProof{
		Token:     "fake-identity-token",
		TokenType: "urn:ietf:params:oauth:token-type:jwt",
		Issuer:    "https://openbao.example.internal",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}, nil
}

func (f *fakeIdentitySource) SourceType() string { return "fake" }

// fakeAdapter records Exchange calls and returns a preset credential.
type fakeAdapter struct {
	calls int32 // accessed atomically
	mu    sync.Mutex
	cred  *tokenexchange.ExchangedCredential
	err   error
	delay time.Duration
}

func (a *fakeAdapter) Exchange(_ context.Context, in tokenexchange.ExchangeInput) (*tokenexchange.ExchangedCredential, error) {
	if a.delay > 0 {
		time.Sleep(a.delay)
	}
	atomic.AddInt32(&a.calls, 1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	cred := a.cred
	if cred == nil {
		cred = &tokenexchange.ExchangedCredential{
			EnvVars:   map[string]string{"TOKEN": "fake-token"},
			ExpiresAt: time.Now().Add(15 * time.Minute),
			Audience:  in.Audience,
			Scope:     "fake-scope",
		}
	}
	return cred, nil
}

func (a *fakeAdapter) ProviderType() string { return "fake" }
func (a *fakeAdapter) CallCount() int32     { return atomic.LoadInt32(&a.calls) }

// setCred safely updates the credential returned by the adapter.
func (a *fakeAdapter) setCred(c *tokenexchange.ExchangedCredential) {
	a.mu.Lock()
	a.cred = c
	a.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestEngine(t *testing.T, adapter *fakeAdapter, opts ...func(*tokenexchange.EngineConfig)) *tokenexchange.Engine {
	t.Helper()
	cfg := tokenexchange.EngineConfig{
		Source: &fakeIdentitySource{},
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"fake": adapter,
		},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 50 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	e := tokenexchange.NewEngine(cfg)
	t.Cleanup(e.Close)
	return e
}

func validInput(audience string) tokenexchange.ExchangeInput {
	return tokenexchange.ExchangeInput{
		Audience:     audience,
		RequestedTTL: 15 * time.Minute,
	}
}

// ---------------------------------------------------------------------------
// TestExchange_SuccessReturnsCreds — successful exchange returns credentials.
// ---------------------------------------------------------------------------

func TestExchange_SuccessReturnsCreds(t *testing.T) {
	adapter := &fakeAdapter{}
	e := newTestEngine(t, adapter)

	cred, err := e.Credential(context.Background(), "svc-a", "fake", validInput("aud:provider"))
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if cred.Audience != "aud:provider" {
		t.Errorf("Audience = %q, want %q", cred.Audience, "aud:provider")
	}
	if adapter.CallCount() != 1 {
		t.Errorf("adapter calls = %d, want 1", adapter.CallCount())
	}
}

// ---------------------------------------------------------------------------
// TestEngine_CacheHit_AdapterCalledOnce — second call within TTL uses cache.
// ---------------------------------------------------------------------------

func TestEngine_CacheHit_AdapterCalledOnce(t *testing.T) {
	adapter := &fakeAdapter{}
	e := newTestEngine(t, adapter)
	ctx := context.Background()

	if _, err := e.Credential(ctx, "svc-b", "fake", validInput("aud:b")); err != nil {
		t.Fatalf("first Credential: %v", err)
	}
	if _, err := e.Credential(ctx, "svc-b", "fake", validInput("aud:b")); err != nil {
		t.Fatalf("second Credential: %v", err)
	}

	if adapter.CallCount() != 1 {
		t.Errorf("adapter calls = %d, want 1 (second call must hit cache)", adapter.CallCount())
	}
}

// ---------------------------------------------------------------------------
// TestEngine_EmptyAudience_Rejected — MCP no-passthrough: empty audience errors.
// ---------------------------------------------------------------------------

func TestEngine_EmptyAudience_Rejected(t *testing.T) {
	adapter := &fakeAdapter{}
	e := newTestEngine(t, adapter)

	_, err := e.Credential(context.Background(), "svc-c", "fake", tokenexchange.ExchangeInput{
		Audience:     "",
		RequestedTTL: 15 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for empty audience, got nil")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("error %q does not mention 'audience'", err.Error())
	}
	if adapter.CallCount() != 0 {
		t.Errorf("adapter calls = %d, want 0 (rejected before exchange)", adapter.CallCount())
	}
}

// ---------------------------------------------------------------------------
// TestEngine_Invalidate_ForcesRefresh — Invalidate causes re-exchange.
// ---------------------------------------------------------------------------

func TestEngine_Invalidate_ForcesRefresh(t *testing.T) {
	adapter := &fakeAdapter{}
	e := newTestEngine(t, adapter)
	ctx := context.Background()

	if _, err := e.Credential(ctx, "svc-d", "fake", validInput("aud:d")); err != nil {
		t.Fatalf("first Credential: %v", err)
	}
	if adapter.CallCount() != 1 {
		t.Fatalf("after first call: adapter calls = %d, want 1", adapter.CallCount())
	}

	e.Invalidate("svc-d")

	if _, err := e.Credential(ctx, "svc-d", "fake", validInput("aud:d")); err != nil {
		t.Fatalf("second Credential after Invalidate: %v", err)
	}
	if adapter.CallCount() != 2 {
		t.Errorf("after Invalidate+re-call: adapter calls = %d, want 2", adapter.CallCount())
	}
}

// ---------------------------------------------------------------------------
// TestEngine_Concurrent_SingleFlight — 20 concurrent calls → 1 adapter call.
// ---------------------------------------------------------------------------

func TestEngine_Concurrent_SingleFlight(t *testing.T) {
	adapter := &fakeAdapter{delay: 30 * time.Millisecond}
	e := newTestEngine(t, adapter)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = e.Credential(context.Background(), "svc-concurrent", "fake", validInput("aud:concurrent"))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
	if adapter.CallCount() != 1 {
		t.Errorf("adapter calls = %d, want 1 (single-flight)", adapter.CallCount())
	}
}

// ---------------------------------------------------------------------------
// TestEngine_ProactiveRefresh — entry within RefreshWindow triggers background
// refresh before TTL expires.
// ---------------------------------------------------------------------------

func TestEngine_ProactiveRefresh(t *testing.T) {
	// First credential expires very soon (100ms), well inside the 5s RefreshWindow.
	firstCred := &tokenexchange.ExchangedCredential{
		EnvVars:   map[string]string{"TOKEN": "first-token"},
		ExpiresAt: time.Now().Add(100 * time.Millisecond),
		Audience:  "aud:proactive",
		Scope:     "proactive",
	}
	adapter := &fakeAdapter{cred: firstCred}

	e := newTestEngine(t, adapter, func(cfg *tokenexchange.EngineConfig) {
		cfg.RefreshWindow = 5 * time.Second // larger than the TTL → near-expiry on first tick
		cfg.CheckInterval = 20 * time.Millisecond
	})
	ctx := context.Background()

	// Prime the cache.
	if _, err := e.Credential(ctx, "svc-proactive", "fake", validInput("aud:proactive")); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if adapter.CallCount() != 1 {
		t.Fatalf("expected 1 call after prime, got %d", adapter.CallCount())
	}

	// Update adapter to return a long-lived cred for the background refresh.
	longCred := &tokenexchange.ExchangedCredential{
		EnvVars:   map[string]string{"TOKEN": "refreshed-token"},
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Audience:  "aud:proactive",
		Scope:     "proactive",
	}
	adapter.setCred(longCred)

	// Wait for the background refresh loop to fire.
	time.Sleep(200 * time.Millisecond)

	if adapter.CallCount() < 2 {
		t.Errorf("adapter calls = %d after refresh window, want >= 2 (background refresh must have fired)", adapter.CallCount())
	}

	// The refreshed credential should now be in cache.
	cred, err := e.Credential(ctx, "svc-proactive", "fake", validInput("aud:proactive"))
	if err != nil {
		t.Fatalf("Credential after refresh: %v", err)
	}
	if cred.EnvVars["TOKEN"] != "refreshed-token" {
		t.Errorf("TOKEN = %q, want %q", cred.EnvVars["TOKEN"], "refreshed-token")
	}
}

// ---------------------------------------------------------------------------
// TestEngine_UnknownProvider_Errors — unregistered provider returns error.
// ---------------------------------------------------------------------------

func TestEngine_UnknownProvider_Errors(t *testing.T) {
	adapter := &fakeAdapter{}
	e := newTestEngine(t, adapter)

	_, err := e.Credential(context.Background(), "svc-e", "nonexistent", validInput("aud:e"))
	if err == nil {
		t.Fatal("expected error for unregistered provider, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestEngine_IdentitySourceError_Propagated — IdentitySource errors bubble up.
// ---------------------------------------------------------------------------

func TestEngine_IdentitySourceError_Propagated(t *testing.T) {
	srcErr := errors.New("openbao: identity token mint failed")
	adapter := &fakeAdapter{}
	cfg := tokenexchange.EngineConfig{
		Source:        &fakeIdentitySource{err: srcErr},
		Adapters:      map[string]tokenexchange.ExchangeAdapter{"fake": adapter},
		RefreshWindow: 5 * time.Minute,
		CheckInterval: 50 * time.Millisecond,
	}
	e := tokenexchange.NewEngine(cfg)
	t.Cleanup(e.Close)

	_, err := e.Credential(context.Background(), "svc-f", "fake", validInput("aud:f"))
	if err == nil {
		t.Fatal("expected error from identity source, got nil")
	}
	if !errors.Is(err, srcErr) {
		t.Errorf("error = %v, want to wrap %v", err, srcErr)
	}
}

// ---------------------------------------------------------------------------
// TestEngine_InlineTriggerBackgroundRefresh — a cache hit with remaining TTL
// inside the RefreshWindow fires triggerBackgroundRefresh inline (distinct from
// the ticker-driven path). Returns the cached cred immediately and refreshes
// in the background.
// ---------------------------------------------------------------------------

func TestEngine_InlineTriggerBackgroundRefresh(t *testing.T) {
	// Credential is already in its refresh window (2s TTL, 5s RefreshWindow).
	soonExpiry := time.Now().Add(2 * time.Second)
	firstCred := &tokenexchange.ExchangedCredential{
		EnvVars:   map[string]string{"TOKEN": "inline-first"},
		ExpiresAt: soonExpiry,
		Audience:  "aud:inline",
		Scope:     "inline",
	}
	adapter := &fakeAdapter{cred: firstCred}

	// Very long CheckInterval so ticker-loop doesn't trigger — only inline path.
	e := newTestEngine(t, adapter, func(cfg *tokenexchange.EngineConfig) {
		cfg.RefreshWindow = 5 * time.Second // > 2s TTL → within window immediately
		cfg.CheckInterval = 10 * time.Minute
	})
	ctx := context.Background()

	// Prime the cache.
	if _, err := e.Credential(ctx, "svc-inline", "fake", validInput("aud:inline")); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if adapter.CallCount() != 1 {
		t.Fatalf("expected 1 call after prime, got %d", adapter.CallCount())
	}

	// Set up a longer-lived cred for the background refresh.
	adapter.setCred(&tokenexchange.ExchangedCredential{
		EnvVars:   map[string]string{"TOKEN": "inline-refreshed"},
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Audience:  "aud:inline",
		Scope:     "inline",
	})

	// Second call — cache HIT within refresh window → triggerBackgroundRefresh
	// fires inline; returns stale cred immediately.
	cred, err := e.Credential(ctx, "svc-inline", "fake", validInput("aud:inline"))
	if err != nil {
		t.Fatalf("second Credential: %v", err)
	}
	if cred.EnvVars["TOKEN"] != "inline-first" {
		t.Errorf("TOKEN = %q, want %q (cached value returned immediately)", cred.EnvVars["TOKEN"], "inline-first")
	}

	// Wait for background refresh.
	time.Sleep(100 * time.Millisecond)

	if adapter.CallCount() < 2 {
		t.Errorf("adapter calls = %d, want >= 2 (inline background refresh must fire)", adapter.CallCount())
	}
}

// ---------------------------------------------------------------------------
// TestEngine_BackgroundRefresh_AdapterError_RemovesEntry — when background
// refresh fails, the cache entry is removed so the next synchronous call
// re-exchanges fresh.
// ---------------------------------------------------------------------------

func TestEngine_BackgroundRefresh_AdapterError_RemovesEntry(t *testing.T) {
	firstCred := &tokenexchange.ExchangedCredential{
		EnvVars:   map[string]string{"TOKEN": "bg-err-first"},
		ExpiresAt: time.Now().Add(100 * time.Millisecond),
		Audience:  "aud:bgerr",
		Scope:     "bgerr",
	}
	adapter := &fakeAdapter{cred: firstCred}

	e := newTestEngine(t, adapter, func(cfg *tokenexchange.EngineConfig) {
		cfg.RefreshWindow = 5 * time.Second
		cfg.CheckInterval = 20 * time.Millisecond
	})
	ctx := context.Background()

	// Prime the cache.
	if _, err := e.Credential(ctx, "svc-bgerr", "fake", validInput("aud:bgerr")); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Make adapter fail so background refresh removes the entry.
	adapter.mu.Lock()
	adapter.err = errors.New("adapter refresh failure")
	adapter.mu.Unlock()

	// Wait for background refresh to fire and fail.
	time.Sleep(200 * time.Millisecond)

	// Reset adapter to succeed on next call.
	adapter.mu.Lock()
	adapter.err = nil
	adapter.cred = &tokenexchange.ExchangedCredential{
		EnvVars:   map[string]string{"TOKEN": "bg-err-recovered"},
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Audience:  "aud:bgerr",
		Scope:     "bgerr",
	}
	adapter.mu.Unlock()

	// Next call should do a fresh synchronous exchange.
	cred, err := e.Credential(ctx, "svc-bgerr", "fake", validInput("aud:bgerr"))
	if err != nil {
		t.Fatalf("Credential after failed refresh: %v", err)
	}
	if cred.EnvVars["TOKEN"] != "bg-err-recovered" {
		t.Errorf("TOKEN = %q, want %q", cred.EnvVars["TOKEN"], "bg-err-recovered")
	}
}
