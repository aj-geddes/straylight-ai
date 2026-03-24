package oauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const (
	// stateTokenBytes is the number of random bytes used for state token generation.
	// 16 bytes → 32 hex chars, providing 128 bits of entropy.
	stateTokenBytes = 16

	// stateTokenTTL is how long a state token remains valid before expiry.
	stateTokenTTL = 10 * time.Minute
)

// stateEntry holds the metadata associated with a pending OAuth state token.
type stateEntry struct {
	provider    string
	serviceName string
	expiresAt   time.Time
}

// StateManager generates and validates CSRF state tokens for the OAuth flow.
// Each token is one-time use and expires after stateTokenTTL.
type StateManager struct {
	mu     sync.Mutex
	states map[string]stateEntry
}

// NewStateManager constructs a StateManager with an empty token store.
func NewStateManager() *StateManager {
	return &StateManager{
		states: make(map[string]stateEntry),
	}
}

// Generate creates a cryptographically random state token, stores it alongside
// the given provider and serviceName, and returns the token string.
// State tokens expire after stateTokenTTL (10 minutes).
func (sm *StateManager) Generate(provider string, serviceName string) string {
	buf := make([]byte, stateTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read fails only under extraordinary OS-level conditions.
		// Panic here so the failure is loud rather than silently producing weak tokens.
		panic("oauth: state token generation failed: " + err.Error())
	}
	token := hex.EncodeToString(buf)

	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.states[token] = stateEntry{
		provider:    provider,
		serviceName: serviceName,
		expiresAt:   time.Now().Add(stateTokenTTL),
	}
	return token
}

// Validate checks the given state token, consuming it (one-time use).
// Returns the associated provider and serviceName, or an error if the token is
// unknown, expired, or has already been consumed.
func (sm *StateManager) Validate(state string) (provider string, serviceName string, err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	entry, ok := sm.states[state]
	if !ok {
		return "", "", fmt.Errorf("oauth: invalid or already consumed state token")
	}

	// Consume the token regardless of expiry to prevent timing attacks.
	delete(sm.states, state)

	if time.Now().After(entry.expiresAt) {
		return "", "", fmt.Errorf("oauth: state token has expired")
	}

	return entry.provider, entry.serviceName, nil
}
