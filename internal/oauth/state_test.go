package oauth

import (
	"testing"
	"time"
)

func TestStateManager_Generate_ReturnsNonEmptyToken(t *testing.T) {
	sm := NewStateManager()
	token := sm.Generate("github", "my-service")
	if token == "" {
		t.Fatal("expected non-empty state token")
	}
}

func TestStateManager_Generate_ReturnsDifferentTokensEachCall(t *testing.T) {
	sm := NewStateManager()
	t1 := sm.Generate("github", "svc1")
	t2 := sm.Generate("github", "svc2")
	if t1 == t2 {
		t.Fatal("expected distinct state tokens")
	}
}

func TestStateManager_Validate_ValidToken(t *testing.T) {
	sm := NewStateManager()
	token := sm.Generate("github", "my-service")

	provider, serviceName, err := sm.Validate(token)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if provider != "github" {
		t.Errorf("expected provider %q, got %q", "github", provider)
	}
	if serviceName != "my-service" {
		t.Errorf("expected serviceName %q, got %q", "my-service", serviceName)
	}
}

func TestStateManager_Validate_OneTimeUse(t *testing.T) {
	sm := NewStateManager()
	token := sm.Generate("github", "my-service")

	_, _, err := sm.Validate(token)
	if err != nil {
		t.Fatalf("first validation failed unexpectedly: %v", err)
	}

	_, _, err = sm.Validate(token)
	if err == nil {
		t.Fatal("expected error on second validation (token is one-time use), got nil")
	}
}

func TestStateManager_Validate_InvalidToken(t *testing.T) {
	sm := NewStateManager()
	_, _, err := sm.Validate("not-a-real-token")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

func TestStateManager_Validate_ExpiredToken(t *testing.T) {
	sm := NewStateManager()
	token := sm.Generate("github", "my-service")

	// Manually expire the token by back-dating it.
	sm.mu.Lock()
	entry := sm.states[token]
	entry.expiresAt = time.Now().Add(-1 * time.Second)
	sm.states[token] = entry
	sm.mu.Unlock()

	_, _, err := sm.Validate(token)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestStateManager_Generate_TokenHasMinimumLength(t *testing.T) {
	sm := NewStateManager()
	token := sm.Generate("github", "svc")
	// 16 bytes hex-encoded = 32 chars minimum
	if len(token) < 32 {
		t.Errorf("state token too short: got len %d, want >= 32", len(token))
	}
}
