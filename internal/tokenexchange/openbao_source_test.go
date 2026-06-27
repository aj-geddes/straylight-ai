// Package tokenexchange_test tests the OpenBaoIdentitySource implementation.
package tokenexchange_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// fakeTokenGenerator implements tokenexchange.TokenGenerator for testing.
type fakeTokenGenerator struct {
	lastRole     string
	lastAudience string
	token        string
	expiry       time.Time
	err          error
}

func (f *fakeTokenGenerator) GenerateIdentityToken(role, audience string) (string, time.Time, error) {
	f.lastRole = role
	f.lastAudience = audience
	if f.err != nil {
		return "", time.Time{}, f.err
	}
	return f.token, f.expiry, nil
}

// ---------------------------------------------------------------------------
// TestOpenBaoIdentitySource_Success — happy path: proof fields are populated.
// ---------------------------------------------------------------------------

func TestOpenBaoIdentitySource_Success(t *testing.T) {
	expiry := time.Now().Add(10 * time.Minute)
	gen := &fakeTokenGenerator{
		token:  "tok1",
		expiry: expiry,
	}

	src := tokenexchange.NewOpenBaoIdentitySource("straylight", gen)

	proof, err := src.Identity(context.Background(), tokenexchange.IdentityRequest{
		Audience: "sts.amazonaws.com",
	})
	if err != nil {
		t.Fatalf("Identity() unexpected error: %v", err)
	}

	if proof.Token != "tok1" {
		t.Errorf("proof.Token = %q, want %q", proof.Token, "tok1")
	}
	if proof.TokenType != "urn:ietf:params:oauth:token-type:jwt" {
		t.Errorf("proof.TokenType = %q, want %q", proof.TokenType, "urn:ietf:params:oauth:token-type:jwt")
	}
	if proof.ExpiresAt.IsZero() {
		t.Error("proof.ExpiresAt must not be zero")
	}
	if proof.ExpiresAt.Unix() != expiry.Unix() {
		t.Errorf("proof.ExpiresAt = %v, want %v", proof.ExpiresAt, expiry)
	}
}

// ---------------------------------------------------------------------------
// TestOpenBaoIdentitySource_SourceType — SourceType returns "openbao".
// ---------------------------------------------------------------------------

func TestOpenBaoIdentitySource_SourceType(t *testing.T) {
	src := tokenexchange.NewOpenBaoIdentitySource("straylight", &fakeTokenGenerator{})
	if got := src.SourceType(); got != "openbao" {
		t.Errorf("SourceType() = %q, want %q", got, "openbao")
	}
}

// ---------------------------------------------------------------------------
// TestOpenBaoIdentitySource_GeneratorError — generator error propagates.
// ---------------------------------------------------------------------------

func TestOpenBaoIdentitySource_GeneratorError(t *testing.T) {
	genErr := errors.New("vault: token mint failed")
	gen := &fakeTokenGenerator{err: genErr}

	src := tokenexchange.NewOpenBaoIdentitySource("straylight", gen)

	_, err := src.Identity(context.Background(), tokenexchange.IdentityRequest{
		Audience: "sts.amazonaws.com",
	})
	if err == nil {
		t.Fatal("Identity() expected error, got nil")
	}
	if !errors.Is(err, genErr) {
		t.Errorf("error %v does not wrap %v", err, genErr)
	}
}

// ---------------------------------------------------------------------------
// TestOpenBaoIdentitySource_AudienceAndRolePassed — correct role and audience
// are forwarded to the generator.
// ---------------------------------------------------------------------------

func TestOpenBaoIdentitySource_AudienceAndRolePassed(t *testing.T) {
	gen := &fakeTokenGenerator{
		token:  "tok2",
		expiry: time.Now().Add(10 * time.Minute),
	}

	src := tokenexchange.NewOpenBaoIdentitySource("my-role", gen)

	_, err := src.Identity(context.Background(), tokenexchange.IdentityRequest{
		Audience: "sts.amazonaws.com",
	})
	if err != nil {
		t.Fatalf("Identity() unexpected error: %v", err)
	}

	if gen.lastRole != "my-role" {
		t.Errorf("generator called with role = %q, want %q", gen.lastRole, "my-role")
	}
	if gen.lastAudience != "sts.amazonaws.com" {
		t.Errorf("generator called with audience = %q, want %q", gen.lastAudience, "sts.amazonaws.com")
	}
}
