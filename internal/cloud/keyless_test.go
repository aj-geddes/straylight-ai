// Package cloud_test — wiring tests for BuildKeylessCloudManager (ADR-012 Phase 2).
//
// RED phase: these tests MUST FAIL until keyless.go is added.
package cloud_test

import (
	"context"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/cloud"
	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// ---------------------------------------------------------------------------
// Fakes — prefixed "Keyless" to avoid collisions with other test files.
// ---------------------------------------------------------------------------

// fakeKeylessTokenGenerator implements tokenexchange.TokenGenerator.
type fakeKeylessTokenGenerator struct{}

func (f *fakeKeylessTokenGenerator) GenerateIdentityToken(role, audience string) (string, time.Time, error) {
	return "fake-jwt", time.Now().Add(1 * time.Hour), nil
}

// fakeKeylessSTSWebIdentityClient implements tokenexchange.STSWebIdentityClient.
type fakeKeylessSTSWebIdentityClient struct {
	called bool
}

func (f *fakeKeylessSTSWebIdentityClient) AssumeRoleWithWebIdentity(
	_ context.Context,
	in tokenexchange.STSAssumeRoleWithWebIdentityInput,
) (*tokenexchange.STSWebIdentityCredentials, error) {
	f.called = true
	return &tokenexchange.STSWebIdentityCredentials{
		AccessKeyID:     "ASIAKEYLESS",
		SecretAccessKey: "keylessSecret",
		SessionToken:    "keylessToken",
		Expiration:      time.Now().Add(15 * time.Minute),
	}, nil
}

// fakeKeylessGCPSTSClient implements tokenexchange.GCPSTSClient.
type fakeKeylessGCPSTSClient struct{}

func (f *fakeKeylessGCPSTSClient) ExchangeToken(
	_ context.Context,
	in tokenexchange.GCPTokenExchangeInput,
) (*tokenexchange.GCPFederatedToken, error) {
	return &tokenexchange.GCPFederatedToken{
		AccessToken: "ya29.keyless",
		ExpiresIn:   3600,
	}, nil
}

// fakeKeylessAzureTokenClient implements tokenexchange.AzureTokenClient.
type fakeKeylessAzureTokenClient struct{}

func (f *fakeKeylessAzureTokenClient) ExchangeToken(
	_ context.Context,
	in tokenexchange.AzureTokenExchangeInput,
) (*tokenexchange.AzureFederatedToken, error) {
	return &tokenexchange.AzureFederatedToken{
		AccessToken: "keyless-azure-tok",
		ExpiresIn:   3600,
	}, nil
}

// mockKeylessStaticSTSClient implements cloud.STSClient (static AssumeRole path).
type mockKeylessStaticSTSClient struct {
	called bool
}

func (m *mockKeylessStaticSTSClient) AssumeRole(
	_ context.Context,
	input cloud.STSAssumeRoleInput,
) (*cloud.STSCredentials, error) {
	m.called = true
	return &cloud.STSCredentials{
		AccessKeyID:     "AKIASTATIC",
		SecretAccessKey: "staticSecret",
		SessionToken:    "staticToken",
		Expiration:      time.Now().Add(15 * time.Minute),
	}, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestBuildKeylessCloudManager_ReturnsNonNilManager verifies that
// BuildKeylessCloudManager returns a non-nil *Manager and does not panic.
func TestBuildKeylessCloudManager_ReturnsNonNilManager(t *testing.T) {
	gen := &fakeKeylessTokenGenerator{}
	awsClient := &fakeKeylessSTSWebIdentityClient{}
	gcpClient := &fakeKeylessGCPSTSClient{}
	azureClient := &fakeKeylessAzureTokenClient{}
	staticClient := &mockKeylessStaticSTSClient{}

	mgr := cloud.BuildKeylessCloudManager(gen, "straylight", awsClient, gcpClient, azureClient, staticClient)

	if mgr == nil {
		t.Fatal("BuildKeylessCloudManager returned nil Manager")
	}
}

// TestBuildKeylessCloudManager_KeylessAWSRoutesThroughEngine verifies that a
// service config with a non-nil WebIdentity block routes through the
// token-exchange Engine (keyless path) and returns credentials without error.
func TestBuildKeylessCloudManager_KeylessAWSRoutesThroughEngine(t *testing.T) {
	gen := &fakeKeylessTokenGenerator{}
	awsClient := &fakeKeylessSTSWebIdentityClient{}
	gcpClient := &fakeKeylessGCPSTSClient{}
	azureClient := &fakeKeylessAzureTokenClient{}
	staticClient := &mockKeylessStaticSTSClient{}

	mgr := cloud.BuildKeylessCloudManager(gen, "straylight", awsClient, gcpClient, azureClient, staticClient)

	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN: "arn:aws:iam::123456789012:role/KeylessRole",
			Region:  "us-east-1",
			WebIdentity: &cloud.AWSWebIdentityConfig{
				Audience: "sts.amazonaws.com",
			},
		},
	}

	creds, err := mgr.GetCredentials(context.Background(), "keyless-aws-svc", cfg)
	if err != nil {
		t.Fatalf("GetCredentials keyless AWS error = %v", err)
	}
	if creds.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", creds.Provider, "aws")
	}
	got, ok := creds.EnvVars["AWS_ACCESS_KEY_ID"]
	if !ok {
		t.Fatal("AWS_ACCESS_KEY_ID not in EnvVars")
	}
	if got != "ASIAKEYLESS" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want %q", got, "ASIAKEYLESS")
	}
	// The static AssumeRole client must NOT have been called.
	if staticClient.called {
		t.Error("static AssumeRole was called on the keyless path — backward-compat violation")
	}
}

// TestBuildKeylessCloudManager_StaticServiceUnaffected verifies that a service
// with no WebIdentity config uses the static path and that the keyless engine
// is NOT invoked. This is the critical backward-compatibility guarantee.
func TestBuildKeylessCloudManager_StaticServiceUnaffected(t *testing.T) {
	gen := &fakeKeylessTokenGenerator{}
	awsClient := &fakeKeylessSTSWebIdentityClient{}
	gcpClient := &fakeKeylessGCPSTSClient{}
	azureClient := &fakeKeylessAzureTokenClient{}
	staticClient := &mockKeylessStaticSTSClient{}

	mgr := cloud.BuildKeylessCloudManager(gen, "straylight", awsClient, gcpClient, azureClient, staticClient)

	// No WebIdentity block — static path.
	cfg := cloud.ServiceConfig{
		Engine: "aws",
		AWS: &cloud.AWSConfig{
			RoleARN: "arn:aws:iam::111111111111:role/StaticRole",
			Region:  "eu-west-1",
		},
	}

	creds, err := mgr.GetCredentials(context.Background(), "static-aws-svc", cfg)
	if err != nil {
		t.Fatalf("GetCredentials static AWS error = %v", err)
	}
	if creds.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", creds.Provider, "aws")
	}
	got, ok := creds.EnvVars["AWS_ACCESS_KEY_ID"]
	if !ok {
		t.Fatal("AWS_ACCESS_KEY_ID not in EnvVars")
	}
	if got != "AKIASTATIC" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want %q (static path expected)", got, "AKIASTATIC")
	}
	// The keyless STS client must NOT have been called.
	if awsClient.called {
		t.Error("keyless AssumeRoleWithWebIdentity was called on the static path — backward-compat violation")
	}
}

// TestBuildKeylessCloudManager_AllProvidersRegistered verifies that GCP and
// Azure providers are also registered in the manager. We invoke each with a
// keyless-configured service to confirm the engine routes correctly.
func TestBuildKeylessCloudManager_AllProvidersRegistered(t *testing.T) {
	gen := &fakeKeylessTokenGenerator{}
	mgr := cloud.BuildKeylessCloudManager(
		gen, "straylight",
		&fakeKeylessSTSWebIdentityClient{},
		&fakeKeylessGCPSTSClient{},
		&fakeKeylessAzureTokenClient{},
		&mockKeylessStaticSTSClient{},
	)

	t.Run("gcp keyless", func(t *testing.T) {
		cfg := cloud.ServiceConfig{
			Engine: "gcp",
			GCP: &cloud.GCPConfig{
				ProjectID: "my-project",
				WebIdentity: &cloud.GCPWebIdentityConfig{
					Audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/pr",
				},
			},
		}
		creds, err := mgr.GetCredentials(context.Background(), "keyless-gcp-svc", cfg)
		if err != nil {
			t.Fatalf("GCP keyless GetCredentials error = %v", err)
		}
		if creds.Provider != "gcp" {
			t.Errorf("Provider = %q, want %q", creds.Provider, "gcp")
		}
		if _, ok := creds.EnvVars["CLOUDSDK_AUTH_ACCESS_TOKEN"]; !ok {
			t.Error("CLOUDSDK_AUTH_ACCESS_TOKEN not set")
		}
	})

	t.Run("azure keyless", func(t *testing.T) {
		cfg := cloud.ServiceConfig{
			Engine: "azure",
			Azure: &cloud.AzureConfig{
				TenantID: "my-tenant",
				ClientID: "my-client",
				WebIdentity: &cloud.AzureWebIdentityConfig{
					TenantID: "my-tenant",
					ClientID: "my-client",
					Audience: "api://AzureADTokenExchange",
				},
			},
		}
		creds, err := mgr.GetCredentials(context.Background(), "keyless-azure-svc", cfg)
		if err != nil {
			t.Fatalf("Azure keyless GetCredentials error = %v", err)
		}
		if creds.Provider != "azure" {
			t.Errorf("Provider = %q, want %q", creds.Provider, "azure")
		}
		if _, ok := creds.EnvVars["AZURE_ACCESS_TOKEN"]; !ok {
			t.Error("AZURE_ACCESS_TOKEN not set")
		}
	})
}
