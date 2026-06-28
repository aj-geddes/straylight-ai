package tokenexchange

import (
	"context"
	"fmt"
	"time"
)

// gcpDefaultTokenLifetimeSecs is the fallback TTL for GCP federated tokens when
// the STS response does not include expires_in.
const gcpDefaultTokenLifetimeSecs = 3600

// GCPTokenExchangeInput holds the parameters for a GCP STS token exchange call,
// keeping the HTTP exchange behind the GCPSTSClient interface for testability.
type GCPTokenExchangeInput struct {
	// Audience is the workload identity pool provider resource name, used as the
	// "audience" field in the RFC 8693 exchange request.
	Audience string
	// SubjectToken is the signed OIDC JWT (the OpenBao identity proof).
	// It is presented as the subject_token in the RFC 8693 request and is never
	// echoed in the returned credential (MCP no-passthrough).
	SubjectToken string
}

// GCPFederatedToken holds the short-lived federated access token returned by
// GCP STS (POST https://sts.googleapis.com/v1/token).
type GCPFederatedToken struct {
	// AccessToken is the bearer token to inject as CLOUDSDK_AUTH_ACCESS_TOKEN.
	AccessToken string
	// ExpiresIn is the token lifetime in seconds as reported by GCP STS.
	ExpiresIn int
}

// GCPSTSClient is the narrow GCP STS interface for the keyless WIF path.
// The real HTTP implementation and test mocks both satisfy this interface.
// It is intentionally separate from the cloud package so that the tokenexchange
// package has no import dependency on internal/cloud.
type GCPSTSClient interface {
	// ExchangeToken exchanges an OIDC identity token for a short-lived GCP
	// federated access token without requiring static service account keys.
	ExchangeToken(ctx context.Context, in GCPTokenExchangeInput) (*GCPFederatedToken, error)
}

// GCPWIFAdapter implements ExchangeAdapter for GCP Workload Identity Federation.
// It is the keyless GCP exchange: an OpenBao OIDC identity token is presented
// to GCP STS; no static service account JSON keys are required.
//
// ExchangeInput.Params keys:
//   - "audience" (required) — workload identity pool provider resource name,
//     e.g. "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider".
//   - "project"  (optional) — GCP project ID for CLOUDSDK_CORE_PROJECT.
//
// SA impersonation is deferred to a follow-up (ADR-012 Phase 3): the federated
// token is sufficient for services that accept direct WIF authentication. To
// impersonate a service account, the caller should use the federated token with
// the IAM credentials API generateAccessToken endpoint separately.
type GCPWIFAdapter struct {
	sts GCPSTSClient
}

// NewGCPWIFAdapter creates a GCPWIFAdapter backed by the given GCPSTSClient.
func NewGCPWIFAdapter(sts GCPSTSClient) *GCPWIFAdapter {
	return &GCPWIFAdapter{sts: sts}
}

// ProviderType implements ExchangeAdapter.
func (a *GCPWIFAdapter) ProviderType() string { return "gcp" }

// Exchange implements ExchangeAdapter. It calls GCP STS with the identity proof
// token (RFC 8693 token exchange) and returns a short-lived federated access
// token as a CLOUDSDK_* environment variable.
//
// The identity proof token is forwarded to GCP STS as the subject_token; it is
// never included in the returned EnvVars (MCP no-passthrough).
func (a *GCPWIFAdapter) Exchange(ctx context.Context, in ExchangeInput) (*ExchangedCredential, error) {
	audience := in.Params["audience"]
	if audience == "" {
		return nil, fmt.Errorf("tokenexchange: gcp wif adapter: audience is required in Params")
	}

	stsIn := GCPTokenExchangeInput{
		Audience:     audience,
		SubjectToken: in.Proof.Token, // never echoed in output
	}

	result, err := a.sts.ExchangeToken(ctx, stsIn)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: gcp wif sts: %w", err)
	}

	expiresIn := result.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = gcpDefaultTokenLifetimeSecs
	}
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	envVars := map[string]string{
		"CLOUDSDK_AUTH_ACCESS_TOKEN": result.AccessToken,
	}
	project := in.Params["project"]
	if project != "" {
		envVars["CLOUDSDK_CORE_PROJECT"] = project
	}

	scope := fmt.Sprintf("gcp wif audience=%s project=%s", audience, project)

	return &ExchangedCredential{
		EnvVars:   envVars,
		ExpiresAt: expiresAt,
		Audience:  in.Audience,
		Scope:     scope,
	}, nil
}
