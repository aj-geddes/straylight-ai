// Package cloud — real cloud API client implementations (ADR-012 issue #10).
//
// This file provides the four real client implementations that replace the noop
// stubs in cmd/straylight/main.go:
//
//  1. GCPSTSClient — HTTP POST to GCP STS (https://sts.googleapis.com/v1/token)
//     using RFC 8693 token-exchange (no service-account keys required).
//  2. AzureHTTPTokenClient — HTTP POST to Azure AD token endpoint using the
//     jwt-bearer client assertion flow (no client_secret required).
//  3. AWSWebIdentitySTSClient — AWS STS AssumeRoleWithWebIdentity using the
//     aws-sdk-go-v2 STS client (no static admin keys required).
//  4. AWSStaticSTSClient — AWS STS AssumeRole using the aws-sdk-go-v2 STS
//     client (uses vault-stored admin keys; static backward-compat path).
//
// The AWS clients share an AWSSTSCaller seam that is injectable for unit tests
// so that no real AWS calls are made in the test suite.
package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// ---------------------------------------------------------------------------
// Shared AWS types
// ---------------------------------------------------------------------------

// RawAWSCredentials holds the raw STS credential fields before mapping to the
// tokenexchange or cloud interface types. It is the shared intermediate type
// between the AWSSTSCaller seam and both AWS client wrappers.
type RawAWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	ExpiresAt       time.Time
}

// AWSSTSCaller is the narrow seam between the two AWS client wrappers and the
// underlying AWS SDK. Replacing this interface with a mock in tests keeps the
// unit tests free of real network calls.
type AWSSTSCaller interface {
	// AssumeRoleWithWebIdentityRaw exchanges a web-identity token for short-lived
	// AWS credentials via STS AssumeRoleWithWebIdentity.
	AssumeRoleWithWebIdentityRaw(
		ctx context.Context,
		roleARN, sessionName, webIdentityToken string,
		durationSecs int32,
		policy *string,
	) (*RawAWSCredentials, error)

	// AssumeRoleRaw assumes the named role via STS AssumeRole.
	AssumeRoleRaw(
		ctx context.Context,
		roleARN, sessionName string,
		durationSecs int32,
		policy *string,
	) (*RawAWSCredentials, error)
}

// ---------------------------------------------------------------------------
// GCP STS client
// ---------------------------------------------------------------------------

const gcpSTSDefaultEndpoint = "https://sts.googleapis.com/v1/token"

// GCPSTSClient implements tokenexchange.GCPSTSClient by posting to the GCP
// Secure Token Service using the RFC 8693 token-exchange grant type. No static
// service-account keys are required; the OIDC identity proof is the credential.
type GCPSTSClient struct {
	httpClient *http.Client
	endpoint   string
}

// NewGCPSTSClient creates a GCPSTSClient.
// When httpClient is nil, a client with a 10-second timeout is used.
// When endpointOverride is empty, the real GCP STS endpoint is used.
func NewGCPSTSClient(httpClient *http.Client, endpointOverride string) *GCPSTSClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	endpoint := endpointOverride
	if endpoint == "" {
		endpoint = gcpSTSDefaultEndpoint
	}
	return &GCPSTSClient{
		httpClient: httpClient,
		endpoint:   endpoint,
	}
}

// ExchangeToken implements tokenexchange.GCPSTSClient. It posts an RFC 8693
// token-exchange request (subject_token = OIDC identity proof) to GCP STS and
// returns the resulting federated access token.
//
// The subject_token is never echoed in the returned GCPFederatedToken.
func (c *GCPSTSClient) ExchangeToken(ctx context.Context, in tokenexchange.GCPTokenExchangeInput) (*tokenexchange.GCPFederatedToken, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", in.SubjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	form.Set("audience", in.Audience)
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("cloud: gcp sts: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloud: gcp sts: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cloud: gcp sts: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloud: gcp sts: HTTP %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("cloud: gcp sts: decode response: %w", err)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("cloud: gcp sts: empty access_token in response")
	}

	return &tokenexchange.GCPFederatedToken{
		AccessToken: result.AccessToken,
		ExpiresIn:   result.ExpiresIn,
	}, nil
}

// ---------------------------------------------------------------------------
// Azure HTTP token client
// ---------------------------------------------------------------------------

const azureDefaultBaseURL = "https://login.microsoftonline.com"

// AzureHTTPTokenClient implements tokenexchange.AzureTokenClient using the
// Azure AD jwt-bearer client assertion flow. No static client_secret is
// required; the OIDC identity proof is presented as the client_assertion.
type AzureHTTPTokenClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewAzureHTTPTokenClient creates an AzureHTTPTokenClient.
// When httpClient is nil, a client with a 10-second timeout is used.
// When baseURLOverride is empty, the real Azure AD login endpoint is used.
// The client appends /{tenantID}/oauth2/v2.0/token to the base URL.
func NewAzureHTTPTokenClient(httpClient *http.Client, baseURLOverride string) *AzureHTTPTokenClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	baseURL := baseURLOverride
	if baseURL == "" {
		baseURL = azureDefaultBaseURL
	}
	return &AzureHTTPTokenClient{
		httpClient: httpClient,
		baseURL:    baseURL,
	}
}

// ExchangeToken implements tokenexchange.AzureTokenClient. It posts the
// jwt-bearer client assertion to the Azure AD token endpoint and returns the
// resulting access token. No client_secret is sent on this path.
//
// The client_assertion (identity proof) is never echoed in the returned
// AzureFederatedToken.
func (c *AzureHTTPTokenClient) ExchangeToken(ctx context.Context, in tokenexchange.AzureTokenExchangeInput) (*tokenexchange.AzureFederatedToken, error) {
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.baseURL, url.PathEscape(in.TenantID))

	form := url.Values{}
	form.Set("grant_type", "client_credentials") // Azure AD requires client_credentials for RFC 7523 client-assertion (FIC/keyless) flow
	form.Set("client_id", in.ClientID)
	form.Set("scope", in.Scope)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", in.ClientAssertion)
	// Intentionally no client_secret — this is the keyless FIC path.

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("cloud: azure fic: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloud: azure fic: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cloud: azure fic: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloud: azure fic: HTTP %d: %s", resp.StatusCode, body)
	}

	// Azure returns expires_in as either a JSON number or a JSON string.
	var rawResp map[string]interface{}
	if err := json.Unmarshal(body, &rawResp); err != nil {
		return nil, fmt.Errorf("cloud: azure fic: decode response: %w", err)
	}

	accessToken, _ := rawResp["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("cloud: azure fic: empty access_token in response")
	}

	var expiresIn int
	switch v := rawResp["expires_in"].(type) {
	case float64:
		expiresIn = int(v)
	case string:
		_, _ = fmt.Sscanf(v, "%d", &expiresIn)
	}
	if expiresIn <= 0 {
		expiresIn = 3600 // Azure default
	}

	return &tokenexchange.AzureFederatedToken{
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
	}, nil
}

// ---------------------------------------------------------------------------
// AWS web-identity STS client
// ---------------------------------------------------------------------------

// AWSWebIdentitySTSClient implements tokenexchange.STSWebIdentityClient. It
// delegates to an AWSSTSCaller (real SDK in production, mock in tests) so that
// no real AWS network calls are made in unit tests.
type AWSWebIdentitySTSClient struct {
	caller AWSSTSCaller
}

// NewAWSWebIdentitySTSClientWithCaller creates an AWSWebIdentitySTSClient
// backed by the given AWSSTSCaller. Use NewAWSSTSCallerFromStaticCredentials
// or NewAWSSTSCallerDefault to obtain a production caller.
func NewAWSWebIdentitySTSClientWithCaller(caller AWSSTSCaller) *AWSWebIdentitySTSClient {
	return &AWSWebIdentitySTSClient{caller: caller}
}

// AssumeRoleWithWebIdentity implements tokenexchange.STSWebIdentityClient. It
// delegates to the underlying AWSSTSCaller and maps the raw credentials to the
// expected interface type. The web-identity token is never echoed in output.
func (c *AWSWebIdentitySTSClient) AssumeRoleWithWebIdentity(ctx context.Context, in tokenexchange.STSAssumeRoleWithWebIdentityInput) (*tokenexchange.STSWebIdentityCredentials, error) {
	raw, err := c.caller.AssumeRoleWithWebIdentityRaw(ctx, in.RoleARN, in.SessionName, in.WebIdentityToken, in.DurationSeconds, in.Policy)
	if err != nil {
		return nil, fmt.Errorf("cloud: aws web-identity sts: %w", err)
	}
	return &tokenexchange.STSWebIdentityCredentials{
		AccessKeyID:     raw.AccessKeyID,
		SecretAccessKey: raw.SecretAccessKey,
		SessionToken:    raw.SessionToken,
		Expiration:      raw.ExpiresAt,
	}, nil
}

// ---------------------------------------------------------------------------
// AWS static STS client
// ---------------------------------------------------------------------------

// AWSStaticSTSClient implements cloud.STSClient for the static AssumeRole path.
// It delegates to an AWSSTSCaller (real SDK in production, mock in tests).
type AWSStaticSTSClient struct {
	caller AWSSTSCaller
}

// NewAWSStaticSTSClientWithCaller creates an AWSStaticSTSClient backed by the
// given AWSSTSCaller.
func NewAWSStaticSTSClientWithCaller(caller AWSSTSCaller) *AWSStaticSTSClient {
	return &AWSStaticSTSClient{caller: caller}
}

// AssumeRole implements cloud.STSClient. It delegates to the underlying
// AWSSTSCaller and maps the raw credentials to STSCredentials.
func (c *AWSStaticSTSClient) AssumeRole(ctx context.Context, in STSAssumeRoleInput) (*STSCredentials, error) {
	raw, err := c.caller.AssumeRoleRaw(ctx, in.RoleARN, in.SessionName, in.DurationSeconds, in.Policy)
	if err != nil {
		return nil, fmt.Errorf("cloud: static aws sts: %w", err)
	}
	return &STSCredentials{
		AccessKeyID:     raw.AccessKeyID,
		SecretAccessKey: raw.SecretAccessKey,
		SessionToken:    raw.SessionToken,
		Expiration:      raw.ExpiresAt,
	}, nil
}

// ---------------------------------------------------------------------------
// Real SDK-backed AWSSTSCaller
// ---------------------------------------------------------------------------

// sdkSTSCaller is the production AWSSTSCaller backed by the aws-sdk-go-v2 STS
// client. It is unexported; callers obtain one via the constructors below.
type sdkSTSCaller struct {
	stsClient *sts.Client
}

// NewAWSSTSCallerFromStaticCredentials creates a production AWSSTSCaller using
// explicit AWS static credentials. This is the path for the static AssumeRole
// caller when vault-stored admin keys are provided.
//
// region defaults to "us-east-1" when empty.
func NewAWSSTSCallerFromStaticCredentials(region, accessKeyID, secretAccessKey string) (AWSSTSCaller, error) {
	if region == "" {
		region = "us-east-1"
	}
	credProvider := credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")
	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.NewCredentialsCache(credProvider)),
	)
	if err != nil {
		return nil, fmt.Errorf("cloud: aws sts caller: load config: %w", err)
	}
	return &sdkSTSCaller{stsClient: sts.NewFromConfig(cfg)}, nil
}

// NewAWSSTSCallerDefault creates a production AWSSTSCaller using the default
// AWS credential chain (env vars, ~/.aws/credentials, IMDS, etc.). Suitable for
// the keyless web-identity path where no static keys are needed.
//
// region defaults to "us-east-1" when empty.
func NewAWSSTSCallerDefault(ctx context.Context, region string) (AWSSTSCaller, error) {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("cloud: aws sts caller: load default config: %w", err)
	}
	return &sdkSTSCaller{stsClient: sts.NewFromConfig(cfg)}, nil
}

// AssumeRoleWithWebIdentityRaw implements AWSSTSCaller.
func (c *sdkSTSCaller) AssumeRoleWithWebIdentityRaw(
	ctx context.Context,
	roleARN, sessionName, webIdentityToken string,
	durationSecs int32,
	policy *string,
) (*RawAWSCredentials, error) {
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &roleARN,
		RoleSessionName:  &sessionName,
		WebIdentityToken: &webIdentityToken,
		DurationSeconds:  &durationSecs,
	}
	if policy != nil {
		input.Policy = policy
	}

	resp, err := c.stsClient.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("sts AssumeRoleWithWebIdentity: %w", err)
	}
	creds := resp.Credentials
	if creds == nil {
		return nil, fmt.Errorf("sts AssumeRoleWithWebIdentity: nil credentials in response")
	}

	return &RawAWSCredentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		ExpiresAt:       aws.ToTime(creds.Expiration),
	}, nil
}

// AssumeRoleRaw implements AWSSTSCaller.
func (c *sdkSTSCaller) AssumeRoleRaw(
	ctx context.Context,
	roleARN, sessionName string,
	durationSecs int32,
	policy *string,
) (*RawAWSCredentials, error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         &roleARN,
		RoleSessionName: &sessionName,
		DurationSeconds: &durationSecs,
	}
	if policy != nil {
		input.Policy = policy
	}

	resp, err := c.stsClient.AssumeRole(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("sts AssumeRole: %w", err)
	}
	creds := resp.Credentials
	if creds == nil {
		return nil, fmt.Errorf("sts AssumeRole: nil credentials in response")
	}

	return &RawAWSCredentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		ExpiresAt:       aws.ToTime(creds.Expiration),
	}, nil
}
