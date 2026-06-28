package tokenexchange

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// awsDefaultSessionName is the RoleSessionName used when not specified in Params.
const awsDefaultSessionName = "straylight-exec"

// awsDefaultRegion is the region injected into AWS_DEFAULT_REGION when not
// specified in ExchangeInput.Params["region"].
const awsDefaultRegion = "us-east-1"

// awsDefaultDurationSecs is the STS session duration used when not specified.
const awsDefaultDurationSecs int32 = 900

// awsMaxDurationSecs is the maximum STS session duration (12 hours). Values
// above this are clamped to 43200 so misconfigurations fail clearly at the
// adapter layer rather than returning an opaque STS ValidationError.
const awsMaxDurationSecs int32 = 43200

// STSAssumeRoleWithWebIdentityInput holds the parameters for an STS
// AssumeRoleWithWebIdentity call, keeping the AWS SDK behind this interface.
type STSAssumeRoleWithWebIdentityInput struct {
	// RoleARN is the IAM role to assume.
	RoleARN string
	// SessionName is the RoleSessionName passed to STS (CloudTrail identifier).
	SessionName string
	// WebIdentityToken is the signed OIDC JWT (the OpenBao identity proof).
	WebIdentityToken string
	// DurationSeconds is the requested session TTL (900-43200).
	DurationSeconds int32
	// Policy is an optional inline session policy JSON.
	Policy *string
}

// STSWebIdentityCredentials holds the temporary credentials returned by STS
// AssumeRoleWithWebIdentity.
type STSWebIdentityCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// STSWebIdentityClient is the narrow STS interface for the keyless path.
// The real AWS SDK implementation and test mocks satisfy this interface.
// It is intentionally separate from the cloud.STSClient interface so that
// the tokenexchange package has no import dependency on internal/cloud.
type STSWebIdentityClient interface {
	// AssumeRoleWithWebIdentity exchanges a web identity token for short-lived
	// AWS credentials without requiring static admin keys.
	AssumeRoleWithWebIdentity(ctx context.Context, in STSAssumeRoleWithWebIdentityInput) (*STSWebIdentityCredentials, error)
}

// AWSWebIdentityAdapter implements ExchangeAdapter for AWS STS
// AssumeRoleWithWebIdentity. It is the keyless AWS exchange: an OpenBao OIDC
// identity token is presented to STS; no static admin AWS keys are needed.
//
// ExchangeInput.Params keys:
//   - "role_arn"       (required) — IAM role ARN to assume.
//   - "session_name"   (optional) — RoleSessionName; defaults to "straylight-exec".
//   - "duration_secs"  (optional) — session TTL in seconds; defaults to 900.
//   - "region"         (optional) — AWS_DEFAULT_REGION; defaults to "us-east-1".
type AWSWebIdentityAdapter struct {
	sts STSWebIdentityClient
}

// NewAWSWebIdentityAdapter creates an AWSWebIdentityAdapter backed by the
// given STSWebIdentityClient.
func NewAWSWebIdentityAdapter(sts STSWebIdentityClient) *AWSWebIdentityAdapter {
	return &AWSWebIdentityAdapter{sts: sts}
}

// ProviderType implements ExchangeAdapter.
func (a *AWSWebIdentityAdapter) ProviderType() string { return "aws" }

// Exchange implements ExchangeAdapter. It calls STS AssumeRoleWithWebIdentity
// with the identity proof token and returns short-lived AWS credentials as
// AWS_* environment variables.
//
// The identity proof token is forwarded to STS as the WebIdentityToken; it is
// never included in the returned EnvVars (MCP no-passthrough).
func (a *AWSWebIdentityAdapter) Exchange(ctx context.Context, in ExchangeInput) (*ExchangedCredential, error) {
	roleARN := in.Params["role_arn"]
	if roleARN == "" {
		return nil, fmt.Errorf("tokenexchange: aws web-identity adapter: role_arn is required in Params")
	}

	sessionName := in.Params["session_name"]
	if sessionName == "" {
		sessionName = awsDefaultSessionName
	}

	region := in.Params["region"]
	if region == "" {
		region = awsDefaultRegion
	}

	duration := awsDefaultDurationSecs
	if ds := in.Params["duration_secs"]; ds != "" {
		parsed, err := strconv.ParseInt(ds, 10, 32)
		if err == nil && parsed > 0 {
			duration = int32(parsed)
		}
	}
	// Clamp to the STS maximum to avoid an opaque ValidationError from AWS.
	if duration > awsMaxDurationSecs {
		duration = awsMaxDurationSecs
	}

	stsIn := STSAssumeRoleWithWebIdentityInput{
		RoleARN:          roleARN,
		SessionName:      sessionName,
		WebIdentityToken: in.Proof.Token, // never echoed in output
		DurationSeconds:  duration,
	}
	if policy := in.Params["policy"]; policy != "" {
		stsIn.Policy = &policy
	}

	result, err := a.sts.AssumeRoleWithWebIdentity(ctx, stsIn)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: aws web-identity sts: %w", err)
	}

	return &ExchangedCredential{
		EnvVars: map[string]string{
			"AWS_ACCESS_KEY_ID":     result.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY": result.SecretAccessKey,
			"AWS_SESSION_TOKEN":     result.SessionToken,
			"AWS_DEFAULT_REGION":    region,
		},
		ExpiresAt: result.Expiration,
		Audience:  in.Audience,
		Scope:     fmt.Sprintf("aws sts assume-role-with-web-identity %s (region=%s)", roleARN, region),
	}, nil
}
