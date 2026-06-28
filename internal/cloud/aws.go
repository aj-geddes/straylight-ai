package cloud

import (
	"context"
	"fmt"
	"time"

	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

const (
	// awsDefaultSessionDurationSecs is the AWS STS minimum and our default TTL.
	awsDefaultSessionDurationSecs = 900

	// awsDefaultRegion is used when no region is specified in the service config.
	awsDefaultRegion = "us-east-1"

	// awsSessionName is the RoleSessionName passed to STS AssumeRole.
	awsSessionName = "straylight-exec"

	// awsDefaultAudience is the STS audience used when none is specified in
	// the WebIdentity config.
	awsDefaultAudience = "sts.amazonaws.com"
)

// STSAssumeRoleInput holds the parameters for an STS AssumeRole call.
// This abstraction allows the real AWS SDK client and test mocks to share the
// same interface.
type STSAssumeRoleInput struct {
	// RoleARN is the ARN of the role to assume.
	RoleARN string

	// SessionName identifies the session in CloudTrail.
	SessionName string

	// DurationSeconds is the requested session TTL (900-43200).
	DurationSeconds int32

	// Policy is an optional inline session policy JSON string.
	Policy *string
}

// STSCredentials holds the temporary credentials returned by STS AssumeRole.
type STSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// STSClient is the interface for calling AWS STS AssumeRole.
// The canonical implementation wraps aws-sdk-go-v2/service/sts.Client.
// Test mocks implement this interface directly.
type STSClient interface {
	AssumeRole(ctx context.Context, input STSAssumeRoleInput) (*STSCredentials, error)
}

// AWSProviderConfig holds dependencies for the AWSProvider.
type AWSProviderConfig struct {
	// STSClient is the STS API client for the static AssumeRole path. Required
	// for the static path; unused when the keyless path is selected.
	STSClient STSClient

	// Engine is the token-exchange engine for the keyless
	// AssumeRoleWithWebIdentity path (ADR-012 Phase 2). When nil, the keyless
	// path cannot be selected even if AWSConfig.WebIdentity is set.
	Engine *tokenexchange.Engine
}

// AWSProvider generates temporary AWS credentials via STS.
// It supports two paths:
//   - Static path (default): STS AssumeRole using admin credentials from vault.
//   - Keyless path (ADR-012): STS AssumeRoleWithWebIdentity using an OpenBao
//     OIDC identity token — no static admin keys required.
//
// The keyless path is selected when AWSConfig.WebIdentity is non-nil and an
// Engine is configured. Otherwise the static path is used unchanged.
type AWSProvider struct {
	sts    STSClient
	engine *tokenexchange.Engine
}

// NewAWSProvider creates an AWSProvider with the given configuration.
func NewAWSProvider(cfg AWSProviderConfig) *AWSProvider {
	return &AWSProvider{
		sts:    cfg.STSClient,
		engine: cfg.Engine,
	}
}

// CloudType implements Provider.
func (p *AWSProvider) CloudType() string { return "aws" }

// GenerateCredentials returns temporary AWS credentials as AWS_* environment
// variables.
//
// Branch logic (ADR-012 backward compat guarantee):
//   - If cfg.AWS.WebIdentity is non-nil AND an Engine is configured → keyless
//     path via STS AssumeRoleWithWebIdentity (no static admin keys used).
//   - Otherwise → existing static AssumeRole path, UNCHANGED.
//
// The admin/root AWS credentials used to call the static AssumeRole path are
// never included in the returned Credentials struct.
func (p *AWSProvider) GenerateCredentials(ctx context.Context, cfg ServiceConfig) (*Credentials, error) {
	if cfg.AWS == nil {
		return nil, fmt.Errorf("cloud: aws config is required for engine %q", cfg.Engine)
	}

	// ── Keyless branch (ADR-012 Phase 2) ──────────────────────────────────
	if cfg.AWS.WebIdentity != nil && p.engine != nil {
		return p.generateKeylessCredentials(ctx, cfg.AWS)
	}

	// ── Static branch (unchanged from pre-ADR-012) ─────────────────────────
	return p.generateStaticCredentials(ctx, cfg.AWS)
}

// generateKeylessCredentials implements the ADR-012 Phase 2 keyless path.
// It delegates to the token-exchange Engine, which calls the OpenBao identity
// source for a proof token and then calls the AWSWebIdentityAdapter to exchange
// it for STS credentials via AssumeRoleWithWebIdentity.
func (p *AWSProvider) generateKeylessCredentials(ctx context.Context, awsCfg *AWSConfig) (*Credentials, error) {
	audience := awsCfg.WebIdentity.Audience
	if audience == "" {
		audience = awsDefaultAudience
	}

	region := awsCfg.Region
	if region == "" {
		region = awsDefaultRegion
	}

	in := tokenexchange.ExchangeInput{
		Audience: audience,
		Params: map[string]string{
			"role_arn":     awsCfg.RoleARN,
			"session_name": awsSessionName,
			"region":       region,
		},
		RequestedTTL: time.Duration(awsCfg.SessionDurationSecs) * time.Second,
	}
	if awsCfg.SessionPolicy != "" {
		in.Params["policy"] = awsCfg.SessionPolicy
	}

	exchanged, err := p.engine.Credential(ctx, awsCfg.RoleARN, "aws", in)
	if err != nil {
		return nil, fmt.Errorf("cloud: aws: keyless exchange for role %q: %w", awsCfg.RoleARN, err)
	}

	return &Credentials{
		EnvVars:   exchanged.EnvVars,
		ExpiresAt: exchanged.ExpiresAt,
		Provider:  "aws",
		Scope:     exchanged.Scope,
	}, nil
}

// generateStaticCredentials is the existing pre-ADR-012 AssumeRole path,
// unchanged. Admin AWS credentials (stored in vault) are used to call STS.
func (p *AWSProvider) generateStaticCredentials(ctx context.Context, awsCfg *AWSConfig) (*Credentials, error) {
	duration := awsCfg.SessionDurationSecs
	if duration <= 0 {
		duration = awsDefaultSessionDurationSecs
	}

	region := awsCfg.Region
	if region == "" {
		region = awsDefaultRegion
	}

	input := STSAssumeRoleInput{
		RoleARN:         awsCfg.RoleARN,
		SessionName:     awsSessionName,
		DurationSeconds: duration,
	}
	if awsCfg.SessionPolicy != "" {
		input.Policy = &awsCfg.SessionPolicy
	}

	result, err := p.sts.AssumeRole(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("cloud: aws: sts assume-role %q: %w", awsCfg.RoleARN, err)
	}

	envVars := map[string]string{
		"AWS_ACCESS_KEY_ID":     result.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": result.SecretAccessKey,
		"AWS_SESSION_TOKEN":     result.SessionToken,
		"AWS_DEFAULT_REGION":    region,
	}

	scope := fmt.Sprintf("aws sts assume-role %s (region=%s)", awsCfg.RoleARN, region)

	return &Credentials{
		EnvVars:   envVars,
		ExpiresAt: result.Expiration,
		Provider:  "aws",
		Scope:     scope,
	}, nil
}
