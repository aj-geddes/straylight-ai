package cloud

import (
	"context"
	"fmt"
	"time"
)

const (
	// awsDefaultSessionDurationSecs is the AWS STS minimum and our default TTL.
	awsDefaultSessionDurationSecs = 900

	// awsDefaultRegion is used when no region is specified in the service config.
	awsDefaultRegion = "us-east-1"

	// awsSessionName is the RoleSessionName passed to STS AssumeRole.
	awsSessionName = "straylight-exec"
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
	// STSClient is the STS API client. Required.
	STSClient STSClient
}

// AWSProvider generates temporary AWS credentials via STS AssumeRole.
type AWSProvider struct {
	sts STSClient
}

// NewAWSProvider creates an AWSProvider with the given configuration.
func NewAWSProvider(cfg AWSProviderConfig) *AWSProvider {
	return &AWSProvider{
		sts: cfg.STSClient,
	}
}

// CloudType implements Provider.
func (p *AWSProvider) CloudType() string { return "aws" }

// GenerateCredentials calls STS AssumeRole with the configured role ARN and
// returns temporary credentials as AWS_* environment variables.
//
// The admin/root AWS credentials used to call STS are never included in the
// returned Credentials struct — only the temp credentials are returned.
func (p *AWSProvider) GenerateCredentials(ctx context.Context, cfg ServiceConfig) (*Credentials, error) {
	if cfg.AWS == nil {
		return nil, fmt.Errorf("cloud: aws config is required for engine %q", cfg.Engine)
	}

	awsCfg := cfg.AWS

	// Apply defaults.
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
