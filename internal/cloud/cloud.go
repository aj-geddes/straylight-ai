// Package cloud implements temporary cloud credential generation for AWS, GCP,
// and Azure. It is used by the straylight_exec MCP tool to inject short-lived
// credentials into command executions so that long-lived root/admin credentials
// never leave the container.
//
// Architecture:
//   - Provider is the interface each cloud implementation satisfies.
//   - Manager coordinates providers and caches credentials until expiry.
//   - Root credentials are read once and used only to generate temp credentials.
//   - Temp credentials are cached per service name for their full TTL.
package cloud

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Provider generates temporary credentials for a single cloud platform.
type Provider interface {
	// GenerateCredentials calls the cloud provider's token/credential API and
	// returns short-lived credentials suitable for injection as env vars.
	GenerateCredentials(ctx context.Context, cfg ServiceConfig) (*Credentials, error)

	// CloudType returns the provider identifier: "aws", "gcp", or "azure".
	CloudType() string
}

// Credentials holds the temporary cloud credentials returned by a Provider.
type Credentials struct {
	// EnvVars maps environment variable names to their values.
	// For AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_DEFAULT_REGION.
	// For GCP: CLOUDSDK_AUTH_ACCESS_TOKEN, CLOUDSDK_CORE_PROJECT.
	// For Azure: AZURE_ACCESS_TOKEN, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID.
	EnvVars map[string]string

	// ExpiresAt is when these credentials become invalid.
	ExpiresAt time.Time

	// Provider is the cloud type that issued these credentials ("aws", "gcp", "azure").
	Provider string

	// Scope is a human-readable description of the credential scope for audit logging.
	Scope string
}

// ServiceConfig holds the cloud-specific configuration for a service.
// Only the fields corresponding to Engine will be used.
type ServiceConfig struct {
	// Engine is the cloud provider: "aws", "gcp", or "azure".
	Engine string

	// AWS holds AWS-specific configuration. Required when Engine is "aws".
	AWS *AWSConfig

	// GCP holds GCP-specific configuration. Required when Engine is "gcp".
	GCP *GCPConfig

	// Azure holds Azure-specific configuration. Required when Engine is "azure".
	Azure *AzureConfig
}

// AWSConfig holds AWS-specific configuration for STS AssumeRole.
type AWSConfig struct {
	// RoleARN is the IAM role to assume, e.g. "arn:aws:iam::123456789012:role/StrayLightRole".
	RoleARN string

	// Region sets AWS_DEFAULT_REGION in the resulting env vars. Defaults to "us-east-1".
	Region string

	// SessionDurationSecs is the TTL for the STS session. Range: 900-43200.
	// Zero defaults to 900 (15 minutes, the AWS minimum).
	SessionDurationSecs int32

	// SessionPolicy is an optional inline IAM policy JSON to scope permissions
	// below what the role allows. Empty means no further restriction.
	SessionPolicy string
}

// GCPConfig holds GCP-specific configuration for access token generation.
type GCPConfig struct {
	// ServiceAccountJSON is the content of the service account key JSON file.
	ServiceAccountJSON string

	// ProjectID sets CLOUDSDK_CORE_PROJECT in the resulting env vars.
	ProjectID string

	// Scopes are the OAuth2 scopes for the access token.
	// Default: ["https://www.googleapis.com/auth/cloud-platform"].
	Scopes []string

	// TokenLifetimeSecs is the requested token lifetime. Range: 0-43200.
	// Zero defaults to 3600 (1 hour, the GCP default).
	TokenLifetimeSecs int
}

// AzureConfig holds Azure-specific configuration for client credentials token exchange.
type AzureConfig struct {
	// TenantID is the Azure Active Directory tenant ID.
	TenantID string

	// ClientID is the service principal application (client) ID.
	ClientID string

	// ClientSecret is the service principal secret. Never included in output env vars.
	ClientSecret string

	// SubscriptionID sets AZURE_SUBSCRIPTION_ID in the resulting env vars.
	SubscriptionID string

	// Scope is the token audience, e.g. "https://management.azure.com/.default".
	// Defaults to "https://management.azure.com/.default".
	Scope string
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// cacheEntry pairs credentials with their expiry for cache lookups.
type cacheEntry struct {
	creds     *Credentials
	expiresAt time.Time
}

// Manager coordinates cloud providers and caches temp credentials.
// It is safe for concurrent use.
type Manager struct {
	mu        sync.RWMutex
	providers map[string]Provider // keyed by cloud type ("aws", "gcp", "azure")
	cache     map[string]*cacheEntry // keyed by service name
}

// NewManager creates a Manager with the given providers.
// providers maps cloud type strings ("aws", "gcp", "azure") to Provider implementations.
func NewManager(providers map[string]Provider) *Manager {
	return &Manager{
		providers: providers,
		cache:     make(map[string]*cacheEntry),
	}
}

// GetCredentials returns temporary credentials for the named service.
// If valid credentials exist in the cache, they are returned immediately.
// Otherwise the appropriate Provider is called to generate new credentials.
//
// Returns an error if the cloud engine is unknown or credential generation fails.
func (m *Manager) GetCredentials(ctx context.Context, serviceName string, cfg ServiceConfig) (*Credentials, error) {
	// Check cache first (read lock).
	m.mu.RLock()
	entry, ok := m.cache[serviceName]
	m.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.creds, nil
	}

	// Cache miss or expired — look up the provider.
	provider, err := m.providerFor(cfg.Engine)
	if err != nil {
		return nil, err
	}

	// Generate new credentials.
	creds, err := provider.GenerateCredentials(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("cloud: generate credentials for %q: %w", serviceName, err)
	}

	// Store in cache.
	m.mu.Lock()
	m.cache[serviceName] = &cacheEntry{
		creds:     creds,
		expiresAt: creds.ExpiresAt,
	}
	m.mu.Unlock()

	return creds, nil
}

// InvalidateCache removes a service's cached credentials, forcing the next
// call to generate fresh ones. Safe to call even if no entry exists.
func (m *Manager) InvalidateCache(serviceName string) {
	m.mu.Lock()
	delete(m.cache, serviceName)
	m.mu.Unlock()
}

// providerFor returns the Provider for the given cloud engine name.
func (m *Manager) providerFor(engine string) (Provider, error) {
	p, ok := m.providers[engine]
	if !ok {
		return nil, fmt.Errorf("cloud: unsupported engine %q: must be one of aws, gcp, azure", engine)
	}
	return p, nil
}
