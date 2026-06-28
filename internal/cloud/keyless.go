// Package cloud — keyless wiring (ADR-012 Phase 2).
package cloud

import (
	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// BuildKeylessCloudManager is the ADR-012 Phase 2 wiring function. It:
//
//  1. Creates an OpenBaoIdentitySource from gen + role.
//  2. Builds a token-exchange Engine with adapters for all three cloud providers
//     (AWS/GCP/Azure), using the given client implementations for each.
//  3. Returns a Manager whose AWSProvider, GCPProvider, and AzureProvider all
//     share that Engine so keyless credentials are available to any service that
//     opts in via a WebIdentity / WIF / FIC config block.
//
// Backward compatibility: services whose ServiceConfig has no WebIdentity block
// continue to use their existing static credential path; the Engine is never
// consulted for those services (the double-guard in each provider guarantees this).
//
// staticAWSClient is the STS client used by the static AssumeRole path. It is
// required so that services without a WebIdentity config remain unaffected.
//
// The Engine starts a background refresh goroutine. Callers that need a clean
// shutdown should call Close on the Engine; the engine is retained only by the
// providers so it will not be garbage-collected while the Manager is in use.
func BuildKeylessCloudManager(
	gen tokenexchange.TokenGenerator,
	role string,
	awsWebIdentityClient tokenexchange.STSWebIdentityClient,
	gcpSTSClient tokenexchange.GCPSTSClient,
	azureTokenClient tokenexchange.AzureTokenClient,
	staticAWSClient STSClient,
) *Manager {
	// 1. Identity source: OpenBao identity-token issuer (ADR-012 Decision B1).
	source := tokenexchange.NewOpenBaoIdentitySource(role, gen)

	// 2. Per-provider exchange adapters.
	awsAdapter := tokenexchange.NewAWSWebIdentityAdapter(awsWebIdentityClient)
	gcpAdapter := tokenexchange.NewGCPWIFAdapter(gcpSTSClient)
	azureAdapter := tokenexchange.NewAzureFICAdapter(azureTokenClient)

	// 3. Shared token-exchange Engine (one engine, three adapters).
	engine := tokenexchange.NewEngine(tokenexchange.EngineConfig{
		Source: source,
		Adapters: map[string]tokenexchange.ExchangeAdapter{
			"aws":   awsAdapter,
			"gcp":   gcpAdapter,
			"azure": azureAdapter,
		},
	})

	// 4. Cloud providers, each receiving the shared Engine.
	awsProvider := NewAWSProvider(AWSProviderConfig{
		STSClient: staticAWSClient,
		Engine:    engine,
	})
	gcpProvider := NewGCPProvider(GCPProviderConfig{
		Engine: engine,
	})
	azureProvider := NewAzureProvider(AzureProviderConfig{
		Engine: engine,
	})

	// 5. Manager that dispatches by cloud type. The Engine starts a background
	// refresh goroutine; the manager's Close method stops it. Callers must call
	// Close when the server shuts down (see cmd/straylight/main.go).
	return newManagerWithStop(map[string]Provider{
		"aws":   awsProvider,
		"gcp":   gcpProvider,
		"azure": azureProvider,
	}, engine.Close)
}
