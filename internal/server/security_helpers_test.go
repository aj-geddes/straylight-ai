package server_test

import (
	"github.com/straylight-ai/straylight/internal/services"
)

// newRegistryWithVault creates a services.Registry backed by the given mock vault.
// Used in security tests that directly test registry operations.
func newRegistryWithVault(vault services.VaultClient) *services.Registry {
	return services.NewRegistry(vault)
}

// validService returns a minimal valid services.Service for the given name.
// All fields satisfy the registry validation rules.
func validService(name string) services.Service {
	return services.Service{
		Name:   name,
		Type:   "http_proxy",
		Target: "https://api.example.com",
		Inject: "header",
	}
}
