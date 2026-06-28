// Package proxy — Injector interface and registry for credential injection strategies.
package proxy

import (
	"fmt"
	"net/http"

	"github.com/straylight-ai/straylight/internal/services"
)

// Injector applies credentials to an outbound HTTP request.
// Each injection strategy implements this interface.
type Injector interface {
	// Inject modifies req in place to include the authentication credentials.
	// fields contains the credential key-value pairs read from the vault.
	// config contains the injection parameters from the auth method definition.
	Inject(req *http.Request, fields map[string]string, config services.InjectionConfig) error
}

// InjectorRegistry maps injection type names to Injector implementations.
// Use NewInjectorRegistry to construct, then Register to add injectors.
type InjectorRegistry struct {
	injectors map[string]Injector
}

// NewInjectorRegistry creates an empty InjectorRegistry.
func NewInjectorRegistry() *InjectorRegistry {
	return &InjectorRegistry{
		injectors: make(map[string]Injector),
	}
}

// Register associates typeName with the given Injector.
// Calling Register twice with the same typeName replaces the previous entry.
func (r *InjectorRegistry) Register(typeName string, injector Injector) {
	r.injectors[typeName] = injector
}

// Get returns the Injector registered for typeName.
// Returns a descriptive error if no injector is registered for typeName.
func (r *InjectorRegistry) Get(typeName string) (Injector, error) {
	inj, ok := r.injectors[typeName]
	if !ok {
		return nil, fmt.Errorf("proxy: no injector registered for type %q", typeName)
	}
	return inj, nil
}

// DefaultInjectorRegistry creates an InjectorRegistry pre-loaded with all
// built-in injection strategies (five original + three Wave-2 additions).
func DefaultInjectorRegistry() *InjectorRegistry {
	r := NewInjectorRegistry()
	// Original five injectors (unchanged).
	r.Register(string(services.InjectionBearerHeader), &BearerHeaderInjector{})
	r.Register(string(services.InjectionCustomHeader), &CustomHeaderInjector{})
	r.Register(string(services.InjectionMultiHeader), &MultiHeaderInjector{})
	r.Register(string(services.InjectionQueryParam), &QueryParamInjector{})
	r.Register(string(services.InjectionBasicAuth), &BasicAuthInjector{})
	// Wave 2: generic custom_auth injector.
	r.Register(string(services.InjectionCustomAuth), &CustomAuthInjector{})
	// Wave 2: HMAC signer.
	r.Register(string(services.InjectionHMACSignature), &HMACInjector{})
	// Wave 2: AWS SigV4 signer — registered under both the new enum type and
	// the legacy named_strategy dispatch key "aws_sigv4" so the existing aws
	// template (InjectionNamedStrategy + Strategy:"aws_sigv4") continues to work.
	awsInj := &AWSSigV4Injector{}
	r.Register(string(services.InjectionAWSSigV4), awsInj)
	r.Register("aws_sigv4", awsInj) // legacy named_strategy key
	return r
}
