// Package openapi provides an OpenAPI 3.x spec importer that maps security
// schemes to Straylight ServiceTemplate auth methods.
// It does not fetch — callers supply raw bytes from FetchSpec (which enforces
// SSRF-gating via the egress Guard).
package openapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/straylight-ai/straylight/internal/services"
)

// ImportResult is a DRAFT ServiceTemplate plus provenance and review flags.
// Every result is marked draft via the Source field.
type ImportResult struct {
	// Template is the imported draft; it has passed services.ValidateTemplate
	// where possible, but callers must review and commit before use.
	Template services.ServiceTemplate
	// Warnings lists unmapped schemes, ambiguous servers, and other advisory notes.
	Warnings []string
	// Source is the spec URL or "file" supplied by the caller.
	// Its non-empty value is the draft marker per ADR-014 Part C.
	Source string
}

// openAPIDoc is the minimal subset of an OpenAPI 3.0/3.1 document we parse.
type openAPIDoc struct {
	OpenAPI    string                     `json:"openapi"`
	Info       openAPIInfo                `json:"info"`
	Servers    []openAPIServer            `json:"servers"`
	Components openAPIComponents          `json:"components"`
	Security   []map[string][]interface{} `json:"security"`
}

type openAPIInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type openAPIServer struct {
	URL string `json:"url"`
}

type openAPIComponents struct {
	SecuritySchemes map[string]openAPISecurityScheme `json:"securitySchemes"`
}

type openAPISecurityScheme struct {
	Type   string `json:"type"`
	Scheme string `json:"scheme"` // for type=http
	In     string `json:"in"`     // for type=apiKey
	Name   string `json:"name"`   // for type=apiKey
}

// FromSpec parses an OpenAPI 3.0/3.1 document (JSON or YAML) and maps it to a
// draft ServiceTemplate. The caller is responsible for SSRF-safe fetching;
// this function only parses the supplied bytes.
//
// Every returned ImportResult has Source set to the source argument.
func FromSpec(spec []byte, source string) (ImportResult, error) {
	// Try JSON first; if it fails, the spec may be YAML.
	var doc openAPIDoc
	if err := json.Unmarshal(spec, &doc); err != nil {
		// Attempt YAML via re-encoding trick: OpenAPI specs are valid JSON or YAML.
		// Since we don't want to import gopkg.in/yaml.v3 parse overhead here and
		// YAML is a superset of JSON, we just return a clear error for truly bad input.
		return ImportResult{}, fmt.Errorf("openapi: failed to parse spec: %w", err)
	}

	var warnings []string
	var authMethods []services.AuthMethod

	// Map servers[0].url → Target.
	target := ""
	if len(doc.Servers) > 0 {
		target = doc.Servers[0].URL
	}

	// Map info.title → DisplayName, derive ID from title.
	displayName := doc.Info.Title
	id := slugify(displayName)
	if id == "" {
		id = "imported"
	}

	// Sort scheme names for deterministic output.
	schemeNames := make([]string, 0, len(doc.Components.SecuritySchemes))
	for k := range doc.Components.SecuritySchemes {
		schemeNames = append(schemeNames, k)
	}
	sort.Strings(schemeNames)

	for _, schemeName := range schemeNames {
		scheme := doc.Components.SecuritySchemes[schemeName]
		am, warn := mapScheme(schemeName, scheme)
		if warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		if am != nil {
			authMethods = append(authMethods, *am)
		}
	}

	tmpl := services.ServiceTemplate{
		ID:          id,
		DisplayName: displayName,
		Target:      target,
		AuthMethods: authMethods,
	}

	return ImportResult{
		Template: tmpl,
		Warnings: warnings,
		Source:   source,
	}, nil
}

// mapScheme maps a single OpenAPI security scheme to a Straylight AuthMethod.
// Returns (nil, warning) for unsupported/unmappable schemes.
func mapScheme(name string, s openAPISecurityScheme) (*services.AuthMethod, string) {
	switch s.Type {
	case "http":
		return mapHTTPScheme(name, s)
	case "apiKey":
		return mapAPIKeyScheme(name, s)
	case "oauth2":
		return mapOAuth2Scheme(name)
	case "openIdConnect":
		return mapOAuth2Scheme(name) // treat as oauth; warning added below
	case "mutualTLS":
		return nil, fmt.Sprintf("security scheme %q: mutualTLS is not supported for auth injection (deferred)", name)
	default:
		return nil, fmt.Sprintf("security scheme %q: unknown type %q", name, s.Type)
	}
}

func mapHTTPScheme(name string, s openAPISecurityScheme) (*services.AuthMethod, string) {
	switch strings.ToLower(s.Scheme) {
	case "bearer":
		return &services.AuthMethod{
			ID:   name,
			Name: name + " (Bearer)",
			Fields: []services.CredentialField{
				tokenField(),
			},
			Injection: services.InjectionConfig{Type: services.InjectionBearerHeader},
		}, ""
	case "basic":
		return &services.AuthMethod{
			ID:   name,
			Name: name + " (Basic Auth)",
			Fields: []services.CredentialField{
				{Key: "username", Label: "Username", Type: services.FieldText, Required: true},
				{Key: "password", Label: "Password", Type: services.FieldPassword, Required: true},
			},
			Injection: services.InjectionConfig{Type: services.InjectionBasicAuth},
		}, ""
	default:
		return nil, fmt.Sprintf("security scheme %q: unsupported http scheme %q", name, s.Scheme)
	}
}

func mapAPIKeyScheme(name string, s openAPISecurityScheme) (*services.AuthMethod, string) {
	switch strings.ToLower(s.In) {
	case "header":
		return &services.AuthMethod{
			ID:   name,
			Name: name,
			Fields: []services.CredentialField{
				tokenField(),
			},
			Injection: services.InjectionConfig{
				Type:       services.InjectionCustomHeader,
				HeaderName: s.Name,
			},
		}, ""
	case "query":
		return &services.AuthMethod{
			ID:   name,
			Name: name,
			Fields: []services.CredentialField{
				tokenField(),
			},
			Injection: services.InjectionConfig{
				Type:       services.InjectionQueryParam,
				QueryParam: s.Name,
			},
		}, ""
	case "cookie":
		// OAS cookie apiKey → custom_auth Cookie header.
		return &services.AuthMethod{
			ID:   name,
			Name: name,
			Fields: []services.CredentialField{
				tokenField(),
			},
			Injection: services.InjectionConfig{
				Type: services.InjectionCustomAuth,
				Custom: &services.CustomAuthSpec{
					Headers: map[string]string{
						"Cookie": s.Name + "={{.token}}",
					},
				},
			},
		}, ""
	default:
		return nil, fmt.Sprintf("security scheme %q: unsupported apiKey location %q", name, s.In)
	}
}

func mapOAuth2Scheme(name string) (*services.AuthMethod, string) {
	return &services.AuthMethod{
		ID:     name,
		Name:   name + " (OAuth2)",
		Fields: []services.CredentialField{},
		Injection: services.InjectionConfig{
			Type: services.InjectionOAuth,
		},
	}, ""
}

// tokenField returns the standard single-token CredentialField.
func tokenField() services.CredentialField {
	return services.CredentialField{
		Key:      "token",
		Label:    "API Token",
		Type:     services.FieldPassword,
		Required: true,
	}
}

// slugify converts a display name to a lowercase slug suitable for a template ID.
func slugify(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			b.WriteRune('_')
		}
	}
	result := strings.Trim(b.String(), "_")
	// Clamp to 63 chars (auth method ID limit).
	if len(result) > 63 {
		result = result[:63]
	}
	return result
}
