// Package oidc provides OIDC discovery and JWKS types for Straylight public endpoints.
package oidc

// JWKKey represents a JSON Web Key
type JWKKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWKKey `json:"keys"`
}

// Discovery represents OIDC discovery information
type Discovery struct {
	IssuerURL     string
	JWKSURI       string
	SupportedAlgs []string
	Keys          []JWKKey
}

// OIDCConfig returns the OIDC discovery document as a map
func (d *Discovery) OIDCConfig() map[string]interface{} {
	config := map[string]interface{}{
		"issuer":                                d.IssuerURL,
		"jwks_uri":                              d.JWKSURI,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "client_secret_basic"},
	}

	if len(d.SupportedAlgs) > 0 {
		config["id_token_signing_alg_values_supported"] = d.SupportedAlgs
	} else {
		config["id_token_signing_alg_values_supported"] = []string{"RS256"}
	}

	return config
}

// PublicJWKS returns the public JWK set
func (d *Discovery) PublicJWKS() JWKSet {
	return JWKSet{Keys: d.Keys}
}
