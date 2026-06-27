package server

import "net/http"

// registerOIDCRoutes registers the public OIDC discovery and JWKS endpoints.
// Both paths are always registered; when OIDCDiscovery is nil they return 404.
// These endpoints are unauthenticated by design — cloud providers fetch them
// server-to-server and do not present credentials.
func registerOIDCRoutes(s *Server) {
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOIDCDiscovery)
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
}

// handleOIDCDiscovery serves GET /.well-known/openid-configuration.
// Returns the OIDC discovery document with issuer, jwks_uri, and supported algorithms.
// Returns 404 when no OIDCDiscovery is configured.
func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	if s.cfg.OIDCDiscovery == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.OIDCDiscovery.OIDCConfig())
}

// handleJWKS serves GET /.well-known/jwks.json.
// Returns the public JWKS containing only public signing keys.
// Returns 404 when no OIDCDiscovery is configured.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if s.cfg.OIDCDiscovery == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.OIDCDiscovery.PublicJWKS())
}
