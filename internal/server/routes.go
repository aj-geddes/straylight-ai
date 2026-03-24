package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/straylight-ai/straylight/internal/services"
	"github.com/straylight-ai/straylight/internal/web"
)

// registerRoutes attaches all HTTP route handlers to the server's mux and
// wraps the mux with the security middleware chain.
func registerRoutes(s *Server) {
	// Health endpoint — method-specific pattern (Go 1.22+).
	// An additional catch-all for the same path returns 405 on wrong methods.
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/health", s.handleMethodNotAllowed)

	// Stats endpoint — in-memory activity log and service counts.
	s.mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	s.mux.HandleFunc("/api/v1/stats", s.handleMethodNotAllowed)

	if s.cfg.Registry != nil {
		// Service management endpoints (WP-1.1).
		s.mux.HandleFunc("GET /api/v1/services", s.handleListServices)
		s.mux.HandleFunc("POST /api/v1/services", s.handleCreateService)
		s.mux.HandleFunc("GET /api/v1/services/{name}/check", s.handleCheckCredential)
		s.mux.HandleFunc("GET /api/v1/services/{name}", s.handleGetService)
		s.mux.HandleFunc("PUT /api/v1/services/{name}", s.handleUpdateService)
		s.mux.HandleFunc("DELETE /api/v1/services/{name}", s.handleDeleteService)
		s.mux.HandleFunc("/api/v1/services/{name}", s.handleMethodNotAllowed)
		s.mux.HandleFunc("/api/v1/services", s.handleMethodNotAllowed)

		// Credential rotation endpoint (WP-2.6).
		s.mux.HandleFunc("POST /api/v1/services/{name}/rotate", s.handleRotateCredential)

		// Templates endpoints.
		s.mux.HandleFunc("GET /api/v1/templates", s.handleListTemplates)
		s.mux.HandleFunc("GET /api/v1/templates/{name}", s.handleGetTemplate)
		s.mux.HandleFunc("/api/v1/templates/{name}", s.handleMethodNotAllowed)
		s.mux.HandleFunc("/api/v1/templates", s.handleMethodNotAllowed)
	} else {
		// Stub when no registry is configured (pre-WP-1.1 state).
		s.mux.HandleFunc("/api/v1/services/", s.handleNotImplemented)
		s.mux.HandleFunc("/api/v1/services", s.handleNotImplemented)
		s.mux.HandleFunc("/api/v1/templates", s.handleNotImplemented)
	}

	// MCP tool forwarding endpoints (WP-1.4).
	if s.cfg.MCPHandler != nil {
		s.mux.HandleFunc("GET /api/v1/mcp/tool-list", s.cfg.MCPHandler.HandleToolList)
		s.mux.HandleFunc("POST /api/v1/mcp/tool-call", s.cfg.MCPHandler.HandleToolCall)
		s.mux.HandleFunc("/api/v1/mcp/", s.handleMethodNotAllowed)
	} else {
		s.mux.HandleFunc("/api/v1/mcp/", s.handleNotImplemented)
	}

	// OAuth endpoints (WP-1.7).
	if s.cfg.OAuthHandler != nil {
		s.mux.HandleFunc("GET /api/v1/oauth/{provider}/start", s.cfg.OAuthHandler.StartOAuth)
		s.mux.HandleFunc("GET /api/v1/oauth/callback", s.cfg.OAuthHandler.Callback)
		// OAuth App credential management endpoints.
		s.mux.HandleFunc("GET /api/v1/oauth/{provider}/config", s.cfg.OAuthHandler.GetOAuthConfig)
		s.mux.HandleFunc("POST /api/v1/oauth/{provider}/config", s.cfg.OAuthHandler.SaveOAuthConfig)
		s.mux.HandleFunc("DELETE /api/v1/oauth/{provider}/config", s.cfg.OAuthHandler.DeleteOAuthConfig)
		// Device Authorization Flow endpoints (RFC 8628).
		// These allow GitHub (and future providers) to work with zero OAuth App
		// registration by the end user. The client_id is baked into the product.
		s.mux.HandleFunc("POST /api/v1/oauth/{provider}/device/start", s.cfg.OAuthHandler.StartDeviceFlow)
		s.mux.HandleFunc("POST /api/v1/oauth/{provider}/device/poll", s.cfg.OAuthHandler.PollDeviceFlow)
		s.mux.HandleFunc("/api/v1/oauth/", s.handleMethodNotAllowed)
	} else {
		s.mux.HandleFunc("/api/v1/oauth/", s.handleNotImplemented)
	}

	// Web UI — serve the embedded React SPA with SPA fallback routing.
	// All non-API paths are handled here; unknown paths return index.html
	// so that client-side routing (React Router) can take over.
	webHandler := web.NewHandler(web.DistFS())
	s.mux.Handle("/", webHandler)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// healthResponse is the JSON payload returned by GET /api/v1/health.
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	OpenBao string `json:"openbao"`
}

// handleHealth returns the current system health status including OpenBao vault status.
// Returns 200 with status=ok when OpenBao is unsealed.
// Returns 503 with status=degraded when OpenBao is sealed or unavailable.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	openBaoStatus := "unavailable"
	if s.cfg.VaultStatus != nil {
		openBaoStatus = s.cfg.VaultStatus()
	}

	statusCode := http.StatusOK
	healthStatus := "ok"
	if openBaoStatus != "unsealed" {
		statusCode = http.StatusServiceUnavailable
		healthStatus = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := healthResponse{
		Status:  healthStatus,
		Version: s.cfg.Version,
		OpenBao: openBaoStatus,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("health: failed to encode response", "error", err)
	}
}

// ---------------------------------------------------------------------------
// Stats endpoint
// ---------------------------------------------------------------------------

// handleStats responds to GET /api/v1/stats.
// Returns aggregate activity counts, uptime, and recent tool calls from the
// in-memory ActivityLog. Counts reset when the server restarts.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.cfg.ActivityLog.Stats()

	// Populate total_services from the registry if available.
	if s.cfg.Registry != nil {
		stats.TotalServices = len(s.cfg.Registry.List())
	}

	writeJSON(w, http.StatusOK, stats)
}

// ---------------------------------------------------------------------------
// Service management endpoints
// ---------------------------------------------------------------------------

// createServiceRequest is the JSON body for POST /api/v1/services.
// Supports both the legacy single-credential format and the new multi-field
// credentials format with template + auth_method selection.
type createServiceRequest struct {
	// Service identity and configuration.
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Target         string            `json:"target"`
	// Template-based creation (new format). When Template and AuthMethod are
	// provided, the service type/target/inject are derived from the template.
	Template       string            `json:"template,omitempty"`
	// Legacy injection configuration fields.
	Inject         string            `json:"inject"`
	HeaderName     string            `json:"header_name,omitempty"`
	HeaderTemplate string            `json:"header_template,omitempty"`
	QueryParam     string            `json:"query_param,omitempty"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty"`
	// AuthMethod is the ID of the chosen auth method from the template.
	AuthMethod     string            `json:"auth_method,omitempty"`
	// Credentials is the new multi-field credential map. If both Credentials
	// and Credential are provided, Credentials takes precedence.
	Credentials    map[string]string `json:"credentials,omitempty"`
	// Credential is the legacy single-string credential field.
	Credential     string            `json:"credential,omitempty"`
}

// updateServiceRequest is the JSON body for PUT /api/v1/services/{name}.
// Credential is optional: if neither Credential nor Credentials are provided,
// the existing credentials are preserved.
type updateServiceRequest struct {
	Type           string            `json:"type"`
	Target         string            `json:"target"`
	Inject         string            `json:"inject"`
	HeaderName     string            `json:"header_name,omitempty"`
	HeaderTemplate string            `json:"header_template,omitempty"`
	QueryParam     string            `json:"query_param,omitempty"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty"`
	// AuthMethod is the ID of the auth method being updated.
	AuthMethod     string            `json:"auth_method,omitempty"`
	// Credentials is the new multi-field credential map.
	Credentials    map[string]string `json:"credentials,omitempty"`
	// Credential is the legacy single-string credential field.
	Credential     string            `json:"credential,omitempty"`
}

// rotateCredentialRequest is the JSON body for POST /api/v1/services/{name}/rotate.
type rotateCredentialRequest struct {
	// Credentials is the new multi-field credential map.
	Credentials map[string]string `json:"credentials,omitempty"`
	// Credential is the legacy single-string credential field.
	Credential  string            `json:"credential,omitempty"`
}

// handleListServices responds to GET /api/v1/services.
func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	list := s.cfg.Registry.List()
	writeJSON(w, http.StatusOK, map[string]interface{}{"services": list})
}

// handleCreateService responds to POST /api/v1/services.
//
// Two creation paths are supported:
//   - Template path: template + auth_method + credentials (map) provided.
//     Looks up the template, validates credentials against the auth method's
//     field definitions, then calls Registry.CreateWithAuth.
//   - Legacy path: credential (string) provided.
//     Calls Registry.Create for backward compatibility.
//
// When both credentials (map) and credential (string) are provided, the
// credentials map takes precedence.
func (s *Server) handleCreateService(w http.ResponseWriter, r *http.Request) {
	var req createServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, "invalid request body: "+err.Error())
		return
	}

	// Template+auth_method path: credentials map provided (new format).
	if len(req.Credentials) > 0 && req.AuthMethod != "" {
		s.handleCreateServiceWithAuth(w, req)
		return
	}

	// Legacy path: single credential string.
	if req.Credential != "" {
		svc := services.Service{
			Name:           req.Name,
			Type:           req.Type,
			Target:         req.Target,
			Inject:         req.Inject,
			HeaderName:     req.HeaderName,
			HeaderTemplate: req.HeaderTemplate,
			QueryParam:     req.QueryParam,
			DefaultHeaders: req.DefaultHeaders,
		}
		if err := s.cfg.Registry.Create(svc, req.Credential); err != nil {
			if strings.Contains(err.Error(), "already exists") {
				WriteError(w, http.StatusConflict, ErrCodeServiceExists, err.Error())
			} else {
				WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, err.Error())
			}
			return
		}
		created, err := s.cfg.Registry.Get(req.Name)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, "failed to retrieve created service")
			return
		}
		// Best-effort: fetch account info and attach to the service.
		if info := services.FetchAccountInfo(created.Target, req.Credential, "legacy", created.DefaultHeaders); info != nil {
			_ = s.cfg.Registry.SetAccountInfo(req.Name, info)
			created.AccountInfo = info
		}
		writeJSON(w, http.StatusCreated, created)
		return
	}

	// Neither credentials nor credential provided.
	WriteError(w, http.StatusBadRequest, ErrCodeCredentialMissing, "credential or credentials required")
}

// handleCreateServiceWithAuth handles the new multi-auth-method creation path.
// It validates the template, auth method, and credential fields before
// calling Registry.CreateWithAuth.
func (s *Server) handleCreateServiceWithAuth(w http.ResponseWriter, req createServiceRequest) {
	// Validate: template must exist (if provided).
	var tmpl *services.ServiceTemplate
	if req.Template != "" {
		t := findTemplate(req.Template)
		if t == nil {
			WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed,
				fmt.Sprintf("template %q not found", req.Template))
			return
		}
		tmpl = t
	}

	// Validate: auth method must exist on the template (if template was found).
	var authMethod *services.AuthMethod
	if tmpl != nil {
		am := findAuthMethod(tmpl, req.AuthMethod)
		if am == nil {
			WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed,
				fmt.Sprintf("auth method %q not found in template %q", req.AuthMethod, req.Template))
			return
		}
		authMethod = am
	}

	// Validate credential fields against the auth method's field definitions.
	if authMethod != nil {
		if err := validateCredentialFields(authMethod, req.Credentials); err != nil {
			WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, err.Error())
			return
		}
	}

	// Build the service. When a template is provided, derive type, target, and
	// inject from the template (and set inject from the auth method injection type).
	svc := services.Service{
		Name:           req.Name,
		Type:           req.Type,
		Target:         req.Target,
		Inject:         req.Inject,
		HeaderName:     req.HeaderName,
		HeaderTemplate: req.HeaderTemplate,
		QueryParam:     req.QueryParam,
		DefaultHeaders: req.DefaultHeaders,
	}
	if tmpl != nil {
		svc.Type = "http_proxy"
		if tmpl.Target != "" {
			svc.Target = tmpl.Target
		}
		svc.DefaultHeaders = tmpl.DefaultHeaders
	}
	if authMethod != nil {
		svc.Inject = injectionTypeToInject(authMethod.Injection.Type)
	}

	if err := s.cfg.Registry.CreateWithAuth(svc, req.AuthMethod, req.Credentials); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			WriteError(w, http.StatusConflict, ErrCodeServiceExists, err.Error())
		} else {
			WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, err.Error())
		}
		return
	}

	created, err := s.cfg.Registry.Get(req.Name)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, "failed to retrieve created service")
		return
	}
	// Best-effort: fetch account info using the primary credential value.
	// We extract the token field (or value field as fallback) from the credentials map.
	primaryCred := extractPrimaryCredential(req.Credentials)
	if primaryCred != "" {
		if info := services.FetchAccountInfo(created.Target, primaryCred, req.AuthMethod, created.DefaultHeaders); info != nil {
			_ = s.cfg.Registry.SetAccountInfo(req.Name, info)
			created.AccountInfo = info
		}
	}
	writeJSON(w, http.StatusCreated, created)
}

// handleGetService responds to GET /api/v1/services/{name}.
// The Service struct includes auth_method_id (set at creation time via CreateWithAuth).
// Credential values are never included in the response.
func (s *Server) handleGetService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	svc, err := s.cfg.Registry.Get(name)
	if err != nil {
		WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, "service not found")
		return
	}
	writeJSON(w, http.StatusOK, svc)
}

// handleUpdateService responds to PUT /api/v1/services/{name}.
//
// Two update paths are supported:
//   - Multi-field: auth_method + credentials (map) provided.
//     Calls Registry.UpdateCredentials to replace all credential fields.
//   - Legacy: credential (string) provided.
//     Calls Registry.Update with the credential pointer.
//   - No credentials: existing credentials are preserved (credential pointer is nil).
func (s *Server) handleUpdateService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req updateServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, "invalid request body: "+err.Error())
		return
	}

	svc := services.Service{
		Name:           name,
		Type:           req.Type,
		Target:         req.Target,
		Inject:         req.Inject,
		HeaderName:     req.HeaderName,
		HeaderTemplate: req.HeaderTemplate,
		QueryParam:     req.QueryParam,
		DefaultHeaders: req.DefaultHeaders,
	}

	// Multi-field credentials path.
	if len(req.Credentials) > 0 && req.AuthMethod != "" {
		if err := s.cfg.Registry.Update(name, svc, nil); err != nil {
			if strings.Contains(err.Error(), "not found") {
				WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, "service not found")
			} else {
				WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, err.Error())
			}
			return
		}
		if err := s.cfg.Registry.UpdateCredentials(name, req.AuthMethod, req.Credentials); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
			return
		}
		updated, err := s.cfg.Registry.Get(name)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, "failed to retrieve updated service")
			return
		}
		writeJSON(w, http.StatusOK, updated)
		return
	}

	// Legacy single credential path (or no credential — preserve existing).
	var credPtr *string
	if req.Credential != "" {
		credPtr = &req.Credential
	}

	if err := s.cfg.Registry.Update(name, svc, credPtr); err != nil {
		if strings.Contains(err.Error(), "not found") {
			WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, "service not found")
		} else {
			WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, err.Error())
		}
		return
	}

	updated, err := s.cfg.Registry.Get(name)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, "failed to retrieve updated service")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleDeleteService responds to DELETE /api/v1/services/{name}.
func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.cfg.Registry.Delete(name); err != nil {
		if strings.Contains(err.Error(), "not found") {
			WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, "service not found")
		} else {
			WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCheckCredential responds to GET /api/v1/services/{name}/check.
func (s *Server) handleCheckCredential(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	status, err := s.cfg.Registry.CheckCredential(name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, "service not found")
		} else {
			WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": status})
}

// handleRotateCredential responds to POST /api/v1/services/{name}/rotate.
// It replaces the stored credential without changing any other service configuration.
//
// Two paths are supported:
//   - Multi-field: credentials (map) provided → calls Registry.UpdateCredentials,
//     preserving the existing auth method ID.
//   - Legacy: credential (string) provided → calls Registry.RotateCredential.
func (s *Server) handleRotateCredential(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req rotateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, "invalid request body: "+err.Error())
		return
	}

	// Multi-field credentials rotation.
	if len(req.Credentials) > 0 {
		// Preserve the existing auth method ID by reading it first.
		authMethod, _, err := s.cfg.Registry.ReadCredentials(name)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, "service not found")
			} else {
				WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
			}
			return
		}
		if err := s.cfg.Registry.UpdateCredentials(name, authMethod, req.Credentials); err != nil {
			if strings.Contains(err.Error(), "not found") {
				WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, "service not found")
			} else {
				WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
			}
			return
		}
		svc, err := s.cfg.Registry.Get(name)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, "failed to retrieve service")
			return
		}
		writeJSON(w, http.StatusOK, svc)
		return
	}

	// Legacy single credential rotation.
	if req.Credential == "" {
		WriteError(w, http.StatusBadRequest, ErrCodeCredentialMissing, "credential or credentials required")
		return
	}

	if err := s.cfg.Registry.RotateCredential(name, req.Credential); err != nil {
		if strings.Contains(err.Error(), "not found") {
			WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, "service not found")
		} else {
			WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
		}
		return
	}

	svc, err := s.cfg.Registry.Get(name)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrCodeInternalError, "failed to retrieve service")
		return
	}
	writeJSON(w, http.StatusOK, svc)
}

// handleListTemplates responds to GET /api/v1/templates.
// Returns the ServiceTemplates slice filtered for personal-tier use: OAuth and
// named-strategy auth methods are excluded, and templates with no remaining
// methods are omitted entirely.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	filtered := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)
	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": filtered})
}

// handleGetTemplate responds to GET /api/v1/templates/{name}.
// Returns a single ServiceTemplate by its ID, including all auth methods.
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	tmpl := findTemplate(name)
	if tmpl == nil {
		WriteError(w, http.StatusNotFound, ErrCodeServiceNotFound, fmt.Sprintf("template %q not found", name))
		return
	}
	writeJSON(w, http.StatusOK, tmpl)
}

// ---------------------------------------------------------------------------
// Utility handlers
// ---------------------------------------------------------------------------

// handleNotImplemented responds with 501 for stub route groups.
func (s *Server) handleNotImplemented(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotImplemented, ErrCodeInternalError, "not yet implemented")
}

// handleMethodNotAllowed responds with 405 when the correct path is accessed
// with a disallowed HTTP method.
func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "GET")
	WriteError(w, http.StatusMethodNotAllowed, ErrCodeInternalError, "method not allowed")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// writeJSON sets Content-Type, writes the status code, and encodes v as JSON.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// findTemplate looks up a ServiceTemplate by its ID in the built-in catalog.
// Returns nil if no template with the given ID exists.
func findTemplate(id string) *services.ServiceTemplate {
	for i := range services.ServiceTemplates {
		if services.ServiceTemplates[i].ID == id {
			return &services.ServiceTemplates[i]
		}
	}
	return nil
}

// findAuthMethod looks up an AuthMethod by ID within a ServiceTemplate.
// Returns nil if no auth method with the given ID exists in the template.
func findAuthMethod(tmpl *services.ServiceTemplate, authMethodID string) *services.AuthMethod {
	for i := range tmpl.AuthMethods {
		if tmpl.AuthMethods[i].ID == authMethodID {
			return &tmpl.AuthMethods[i]
		}
	}
	return nil
}

// validateCredentialFields checks that all required fields defined in the
// AuthMethod are present in the credentials map, and that any provided field
// values match their defined regex pattern. Delegates to services.ValidateCredentialFields
// which uses pre-compiled patterns to avoid ReDoS and repeated compilation overhead.
func validateCredentialFields(am *services.AuthMethod, credentials map[string]string) error {
	return services.ValidateCredentialFields(am, credentials)
}

// injectionTypeToInject maps an InjectionType to the legacy "inject" string
// used by the Service struct validator. All non-query injection types map to
// "header" since the inject field predates the multi-auth model.
func injectionTypeToInject(t services.InjectionType) string {
	if t == services.InjectionQueryParam {
		return "query"
	}
	return "header"
}

// extractPrimaryCredential returns the primary credential value from a
// multi-field credentials map. It prefers the "token" key, then "value",
// then the first string value in the map.
func extractPrimaryCredential(credentials map[string]string) string {
	for _, key := range []string{"token", "value"} {
		if v, ok := credentials[key]; ok && v != "" {
			return v
		}
	}
	for _, v := range credentials {
		if v != "" {
			return v
		}
	}
	return ""
}
