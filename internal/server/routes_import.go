package server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/openapi"
)

// importSpecRequest is the JSON body for POST /api/v1/templates/import when a
// URL is provided instead of a raw spec body.
type importSpecRequest struct {
	URL string `json:"url"`
}

// handleImportTemplate responds to POST /api/v1/templates/import.
//
// Two modes are supported:
//   - URL mode: body is {"url": "https://..."} — fetches the spec via FetchSpec
//     (SSRF-gated through the egress Guard) then parses it.
//   - Body mode: body is the raw OpenAPI spec (JSON). Parsed directly without fetching.
//
// Returns a draft ServiceTemplate JSON plus any import warnings.
// The endpoint never requires a registry and is always registered.
func (s *Server) handleImportTemplate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, "failed to read request body: "+err.Error())
		return
	}
	if len(body) == 0 {
		WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, "request body is required")
		return
	}

	guard := s.cfg.EgressGuard
	if guard == nil {
		guard = egress.New()
	}

	// Detect URL mode: try to decode as {"url": "..."}.
	var urlReq importSpecRequest
	if err := json.Unmarshal(body, &urlReq); err == nil && urlReq.URL != "" {
		specBytes, fetchErr := openapi.FetchSpec(r.Context(), guard, urlReq.URL)
		if fetchErr != nil {
			WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, "failed to fetch spec: "+fetchErr.Error())
			return
		}
		result, importErr := openapi.FromSpec(specBytes, urlReq.URL)
		if importErr != nil {
			WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, "failed to parse spec: "+importErr.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"template": result.Template,
			"warnings": result.Warnings,
			"source":   result.Source,
		})
		return
	}

	// Body mode: treat the body as the raw spec.
	result, importErr := openapi.FromSpec(body, "body")
	if importErr != nil {
		WriteError(w, http.StatusBadRequest, ErrCodeValidationFailed, "failed to parse spec: "+importErr.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"template": result.Template,
		"warnings": result.Warnings,
		"source":   result.Source,
	})
}
