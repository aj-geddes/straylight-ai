// Package mcp provides the HTTP handler and tool implementations for the
// Model Context Protocol (MCP) tool forwarding API at /api/v1/mcp/*.
package mcp

import (
	"encoding/json"
	"net/http"
)

// Handler is the HTTP handler for the MCP tool forwarding endpoints.
type Handler struct {
	proxy    ProxyHandler
	services ServiceLister
}

// NewHandler creates a new Handler with the given proxy and service dependencies.
func NewHandler(proxy ProxyHandler, services ServiceLister) *Handler {
	return &Handler{
		proxy:    proxy,
		services: services,
	}
}

// ServeHTTP implements http.Handler for use in tests and integration.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/mcp/tool-list":
		h.HandleToolList(w, r)
	case "/api/v1/mcp/tool-call":
		h.HandleToolCall(w, r)
	default:
		http.NotFound(w, r)
	}
}

// HandleToolList processes GET /api/v1/mcp/tool-list.
// Returns all four tool definitions with their input schemas.
func (h *Handler) HandleToolList(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"tools": toolDefinitions,
	}
	writeJSON(w, http.StatusOK, resp)
}

// HandleToolCall processes POST /api/v1/mcp/tool-call.
// Request body: {"tool": "<name>", "arguments": {...}}
// Response body: MCP CallToolResult format with isError for logical errors.
// Returns HTTP 400 only for malformed requests (bad JSON, unknown tool).
func (h *Handler) HandleToolCall(w http.ResponseWriter, r *http.Request) {
	var req ToolCallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.Tool == "" {
		writeError(w, http.StatusBadRequest, "missing required field: tool")
		return
	}

	// Validate that the tool name is known before dispatching.
	if !isKnownTool(req.Tool) {
		writeError(w, http.StatusBadRequest, "unknown tool: "+req.Tool)
		return
	}

	result := dispatchToolCall(r.Context(), req, h.proxy, h.services)
	writeJSON(w, http.StatusOK, result)
}

// isKnownTool returns true if name is one of the four registered tool names.
func isKnownTool(name string) bool {
	for _, def := range toolDefinitions {
		if def.Name == name {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// writeJSON sets Content-Type, writes the status code, and encodes v as JSON.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a plain JSON error response (not MCP format — only used for
// HTTP-level errors before a ToolCallResult can be constructed).
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
