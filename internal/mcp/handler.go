// Package mcp provides the HTTP handler and tool implementations for the
// Model Context Protocol (MCP) tool forwarding API at /api/v1/mcp/*.
package mcp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/database"
	"github.com/straylight-ai/straylight/internal/scanner"
)

// DirectoryScanner abstracts the scanner dependency for the MCP handler.
// The canonical implementation is *scanner.Scanner.
type DirectoryScanner interface {
	ScanDirectory(root string) (*scanner.ScanResult, error)
}

// DBExecutor abstracts the database Manager for the MCP handler.
// The canonical implementation is *database.Manager.
type DBExecutor interface {
	GetCredentials(serviceName, role string) (username, password, leaseID string, err error)
	GetDatabaseConfig(name string) (database.DatabaseConfig, bool)
	ListDatabases() []string
}

// CommandExecutor abstracts the command wrapper dependency for the MCP handler.
// The canonical implementation is *cmdwrap.Wrapper.
// When nil, handleExec returns the stub message for backward compatibility.
type CommandExecutor interface {
	Execute(ctx context.Context, req cmdwrap.ExecRequest) (*cmdwrap.ExecResponse, error)
}

// Handler is the HTTP handler for the MCP tool forwarding endpoints.
type Handler struct {
	proxy       ProxyHandler
	services    ServiceLister
	auditLog    audit.Emitter
	scanner     DirectoryScanner // may be nil; handleScan falls back gracefully
	fileReader  FileReader       // may be nil; handleReadFile creates a default Firewall
	dbExecutor  DBExecutor       // may be nil; straylight_db_query returns error when nil
	cmdExecutor CommandExecutor  // may be nil; handleExec returns stub when nil
}

// NewHandler creates a new Handler with the given proxy and service dependencies.
func NewHandler(proxy ProxyHandler, services ServiceLister) *Handler {
	return &Handler{
		proxy:    proxy,
		services: services,
	}
}

// SetAudit registers an audit emitter on the handler.
func (h *Handler) SetAudit(a audit.Emitter) {
	h.auditLog = a
}

// SetScanner registers a DirectoryScanner on the handler.
func (h *Handler) SetScanner(s DirectoryScanner) {
	h.scanner = s
}

// SetFileReader registers a FileReader (Firewall) on the handler.
func (h *Handler) SetFileReader(fr FileReader) {
	h.fileReader = fr
}

// SetDBExecutor registers a DBExecutor on the handler.
func (h *Handler) SetDBExecutor(db DBExecutor) {
	h.dbExecutor = db
}

// SetCommandExecutor registers a CommandExecutor on the handler, enabling the
// real straylight_exec implementation. When not set (nil), handleExec returns
// the stub message for backward compatibility.
func (h *Handler) SetCommandExecutor(exec CommandExecutor) {
	h.cmdExecutor = exec
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
func (h *Handler) HandleToolList(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"tools": toolDefinitions,
	}
	writeJSON(w, http.StatusOK, resp)
}

// HandleToolCall processes POST /api/v1/mcp/tool-call.
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

	if !isKnownTool(req.Tool) {
		writeError(w, http.StatusBadRequest, "unknown tool: "+req.Tool)
		return
	}

	result := dispatchToolCall(r.Context(), req, h.proxy, h.services, h.scanner, h.fileReader, h.dbExecutor, h.cmdExecutor, h.auditLog)
	writeJSON(w, http.StatusOK, result)
}

// isKnownTool returns true if name is one of the registered tool names.
func isKnownTool(name string) bool {
	for _, def := range toolDefinitions {
		if def.Name == name {
			return true
		}
	}
	return false
}

// writeJSON sets Content-Type, writes the status code, and encodes v as JSON.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a plain JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
