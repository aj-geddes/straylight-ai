// server.go implements the minimal JSON-RPC 2.0 MCP server for straylight-mcp.
// It reads newline-delimited JSON from stdin and writes responses to stdout.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// JSON-RPC 2.0 error codes (standard).
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
)

// Protocol version advertised in the initialize response.
const mcpProtocolVersion = "2024-11-05"

// Server name and version reported in the initialize response.
const (
	serverName    = "straylight-ai"
	serverVersion = "0.1.0"
)

// JSONRPCRequest is a JSON-RPC 2.0 request message.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response message.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError is the JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPServer handles JSON-RPC 2.0 MCP messages by forwarding tool operations
// to the Straylight-AI container via the ContainerClient.
type MCPServer struct {
	client *ContainerClient
}

// NewMCPServer creates an MCPServer backed by the given ContainerClient.
func NewMCPServer(client *ContainerClient) *MCPServer {
	return &MCPServer{client: client}
}

// Serve reads newline-delimited JSON-RPC messages from r and writes responses
// to w until r reaches EOF or an unrecoverable error occurs.
// All logging goes to stderr; stdout (w) carries only MCP protocol messages.
func (s *MCPServer) Serve(r io.Reader, w io.Writer) {
	scanner := bufio.NewScanner(r)
	// Allow lines up to 4 MB (large tool responses).
	const maxLineBytes = 4 * 1024 * 1024
	buf := make([]byte, maxLineBytes)
	scanner.Buffer(buf, maxLineBytes)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		s.handleLine(line, w)
	}
}

// handleLine processes a single JSON-RPC line and writes the response to w.
// Notifications (requests without an ID) produce no output.
func (s *MCPServer) handleLine(line string, w io.Writer) {
	var req JSONRPCRequest
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		writeResponse(w, errorResponse(nil, rpcParseError, "Parse error"))
		return
	}

	// Notifications have no ID — do not send a response.
	if req.ID == nil {
		// Still dispatch so the server can update internal state if needed.
		s.dispatch(req, io.Discard)
		return
	}

	s.dispatch(req, w)
}

// dispatch routes a request to the appropriate handler and writes the response.
func (s *MCPServer) dispatch(req JSONRPCRequest, w io.Writer) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req, w)
	case "notifications/initialized":
		// Notification — no response.
	case "ping":
		writeResponse(w, successResponse(req.ID, map[string]interface{}{}))
	case "tools/list":
		s.handleToolsList(req, w)
	case "tools/call":
		s.handleToolsCall(req, w)
	default:
		if w != io.Discard {
			writeResponse(w, errorResponse(req.ID, rpcMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method)))
		}
	}
}

// handleInitialize responds to the MCP initialize handshake.
func (s *MCPServer) handleInitialize(req JSONRPCRequest, w io.Writer) {
	result := map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    serverName,
			"version": serverVersion,
		},
	}
	writeResponse(w, successResponse(req.ID, result))
}

// handleToolsList fetches the tool list from the container and returns it.
func (s *MCPServer) handleToolsList(req JSONRPCRequest, w io.Writer) {
	tools, err := s.client.GetToolList()
	if err != nil {
		writeResponse(w, errorResponse(req.ID, rpcInternalError, fmt.Sprintf("Container unavailable: %v", err)))
		return
	}

	// Convert to the MCP tools/list response format.
	toolItems := make([]interface{}, 0, len(tools))
	for _, t := range tools {
		item := map[string]interface{}{
			"name":        t.Name,
			"description": t.Description,
		}
		if len(t.InputSchema) > 0 {
			var schema interface{}
			if err := json.Unmarshal(t.InputSchema, &schema); err == nil {
				item["inputSchema"] = schema
			}
		}
		toolItems = append(toolItems, item)
	}

	writeResponse(w, successResponse(req.ID, map[string]interface{}{
		"tools": toolItems,
	}))
}

// handleToolsCall forwards a tools/call request to the container.
func (s *MCPServer) handleToolsCall(req JSONRPCRequest, w io.Writer) {
	// Parse params: { "name": "<tool>", "arguments": { ... } }
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	if len(req.Params) == 0 {
		writeResponse(w, errorResponse(req.ID, rpcInvalidParams, "tools/call requires params"))
		return
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeResponse(w, errorResponse(req.ID, rpcInvalidParams, fmt.Sprintf("Invalid params: %v", err)))
		return
	}
	if params.Name == "" {
		writeResponse(w, errorResponse(req.ID, rpcInvalidParams, "tools/call: missing required field 'name'"))
		return
	}
	if params.Arguments == nil {
		params.Arguments = map[string]interface{}{}
	}

	result, err := s.client.CallTool(params.Name, params.Arguments)
	if err != nil {
		// Container-level error: return as an MCP tool error result, not RPC error.
		// This matches the MCP spec: tool errors are result.isError=true.
		errResult := map[string]interface{}{
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": fmt.Sprintf("Error: container unavailable: %v", err),
				},
			},
			"isError": true,
		}
		writeResponse(w, successResponse(req.ID, errResult))
		return
	}

	// Convert ToolCallResult to MCP response format.
	contentItems := make([]interface{}, 0, len(result.Content))
	for _, item := range result.Content {
		contentItems = append(contentItems, map[string]interface{}{
			"type": item.Type,
			"text": item.Text,
		})
	}

	mcpResult := map[string]interface{}{
		"content": contentItems,
	}
	if result.IsError {
		mcpResult["isError"] = true
	}

	writeResponse(w, successResponse(req.ID, mcpResult))
}

// ---------------------------------------------------------------------------
// Response constructors
// ---------------------------------------------------------------------------

func successResponse(id interface{}, result interface{}) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func errorResponse(id interface{}, code int, message string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	}
}

// writeResponse serializes resp as JSON followed by a newline to w.
// Write errors are silently ignored: the MCP host cannot recover from
// a broken pipe to the AI agent.
func writeResponse(w io.Writer, resp JSONRPCResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = w.Write(data)
}
