// Package main provides the straylight-mcp MCP host binary.
// client.go contains the HTTP client for communicating with the Straylight-AI container.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/straylight-ai/straylight/internal/services"
)

const defaultContainerURL = "http://localhost:9470"

// ToolDefinition represents a single MCP tool's metadata as returned by the container.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ContentItem is a single content block in an MCP tool call result.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolCallResult is the response from a container tool call.
type ToolCallResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ContainerClient communicates with the Straylight-AI container HTTP API.
type ContainerClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewContainerClient creates a ContainerClient targeting the given base URL.
func NewContainerClient(baseURL string) *ContainerClient {
	return &ContainerClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Health checks that the container is reachable and healthy.
// Returns nil if the container responds with HTTP 200, error otherwise.
func (c *ContainerClient) Health() error {
	resp, err := c.httpClient.Get(c.baseURL + "/api/v1/health")
	if err != nil {
		return fmt.Errorf("container health check: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("container health check: status %d", resp.StatusCode)
	}
	return nil
}

// GetToolList fetches the list of available MCP tools from the container.
func (c *ContainerClient) GetToolList() ([]ToolDefinition, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/api/v1/mcp/tool-list")
	if err != nil {
		return nil, fmt.Errorf("get tool list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get tool list: status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Tools []ToolDefinition `json:"tools"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("get tool list: decode: %w", err)
	}
	return result.Tools, nil
}

// CallTool forwards a tool call to the container and returns the result.
func (c *ContainerClient) CallTool(name string, arguments map[string]interface{}) (*ToolCallResult, error) {
	payload := map[string]interface{}{
		"tool":      name,
		"arguments": arguments,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("call tool: marshal: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/v1/mcp/tool-call",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("call tool %q: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("call tool %q: status %d: %s", name, resp.StatusCode, string(respBody))
	}

	var result ToolCallResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("call tool %q: decode: %w", name, err)
	}
	return &result, nil
}

// ---------------------------------------------------------------------------
// ContainerServiceLister — bridges ContainerClient to hooks.ServiceLister
// ---------------------------------------------------------------------------

// ContainerServiceLister fetches services from the container API to satisfy
// the hooks.ServiceLister interface needed by the PreToolUse hook.
type ContainerServiceLister struct {
	client *ContainerClient
}

// NewContainerServiceLister creates a lister backed by the given client.
func NewContainerServiceLister(client *ContainerClient) *ContainerServiceLister {
	return &ContainerServiceLister{client: client}
}

// List fetches services from GET /api/v1/services and returns them.
// On error, returns an empty slice (the hook degrades gracefully).
func (l *ContainerServiceLister) List() []services.Service {
	resp, err := l.client.httpClient.Get(l.client.baseURL + "/api/v1/services")
	if err != nil {
		return []services.Service{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return []services.Service{}
	}

	var result struct {
		Services []services.Service `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []services.Service{}
	}
	if result.Services == nil {
		return []services.Service{}
	}
	return result.Services
}

// parseContainerURL returns a trimmed container URL, falling back to the
// default if the provided value is empty.
func parseContainerURL(url string) string {
	if url == "" {
		return defaultContainerURL
	}
	return strings.TrimRight(url, "/")
}
