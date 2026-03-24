// Package mcp provides the HTTP handler and tool implementations for the
// Model Context Protocol (MCP) tool forwarding API at /api/v1/mcp/*.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// execStubMessage is returned for straylight_exec until the feature is implemented.
const execStubMessage = "straylight_exec is not available yet. It will be enabled in a future update."

// ProxyHandler abstracts the proxy dependency for the MCP handler.
type ProxyHandler interface {
	HandleAPICall(ctx context.Context, req proxy.APICallRequest) (*proxy.APICallResponse, error)
}

// ServiceLister abstracts the service registry dependency for the MCP handler.
type ServiceLister interface {
	List() []services.Service
	CheckCredential(name string) (string, error)
}

// ToolDefinition holds the name, description, and input schema for an MCP tool
// as returned by the tool-list endpoint.
type ToolDefinition struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// ToolCallRequest is the JSON body for POST /api/v1/mcp/tool-call.
type ToolCallRequest struct {
	Tool      string                 `json:"tool"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolCallResult is the MCP CallToolResult response format.
type ToolCallResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ContentItem is a single content item in a ToolCallResult. All items produced
// by this handler use type "text".
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolDefinitions holds the static tool registry matching contracts/mcp-tools.json.
var toolDefinitions = []ToolDefinition{
	{
		Name:        "straylight_api_call",
		Description: "Make an authenticated HTTP request to an external service through Straylight-AI. The credential is injected by the proxy — you never see or handle the secret. Use this for any API call that requires authentication.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service": map[string]interface{}{
					"type":        "string",
					"description": "The name of the configured service (e.g., 'stripe', 'github', 'openai'). Must match a service registered in Straylight-AI.",
				},
				"method": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"},
					"description": "HTTP method for the request.",
					"default":     "GET",
				},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "The API path (appended to the service's base URL). Must start with '/'.",
					"pattern":     "^/",
				},
				"headers": map[string]interface{}{
					"type":        "object",
					"description": "Additional HTTP headers to include in the request. Authorization headers are injected automatically — do NOT include them here.",
					"additionalProperties": map[string]interface{}{
						"type": "string",
					},
					"default": map[string]interface{}{},
				},
				"query": map[string]interface{}{
					"type":        "object",
					"description": "Query string parameters as key-value pairs.",
					"additionalProperties": map[string]interface{}{
						"type": "string",
					},
					"default": map[string]interface{}{},
				},
				"body": map[string]interface{}{
					"description": "Request body. For JSON APIs, provide an object. For form data, provide a URL-encoded string.",
					"oneOf": []interface{}{
						map[string]interface{}{"type": "object"},
						map[string]interface{}{"type": "string"},
						map[string]interface{}{"type": "null"},
					},
					"default": nil,
				},
			},
			"required":             []string{"service", "path"},
			"additionalProperties": false,
		},
	},
	{
		Name:        "straylight_exec",
		Description: "Execute a command with credentials injected as environment variables. The command runs inside the Straylight-AI container with the appropriate secrets set in the environment. Output (stdout/stderr) is sanitized to remove any credential values before being returned to you.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service": map[string]interface{}{
					"type":        "string",
					"description": "The name of the configured service whose credentials should be injected into the command's environment.",
				},
				"command": map[string]interface{}{
					"type":        "string",
					"description": "The command to execute. Credentials are injected via environment variables — do NOT include secrets in the command string.",
				},
				"timeout_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum execution time in seconds. Command is killed after this timeout.",
					"default":     30,
					"minimum":     1,
					"maximum":     300,
				},
			},
			"required":             []string{"service", "command"},
			"additionalProperties": false,
		},
	},
	{
		Name:        "straylight_check",
		Description: "Check whether a credential is available and valid for a given service. Use this before making API calls to verify the service is configured and the credential has not expired.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service": map[string]interface{}{
					"type":        "string",
					"description": "The name of the service to check.",
				},
			},
			"required":             []string{"service"},
			"additionalProperties": false,
		},
	},
	{
		Name:        "straylight_services",
		Description: "List all services configured in Straylight-AI and their capabilities. Use this to discover what services are available before making API calls or running commands.",
		InputSchema: map[string]interface{}{
			"type":                 "object",
			"properties":          map[string]interface{}{},
			"additionalProperties": false,
		},
	},
}

// serviceView is a credential-free view of a service suitable for tool responses.
type serviceView struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
	BaseURL      string   `json:"base_url,omitempty"`
	// Scopes is a pointer so that omitempty suppresses the field entirely for
	// non-oauth services (nil) while still serialising an empty JSON array for
	// oauth services that have no scopes configured yet (non-nil, empty slice).
	Scopes      *[]string `json:"scopes,omitempty"`
	Description string    `json:"description,omitempty"`
}

// servicesResponse is the top-level payload returned by straylight_services.
type servicesResponse struct {
	Services []serviceView `json:"services"`
	Total    int           `json:"total"`
	Message  string        `json:"message"`
}

// knownDescriptions maps well-known target URL hostnames to human-friendly descriptions.
var knownDescriptions = map[string]string{
	"api.stripe.com":      "Stripe payment API",
	"api.github.com":      "GitHub API",
	"api.openai.com":      "OpenAI completions API",
	"api.anthropic.com":   "Anthropic Claude API",
	"slack.com":           "Slack messaging API",
	"api.slack.com":       "Slack messaging API",
	"api.linear.app":      "Linear project management API",
	"api.notion.com":      "Notion workspace API",
	"api.sendgrid.com":    "SendGrid email API",
	"api.twilio.com":      "Twilio communications API",
	"api.hubspot.com":     "HubSpot CRM API",
	"api.airtable.com":    "Airtable database API",
	"api.shopify.com":     "Shopify commerce API",
	"api.atlassian.com":   "Atlassian API",
	"api.zendesk.com":     "Zendesk support API",
	"api.intercom.io":     "Intercom messaging API",
	"api.pagerduty.com":   "PagerDuty alerting API",
	"api.datadog.com":     "Datadog monitoring API",
}

// serviceDescription returns a human-friendly description for the given service.
// It checks knownDescriptions first; for unknown services it falls back to the hostname.
func serviceDescription(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return target
	}
	if desc, ok := knownDescriptions[u.Host]; ok {
		return desc
	}
	return u.Host
}

// serviceCapabilities returns the capability list for a service.
// All services get "api_call". Services with ExecEnabled also get "exec".
func serviceCapabilities(svc services.Service) []string {
	caps := []string{"api_call"}
	if svc.ExecEnabled {
		caps = append(caps, "exec")
	}
	return caps
}

// dispatchToolCall routes a validated ToolCallRequest to the appropriate handler
// and returns a ToolCallResult. All errors are encoded as isError results rather
// than returned as Go errors, so the HTTP response is always 200 OK.
func dispatchToolCall(ctx context.Context, req ToolCallRequest, p ProxyHandler, s ServiceLister) ToolCallResult {
	switch req.Tool {
	case "straylight_api_call":
		return handleAPICall(ctx, req.Arguments, p)
	case "straylight_check":
		return handleCheck(req.Arguments, s)
	case "straylight_services":
		return handleServices(s)
	case "straylight_exec":
		return handleExec()
	default:
		return errorResult(fmt.Sprintf("Error: unknown tool %q", req.Tool))
	}
}

// handleAPICall implements the straylight_api_call tool.
func handleAPICall(ctx context.Context, args map[string]interface{}, p ProxyHandler) ToolCallResult {
	service, ok := stringArg(args, "service")
	if !ok || service == "" {
		return errorResult("Error: missing required argument 'service'")
	}

	path, ok := stringArg(args, "path")
	if !ok || path == "" {
		return errorResult("Error: missing required argument 'path'")
	}

	method, _ := stringArg(args, "method")
	if method == "" {
		method = "GET"
	}

	headers := stringMapArg(args, "headers")
	query := stringMapArg(args, "query")
	body := args["body"]

	apiReq := proxy.APICallRequest{
		Service: service,
		Method:  method,
		Path:    path,
		Headers: headers,
		Query:   query,
		Body:    body,
	}

	resp, err := p.HandleAPICall(ctx, apiReq)
	if err != nil {
		return errorResult("Error: " + err.Error())
	}

	if resp.StatusCode >= 400 {
		return ToolCallResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Error: upstream returned HTTP %d. Response: %s", resp.StatusCode, resp.Body)}},
			IsError: true,
		}
	}

	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: resp.Body}},
	}
}

// handleCheck implements the straylight_check tool.
func handleCheck(args map[string]interface{}, s ServiceLister) ToolCallResult {
	service, ok := stringArg(args, "service")
	if !ok || service == "" {
		return errorResult("Error: missing required argument 'service'")
	}

	status, err := s.CheckCredential(service)
	if err != nil {
		return errorResult(fmt.Sprintf("Error: service %q not found", service))
	}

	result := map[string]interface{}{
		"service": service,
		"status":  status,
	}
	text, _ := json.Marshal(result)
	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: string(text)}},
	}
}

// handleServices implements the straylight_services tool.
// Credential values are never included in the response.
func handleServices(s ServiceLister) ToolCallResult {
	svcs := s.List()

	views := make([]serviceView, 0, len(svcs))
	for _, svc := range svcs {
		view := serviceView{
			Name:         svc.Name,
			Type:         svc.Type,
			Status:       svc.Status,
			Capabilities: serviceCapabilities(svc),
			BaseURL:      svc.Target,
			Description:  serviceDescription(svc.Target),
		}
		if svc.Type == "oauth" {
			// Emit an explicit (possibly empty) scopes slice for oauth services
			// so agents can detect the field. Scopes will be populated by WP-2.3.
			empty := []string{}
			view.Scopes = &empty
		}
		views = append(views, view)
	}

	var message string
	if len(views) == 0 {
		message = "No services configured. Add services at http://localhost:9470 to get started."
	} else {
		message = fmt.Sprintf(
			"%d services configured. Use straylight_api_call to make authenticated requests or straylight_exec to run commands with secrets injected as environment variables.",
			len(views),
		)
	}

	payload := servicesResponse{
		Services: views,
		Total:    len(views),
		Message:  message,
	}

	text, _ := json.Marshal(payload)
	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: string(text)}},
	}
}

// handleExec returns the stub response for straylight_exec.
func handleExec() ToolCallResult {
	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: execStubMessage}},
	}
}

// ---------------------------------------------------------------------------
// Argument extraction helpers
// ---------------------------------------------------------------------------

// stringArg extracts a string value from the arguments map.
// Returns ("", false) if the key is absent or the value is not a string.
func stringArg(args map[string]interface{}, key string) (string, bool) {
	v, ok := args[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// stringMapArg extracts a map[string]string from the arguments map.
// Returns nil if the key is absent or the value cannot be converted.
func stringMapArg(args map[string]interface{}, key string) map[string]string {
	v, ok := args[key]
	if !ok {
		return nil
	}
	raw, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	result := make(map[string]string, len(raw))
	for k, val := range raw {
		if s, ok := val.(string); ok {
			result[k] = s
		}
	}
	return result
}

// errorResult constructs a ToolCallResult representing an error.
func errorResult(msg string) ToolCallResult {
	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: msg}},
		IsError: true,
	}
}
