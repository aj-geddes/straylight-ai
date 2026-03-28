// Package mcp provides the HTTP handler and tool implementations for the
// Model Context Protocol (MCP) tool forwarding API at /api/v1/mcp/*.
package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/straylight-ai/straylight/internal/audit"
	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/database"
	"github.com/straylight-ai/straylight/internal/firewall"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/scanner"
	"github.com/straylight-ai/straylight/internal/services"

	// PostgreSQL driver — side-effect import registers "postgres" driver.
	_ "github.com/lib/pq"
	// MySQL driver — side-effect import registers "mysql" driver.
	_ "github.com/go-sql-driver/mysql"
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
	{
		Name:        "straylight_scan",
		Description: "Scan a project directory for secrets and sensitive files before reading them. Reports findings with file path, line number, pattern type, and severity. Use this at the start of a session to understand which files contain secrets. Can generate ignore rules for AI tools (.claudeignore, .cursorignore format).",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Directory to scan. Defaults to the current working directory '.'.",
					"default":     ".",
				},
				"generate_ignore": map[string]interface{}{
					"type":        "boolean",
					"description": "If true, include recommended ignore rules for AI tools (.claudeignore, .cursorignore format) in the response.",
					"default":     false,
				},
				"severity_filter": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"high", "medium", "low", "all"},
					"description": "Only return findings at or above this severity level.",
					"default":     "all",
				},
			},
			"additionalProperties": false,
		},
	},
	{
		Name:        "straylight_read_file",
		Description: "Read a file with secrets automatically redacted. Use this instead of reading files directly when the file may contain credentials, API keys, connection strings, or other secrets. Returns the file content with sensitive values replaced by [STRAYLIGHT:pattern] placeholders. The file structure and non-secret content are preserved. Blocked files (e.g. .env, *.pem, id_rsa) return a helpful error message.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the file to read (relative to project root or absolute).",
				},
				"encoding": map[string]interface{}{
					"type":        "string",
					"description": "File encoding. Default: utf-8.",
					"default":     "utf-8",
				},
			},
			"required":             []string{"path"},
			"additionalProperties": false,
		},
	},
	{
		Name:        "straylight_db_query",
		Description: "Execute a database query through Straylight-AI. Straylight provisions temporary database credentials, connects to the database, runs the query, and returns sanitized results. You never see the database password or connection string. Supports PostgreSQL and MySQL.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service": map[string]interface{}{
					"type":        "string",
					"description": "The name of the configured database service.",
				},
				"query": map[string]interface{}{
					"type":        "string",
					"description": "The SQL query to execute. Prefer read-only queries. Use $1, $2 (PostgreSQL) or ? (MySQL) for bind parameters.",
				},
				"params": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
					"description": "Optional bind parameters for parameterized queries.",
					"default":     []interface{}{},
				},
				"max_rows": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of rows to return. Default: 100. Max: 10000.",
					"default":     100,
					"minimum":     1,
					"maximum":     10000,
				},
			},
			"required":             []string{"service", "query"},
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

// FileReader provides the straylight_read_file capability: reading a file with
// secrets automatically redacted. The canonical implementation is *firewall.Firewall.
type FileReader interface {
	ReadFileRedacted(path string) (*firewall.ReadResult, error)
}

// dispatchToolCall routes a validated ToolCallRequest to the appropriate handler
// and returns a ToolCallResult. All errors are encoded as isError results rather
// than returned as Go errors, so the HTTP response is always 200 OK.
//
// When a non-nil AuditEmitter is provided, a tool_call event is emitted after
// each tool invocation with the tool name, service name (when applicable),
// and outcome ("success" or "error"). Credential values are never included.
func dispatchToolCall(ctx context.Context, req ToolCallRequest, p ProxyHandler, s ServiceLister, sc DirectoryScanner, fr FileReader, db DBExecutor, exec CommandExecutor, a audit.Emitter) ToolCallResult {
	var result ToolCallResult
	switch req.Tool {
	case "straylight_api_call":
		result = handleAPICall(ctx, req.Arguments, p)
	case "straylight_check":
		result = handleCheck(req.Arguments, s)
	case "straylight_services":
		result = handleServices(s)
	case "straylight_exec":
		result = handleExec(ctx, req.Arguments, exec)
	case "straylight_scan":
		result = handleScan(req.Arguments, sc)
	case "straylight_read_file":
		result = handleReadFile(req.Arguments, fr)
	case "straylight_db_query":
		result = handleDBQuery(ctx, req.Arguments, db)
	default:
		return errorResult(fmt.Sprintf("Error: unknown tool %q", req.Tool))
	}

	if a != nil {
		emitToolCallAuditEvent(a, req, result)
	}
	return result
}

// emitToolCallAuditEvent emits a tool_call audit event after a tool invocation.
// It extracts the service name from the arguments (when present) and records
// the outcome as "success" or "error". Credential values are never included.
func emitToolCallAuditEvent(a audit.Emitter, req ToolCallRequest, result ToolCallResult) {
	outcome := "success"
	if result.IsError {
		outcome = "error"
	}

	details := map[string]string{"outcome": outcome}

	// Extract path for api_call events (no credential values ever included).
	if path, ok := stringArg(req.Arguments, "path"); ok {
		details["path"] = path
	}

	service, _ := stringArg(req.Arguments, "service")

	a.Emit(audit.Event{
		Type:    audit.EventToolCall,
		Tool:    req.Tool,
		Service: service,
		Details: details,
	})
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

// handleExec implements the straylight_exec tool.
// When exec is nil (no CommandExecutor configured), it returns the backward-compatible
// stub message. Otherwise it dispatches to the real command wrapper.
func handleExec(ctx context.Context, args map[string]interface{}, exec CommandExecutor) ToolCallResult {
	if exec == nil {
		return ToolCallResult{
			Content: []ContentItem{{Type: "text", Text: execStubMessage}},
		}
	}

	service, ok := stringArg(args, "service")
	if !ok || service == "" {
		return errorResult("Error: missing required argument 'service'")
	}

	command, ok := stringArg(args, "command")
	if !ok || command == "" {
		return errorResult("Error: missing required argument 'command'")
	}

	// JSON schema constraints (minimum: 1, maximum: 300) are advisory only.
	// Enforce bounds server-side regardless of what the AI sends.
	const minTimeoutSeconds = 1
	const maxTimeoutSeconds = 300

	timeoutSeconds := 30
	if t, ok := args["timeout_seconds"]; ok {
		switch v := t.(type) {
		case float64:
			timeoutSeconds = int(v)
		case int:
			timeoutSeconds = v
		}
	}
	if timeoutSeconds < minTimeoutSeconds {
		timeoutSeconds = minTimeoutSeconds
	}
	if timeoutSeconds > maxTimeoutSeconds {
		timeoutSeconds = maxTimeoutSeconds
	}

	req := cmdwrap.ExecRequest{
		Service:        service,
		Command:        command,
		TimeoutSeconds: timeoutSeconds,
	}

	resp, err := exec.Execute(ctx, req)
	if err != nil {
		return errorResult("Error: " + err.Error())
	}

	// Build output combining stdout and stderr.
	output := resp.Stdout
	if resp.Stderr != "" {
		if output != "" {
			output += "\n[stderr]\n" + resp.Stderr
		} else {
			output = "[stderr]\n" + resp.Stderr
		}
	}

	if resp.ExitCode != 0 {
		exitMsg := fmt.Sprintf("[exit code %d]", resp.ExitCode)
		if resp.ExitCode == -1 {
			exitMsg = "[timed out]"
		}
		if output == "" {
			output = exitMsg
		} else {
			output = output + "\n" + exitMsg
		}
		return ToolCallResult{
			Content: []ContentItem{{Type: "text", Text: output}},
			IsError: true,
		}
	}

	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: output}},
	}
}

// scanResponse is the JSON payload returned by straylight_scan.
type scanResponse struct {
	Findings     []scanner.Finding `json:"findings"`
	FilesScanned int               `json:"files_scanned"`
	FilesSkipped int               `json:"files_skipped"`
	DurationMS   int64             `json:"duration_ms"`
	Summary      scanner.Summary   `json:"summary"`
	IgnoreRules  string            `json:"ignore_rules,omitempty"`
}

// handleScan implements the straylight_scan tool.
// It scans the given directory (defaulting to ".") using the injected
// DirectoryScanner, then serialises the ScanResult as JSON.
// If generate_ignore is true, it appends recommended ignore file content.
// When no scanner is injected, a default scanner.Scanner is created inline.
//
// Security: absolute paths are rejected outright. Relative paths are cleaned
// and validated to ensure they do not escape the working directory via
// path traversal ("../..").
func handleScan(args map[string]interface{}, sc DirectoryScanner) ToolCallResult {
	if sc == nil {
		sc = scanner.New()
	}

	// Path defaults to "." when omitted.
	path, _ := stringArg(args, "path")
	if path == "" {
		path = "."
	}

	// Reject absolute paths — the AI must not be able to scan /etc, /data, etc.
	if filepath.IsAbs(path) {
		return errorResult("Error: absolute paths are not allowed for straylight_scan; use a relative path (e.g., '.' or 'src')")
	}

	// Clean the path and reject any that escape the working directory.
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, "..") {
		return errorResult("Error: path traversal is not allowed for straylight_scan; the path must not escape the working directory")
	}

	result, err := sc.ScanDirectory(clean)
	if err != nil {
		return errorResult("Error: " + err.Error())
	}

	// Apply severity filter when present.
	severityFilter, _ := stringArg(args, "severity_filter")
	findings := filterBySeverity(result.Findings, severityFilter)

	resp := scanResponse{
		Findings:     findings,
		FilesScanned: result.FilesScanned,
		FilesSkipped: result.FilesSkipped,
		DurationMS:   result.DurationMS,
		Summary:      scanner.BuildSummary(findings),
	}

	// Optionally generate ignore rules.
	if generateIgnore, _ := args["generate_ignore"].(bool); generateIgnore {
		resp.IgnoreRules = scanner.GenerateIgnoreRules(findings, ".claudeignore")
	}

	text, _ := json.Marshal(resp)
	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: string(text)}},
	}
}

// handleReadFile implements the straylight_read_file tool.
// It reads the file at the given path through the Firewall, which redacts
// secrets and blocks access to entirely sensitive files.
// When the FileReader is nil (Firewall not configured), it returns an error
// rather than silently creating a Firewall with no project root restriction.
func handleReadFile(args map[string]interface{}, fr FileReader) ToolCallResult {
	path, ok := stringArg(args, "path")
	if !ok || path == "" {
		return errorResult("Error: missing required argument 'path'")
	}

	if fr == nil {
		// Firewall not configured — refuse rather than create a rootless Firewall
		// that would allow reading any file on the filesystem.
		return errorResult("Error: file reader not configured; set a project root in the Straylight dashboard to enable straylight_read_file")
	}

	result, err := fr.ReadFileRedacted(path)
	if err != nil {
		return ToolCallResult{
			Content: []ContentItem{{Type: "text", Text: "Error: " + err.Error()}},
			IsError: true,
		}
	}

	// Build a structured JSON response so callers can extract redaction metadata.
	resp := map[string]interface{}{
		"content":          result.Content,
		"redactions":       result.Redactions,
		"redacted_patterns": result.RedactedPatterns,
		"file_size":        result.FileSize,
	}
	if result.Warning != "" {
		resp["warning"] = result.Warning
	}

	text, _ := json.Marshal(resp)
	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: string(text)}},
	}
}

// dbQueryResponse is the JSON payload returned by straylight_db_query.
//
// LeaseID and LeaseTTLSeconds are intentionally excluded: they are vault
// infrastructure identifiers (revealing mount names and role names) with no
// legitimate use for AI callers. They are retained on database.QueryResult
// for internal audit logging only.
type dbQueryResponse struct {
	Columns    []string        `json:"columns"`
	Rows       [][]interface{} `json:"rows"`
	RowCount   int             `json:"row_count"`
	DurationMS int64           `json:"duration_ms"`
	Engine     string          `json:"engine"`
}

// defaultMaxRows is the default row limit for straylight_db_query.
const defaultMaxRows = 100

// absoluteMaxRows is the hard upper bound for straylight_db_query row results.
const absoluteMaxRows = 10000

// handleDBQuery implements the straylight_db_query tool.
// It retrieves temporary credentials from the DBExecutor, connects to the
// database using the appropriate driver, executes the query, sanitizes the
// results, and returns them as JSON.
//
// The AI never sees the database password, connection string, or lease credentials.
// Only the query result columns and rows are returned, sanitized.
func handleDBQuery(ctx context.Context, args map[string]interface{}, db DBExecutor) ToolCallResult {
	if db == nil {
		return errorResult("Error: database query is not configured. Add a database service at the Straylight dashboard first.")
	}

	serviceName, ok := stringArg(args, "service")
	if !ok || serviceName == "" {
		return errorResult("Error: missing required argument 'service'")
	}

	query, ok := stringArg(args, "query")
	if !ok || query == "" {
		return errorResult("Error: missing required argument 'query'")
	}

	// Parse optional params.
	params := extractQueryParams(args)

	// Parse max_rows with bounds checking.
	maxRows := defaultMaxRows
	if mr, ok := args["max_rows"].(float64); ok {
		maxRows = int(mr)
		if maxRows < 1 {
			maxRows = 1
		}
		if maxRows > absoluteMaxRows {
			maxRows = absoluteMaxRows
		}
	}

	// Look up the database config to get the engine type.
	cfg, ok := db.GetDatabaseConfig(serviceName)
	if !ok {
		return errorResult(fmt.Sprintf("Error: database service %q not found. Configure it via the Straylight dashboard.", serviceName))
	}

	// Get temporary credentials from vault (or lease cache).
	username, password, leaseID, err := db.GetCredentials(serviceName, "readonly")
	if err != nil {
		// Never include connection details in error message.
		return errorResult(fmt.Sprintf("Error: could not obtain credentials for service %q: %s", serviceName, err.Error()))
	}

	// Build driver name and DSN.
	driverName, dsn := buildDriverDSN(cfg, username, password)
	if driverName == "" {
		return errorResult(fmt.Sprintf("Error: unsupported database engine %q", cfg.Engine))
	}

	// Open connection and execute query.
	start := time.Now()
	result, queryErr := executeQuery(ctx, driverName, dsn, query, params, maxRows)
	if queryErr != nil {
		// Sanitize error: remove DSN/connection string details.
		safeErr := sanitizeDBError(queryErr)
		return errorResult(fmt.Sprintf("Error: query failed: %s", safeErr))
	}
	result.Duration = time.Since(start)
	result.LeaseID = leaseID
	result.Engine = cfg.Engine

	// Sanitize results — remove any cells containing temporary credential values.
	sensitiveValues := []string{username, password}
	result.Rows = database.SanitizeRows(result.Rows, sensitiveValues)

	// Emit audit event for this query execution.
	_ = ctx // audit integration added when audit.Emitter is available at call site

	// LeaseID and LeaseTTLSeconds are retained on result for internal audit
	// logging but are NOT included in the response to the AI caller.
	resp := dbQueryResponse{
		Columns:    result.Columns,
		Rows:       result.Rows,
		RowCount:   result.RowCount,
		DurationMS: result.Duration.Milliseconds(),
		Engine:     result.Engine,
	}

	text, _ := json.Marshal(resp)
	return ToolCallResult{
		Content: []ContentItem{{Type: "text", Text: string(text)}},
	}
}

// buildDriverDSN returns the Go sql driver name and DSN for the given config
// and temporary credentials. Returns ("", "") for unsupported engines.
func buildDriverDSN(cfg database.DatabaseConfig, username, password string) (driverName, dsn string) {
	connStr := database.BuildConnectionString(cfg, username, password)
	switch cfg.Engine {
	case "postgresql":
		return "postgres", connStr
	case "mysql":
		return "mysql", connStr
	default:
		return "", ""
	}
}

// executeQuery opens a database connection, executes a parameterized query,
// scans all rows up to maxRows, and returns a QueryResult.
// The connection is closed before returning.
func executeQuery(ctx context.Context, driverName, dsn, query string, params []interface{}, maxRows int) (*database.QueryResult, error) {
	sqlDB, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer sqlDB.Close()

	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(0)
	sqlDB.SetConnMaxLifetime(30 * time.Second)

	rows, err := sqlDB.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	cols, data, err := database.ScanRows(rows)
	if err != nil {
		return nil, err
	}

	// Enforce max_rows after scanning.
	data = database.ApplyMaxRows(data, maxRows)

	return &database.QueryResult{
		Columns:  cols,
		Rows:     data,
		RowCount: len(data),
	}, nil
}

// sanitizeDBError removes any sensitive information from a database error
// before returning it to the AI caller. Connection strings, passwords, and
// hostnames must never appear in tool result errors.
func sanitizeDBError(err error) string {
	msg := err.Error()
	// Remove anything that looks like a DSN: "host=..." "user=..." "password=..."
	// Use a conservative approach: return a generic message for connection errors,
	// but preserve SQL syntax errors which help the AI fix the query.
	for _, keyword := range []string{"password=", "host=", "user=", "@tcp(", "://", "sslmode="} {
		if containsKeyword(msg, keyword) {
			return "database connection error (connection details redacted)"
		}
	}
	return msg
}

// containsKeyword checks if s contains substr (case-insensitive, reuse stdlib).
func containsKeyword(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1, c2 := s[i+j], substr[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// extractQueryParams converts the "params" argument (array of interface{}) into
// []interface{} for use as database/sql query parameters.
func extractQueryParams(args map[string]interface{}) []interface{} {
	raw, ok := args["params"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	return arr
}

// filterBySeverity returns only findings matching the given filter level.
// "all" or empty string returns all findings unchanged.
// "high" returns only high-severity findings.
// "medium" returns high and medium.
// "low" returns all (same as "all").
func filterBySeverity(findings []scanner.Finding, filter string) []scanner.Finding {
	switch filter {
	case "high":
		return findingsBySeverity(findings, "high")
	case "medium":
		return findingsBySeverityOrAbove(findings, "medium")
	default:
		return findings
	}
}

// findingsBySeverity filters to exactly one severity level.
func findingsBySeverity(findings []scanner.Finding, sev string) []scanner.Finding {
	var out []scanner.Finding
	for _, f := range findings {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

// findingsBySeverityOrAbove returns findings at the given severity or higher.
// Severity order: high > medium > low.
func findingsBySeverityOrAbove(findings []scanner.Finding, min string) []scanner.Finding {
	var out []scanner.Finding
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == min {
			out = append(out, f)
		}
	}
	return out
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
