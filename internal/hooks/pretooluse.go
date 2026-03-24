// Package hooks provides Claude Code hook script implementations.
// pretooluse.go intercepts tool calls before execution to block credential leakage.
package hooks

import (
	"fmt"
	"strings"

	"github.com/straylight-ai/straylight/internal/services"
)

// credentialEnvVars is the set of environment variable names that are
// treated as credential references. Matching is case-sensitive because shell
// env vars are case-sensitive on Linux.
var credentialEnvVars = []string{
	"STRIPE_API_KEY",
	"STRIPE_SECRET_KEY",
	"GH_TOKEN",
	"GITHUB_TOKEN",
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"DATABASE_URL",
	"POSTGRES_PASSWORD",
	"REDIS_URL",
	"SLACK_TOKEN",
	"DISCORD_TOKEN",
	"SENDGRID_API_KEY",
	"TWILIO_AUTH_TOKEN",
}

// credentialFilePaths contains path fragments that indicate a command is
// trying to read a credential file. Matching uses substring search.
var credentialFilePaths = []string{
	"/data/openbao/init.json",
	"openbao/init.json",
	".straylight-ai/data/openbao",
}

// credentialFilePatterns contains file name patterns that indicate a command
// is trying to read a secrets file. Matching uses substring search.
var credentialFilePatterns = []string{
	".env",
}

// suggestionMessage is appended to every block reason.
const suggestionMessage = "Use straylight_api_call or straylight_exec instead."

// ServiceLister provides the list of registered services.
// The PreToolUseChecker uses this to derive runtime credential env var names.
type ServiceLister interface {
	List() []services.Service
}

// PreToolUseInput is the JSON payload Claude Code sends to a PreToolUse hook.
type PreToolUseInput struct {
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
}

// PreToolUseChecker examines a tool's input and decides whether to allow or
// block the tool call based on credential-leakage detection rules.
type PreToolUseChecker struct {
	services ServiceLister
}

// NewPreToolUseChecker creates a PreToolUseChecker backed by the given lister.
func NewPreToolUseChecker(services ServiceLister) *PreToolUseChecker {
	return &PreToolUseChecker{services: services}
}

// Check examines a PreToolUseInput and returns (allow, message).
// allow=true means the tool call should proceed; allow=false means block.
// When blocking, message contains the human-readable reason and suggestion.
func (c *PreToolUseChecker) Check(input PreToolUseInput) (allow bool, message string) {
	if input.ToolInput == nil {
		return true, ""
	}

	// Collect all string values from the tool input for uniform inspection.
	text := extractText(input.ToolInput)
	if text == "" {
		return true, ""
	}

	// Build the full set of credential env var names: builtins plus any
	// service-derived names from the runtime registry.
	envVars := c.credentialEnvVarNames()

	// Check for credential env var references ($VAR or ${VAR}).
	for _, name := range envVars {
		if strings.Contains(text, "$"+name) || strings.Contains(text, "${"+name+"}") {
			return false, fmt.Sprintf(
				"Blocked: command references credential env var $%s. %s",
				name, suggestionMessage,
			)
		}
	}

	// Check for credential file paths.
	for _, path := range credentialFilePaths {
		if strings.Contains(text, path) {
			return false, fmt.Sprintf(
				"Blocked: command targets credential path %q. %s",
				path, suggestionMessage,
			)
		}
	}

	// Check for credential file name patterns (e.g. "cat .env").
	for _, pattern := range credentialFilePatterns {
		if matchesFilePattern(text, pattern) {
			return false, fmt.Sprintf(
				"Blocked: command targets credential file %q. %s",
				pattern, suggestionMessage,
			)
		}
	}

	return true, ""
}

// credentialEnvVarNames returns the combined list of built-in credential env
// var names plus service-derived names from the registry.
func (c *PreToolUseChecker) credentialEnvVarNames() []string {
	names := make([]string, len(credentialEnvVars))
	copy(names, credentialEnvVars)

	for _, svc := range c.services.List() {
		upper := strings.ToUpper(strings.ReplaceAll(svc.Name, "-", "_"))
		names = append(names, upper+"_API_KEY", upper+"_TOKEN", upper+"_SECRET")
	}
	return names
}

// extractText concatenates all string values from the tool input map,
// separated by spaces, for uniform text analysis.
func extractText(input map[string]interface{}) string {
	var parts []string
	for _, v := range input {
		if s, ok := v.(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// matchesFilePattern checks whether the text contains a reference to a
// specific file by name (not as part of a longer path segment).
// For ".env" it checks for the literal string " .env" or starts with ".env"
// or appears after a path separator to avoid false positives on ".envrc" etc.
func matchesFilePattern(text, pattern string) bool {
	// Look for the pattern appearing as a distinct token: preceded by space,
	// slash, or at the start, and followed by whitespace, end, or specific chars.
	for i := 0; i <= len(text)-len(pattern); i++ {
		if text[i:i+len(pattern)] != pattern {
			continue
		}
		// Check left boundary.
		leftOK := i == 0 || text[i-1] == ' ' || text[i-1] == '\t' || text[i-1] == '/'
		// Check right boundary.
		end := i + len(pattern)
		rightOK := end == len(text) || text[end] == ' ' || text[end] == '\t' || text[end] == '\n' || text[end] == ';' || text[end] == '|'
		if leftOK && rightOK {
			return true
		}
	}
	return false
}
