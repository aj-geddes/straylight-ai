// Command straylight-mcp is the MCP host binary for Straylight-AI.
//
// It acts as a thin stdio adapter that bridges MCP tool calls from an AI agent
// (e.g., Claude Code) to the Straylight-AI HTTP API running on localhost:9470.
//
// This binary is registered as an MCP server in the agent's configuration and
// communicates over stdin/stdout using the MCP JSON-RPC protocol.
//
// Usage:
//
//	straylight-mcp                     -- Run as MCP stdio server (default)
//	straylight-mcp hook pretooluse     -- Run the PreToolUse hook
//	straylight-mcp hook posttooluse    -- Run the PostToolUse hook
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/straylight-ai/straylight/internal/hooks"
	"github.com/straylight-ai/straylight/internal/sanitizer"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run implements the binary's logic and returns an exit code.
// Separated from main() to allow testing without os.Exit side-effects.
func run(args []string) int {
	// Subcommand routing.
	if len(args) >= 2 && args[0] == "hook" {
		return runHook(args[1])
	}

	// Default: run as MCP stdio server.
	return runMCPServer()
}

// runMCPServer starts the JSON-RPC 2.0 MCP stdio server.
func runMCPServer() int {
	containerURL := parseContainerURL(os.Getenv("STRAYLIGHT_URL"))
	client := NewContainerClient(containerURL)

	// Startup health check. Log to stderr only — stdout is reserved for MCP.
	if err := client.Health(); err != nil {
		logStderr("warn", "container unavailable at startup", map[string]interface{}{
			"url":   containerURL,
			"error": err.Error(),
		})
		// Continue running: the container may start later.
	} else {
		logStderr("info", "container healthy", map[string]interface{}{
			"url": containerURL,
		})
	}

	server := NewMCPServer(client)

	// Handle SIGTERM/SIGINT for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Serve(os.Stdin, os.Stdout)
	}()

	select {
	case <-sigCh:
		logStderr("info", "shutdown signal received", nil)
	case <-done:
		// stdin closed (AI agent disconnected).
	}

	return 0
}

// runHook dispatches to the appropriate hook handler.
func runHook(hookName string) int {
	containerURL := parseContainerURL(os.Getenv("STRAYLIGHT_URL"))
	client := NewContainerClient(containerURL)

	switch hookName {
	case "pretooluse":
		lister := NewContainerServiceLister(client)
		return hooks.RunPreToolUse(os.Stdin, os.Stdout, lister)

	case "posttooluse":
		san := sanitizer.NewSanitizer()
		return hooks.RunPostToolUse(os.Stdin, os.Stdout, san)

	default:
		fmt.Fprintf(os.Stderr, "straylight-mcp: unknown hook %q (expected pretooluse or posttooluse)\n", hookName)
		return 1
	}
}

// logStderr writes a structured JSON log line to stderr.
// Errors writing to stderr are silently ignored.
func logStderr(level, msg string, fields map[string]interface{}) {
	entry := map[string]interface{}{
		"level": level,
		"msg":   msg,
	}
	for k, v := range fields {
		entry[k] = v
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	fmt.Fprintln(os.Stderr, string(data))
}
