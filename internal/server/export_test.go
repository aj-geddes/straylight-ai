// Package server provides internal test seams for server functionality.
package server

// BuildRemoteServer is a method expression exposing the unexported buildRemoteServer
// method for integration tests that verify remote MCP wiring (ADR-015 / issue #12).
// Usage: httpSrv, err := server.BuildRemoteServer(serverInstance)
var BuildRemoteServer = (*Server).buildRemoteServer
