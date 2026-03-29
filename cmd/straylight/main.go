// Command straylight is the main Straylight-AI server binary.
//
// Usage:
//
//	straylight serve  [--port PORT] [--config PATH]
//	straylight health
//	straylight version
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/straylight-ai/straylight/internal/config"
	"github.com/straylight-ai/straylight/internal/datadir"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/oauth"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/sanitizer"
	"github.com/straylight-ai/straylight/internal/server"
	"github.com/straylight-ai/straylight/internal/services"
	"github.com/straylight-ai/straylight/internal/vault"
)

const (
	version           = "1.0.1"
	defaultPort       = 9470
	defaultConfigPath = config.DefaultConfigPath
	defaultDataDir    = "/data"
	healthTimeout     = 5 * time.Second
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "straylight",
		Short: "Straylight-AI — zero-knowledge credential proxy for AI agents",
		Long: `Straylight-AI is a zero-knowledge credential proxy that allows AI agents
to call external APIs without ever seeing or storing your credentials.`,
	}

	root.AddCommand(newServeCmd())
	root.AddCommand(newHealthCmd())
	root.AddCommand(newVersionCmd())

	return root
}

func newServeCmd() *cobra.Command {
	var portFlag int
	var configPath string
	var dataDirFlag string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Straylight-AI HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Data directory resolution: flag > env > default
			dataDir := resolveDataDir(dataDirFlag)

			logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
			logger.Info("initializing data directory", "path", dataDir)

			if err := datadir.Initialize(dataDir); err != nil {
				return fmt.Errorf("serve: %w", err)
			}

			// Port resolution: flag > env > default
			port := resolvePort(portFlag)
			listenAddr := fmt.Sprintf("0.0.0.0:%d", port)

			// Load config if the file exists; otherwise use defaults
			var cfg *config.Config
			if _, err := os.Stat(configPath); err == nil {
				loaded, err := config.Load(configPath)
				if err != nil {
					return fmt.Errorf("serve: %w", err)
				}
				cfg = loaded
				if portFlag != 0 || os.Getenv("STRAYLIGHT_PORT") != "" {
					cfg.Server.ListenAddress = listenAddr
				} else {
					listenAddr = cfg.Server.ListenAddress
				}
			} else {
				listenAddr = fmt.Sprintf("0.0.0.0:%d", port)
			}

			_ = cfg

			logger.Info("starting straylight", "version", version, "listen", listenAddr)

			// --- Start OpenBao vault supervisor ---
			sup := vault.NewSupervisor(vault.SupervisorConfig{
				InitPath: dataDir + "/openbao/init.json",
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			logger.Info("starting OpenBao")
			if err := sup.Start(ctx); err != nil {
				return fmt.Errorf("serve: start vault: %w", err)
			}
			defer sup.Stop()

			logger.Info("waiting for OpenBao to be ready")
			if err := sup.WaitForReady(30 * time.Second); err != nil {
				return fmt.Errorf("serve: vault not ready: %w", err)
			}

			logger.Info("initializing vault (init, unseal, auth)")
			vaultClient, err := sup.InitializeVault()
			if err != nil {
				return fmt.Errorf("serve: vault init: %w", err)
			}
			logger.Info("vault ready", "address", sup.Config().ListenAddr)

			// --- Build component graph ---
			registry := services.NewRegistry(vaultClient)

			// Restore persisted services from vault metadata after restart.
			if err := registry.LoadFromVault(); err != nil {
				logger.Warn("failed to load services from vault", "error", err)
			}
			logger.Info("services loaded", "count", len(registry.List()))

			// Re-enrich account info for each reloaded service (best-effort).
			for _, svc := range registry.List() {
				cred, err := registry.GetCredential(svc.Name)
				if err == nil && cred != "" {
					if info := services.FetchAccountInfo(svc.Target, cred, svc.AuthMethodID, svc.DefaultHeaders); info != nil {
						_ = registry.SetAccountInfo(svc.Name, info)
					}
				}
			}

			san := sanitizer.NewSanitizer()
			p := proxy.NewProxy(registry, san)
			mcpHandler := mcp.NewHandler(p, registry)

			baseURL := fmt.Sprintf("http://localhost:%d", port)
			oauthHandler := oauth.NewHandler(vaultClient, registry, baseURL)

			srv := server.New(server.Config{
				ListenAddress: listenAddr,
				Version:       version,
				VaultStatus:   sup.VaultStatus,
				Registry:      registry,
				OAuthHandler:  oauthHandler,
				MCPHandler:    mcpHandler,
			})
			return srv.Run()
		},
	}

	cmd.Flags().IntVarP(&portFlag, "port", "p", 0,
		"Port to listen on (default 9470, overrides config; env: STRAYLIGHT_PORT)")
	cmd.Flags().StringVarP(&configPath, "config", "c", defaultConfigPath,
		"Path to config.yaml")
	cmd.Flags().StringVar(&dataDirFlag, "data-dir", "",
		"Path to data directory (default /data; env: STRAYLIGHT_DATA_DIR)")

	return cmd
}

// resolveDataDir returns the effective data directory based on
// flag > env > default precedence.
func resolveDataDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if envVal := os.Getenv("STRAYLIGHT_DATA_DIR"); envVal != "" {
		return envVal
	}
	return defaultDataDir
}

// resolvePort returns the effective port based on flag > env > default precedence.
func resolvePort(flagPort int) int {
	if flagPort != 0 {
		return flagPort
	}
	if envPort := os.Getenv("STRAYLIGHT_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			return p
		}
	}
	return defaultPort
}

func newHealthCmd() *cobra.Command {
	var portFlag int

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check health of a running Straylight-AI server",
		RunE: func(cmd *cobra.Command, args []string) error {
			port := resolvePort(portFlag)
			url := fmt.Sprintf("http://localhost:%d/api/v1/health", port)

			client := &http.Client{Timeout: healthTimeout}
			resp, err := client.Get(url)
			if err != nil {
				return fmt.Errorf("health: cannot reach server at %s: %w", url, err)
			}
			defer resp.Body.Close()

			var body map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				return fmt.Errorf("health: failed to decode response: %w", err)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(body)

			if resp.StatusCode >= 500 {
				return fmt.Errorf("health: server reported unhealthy status %d", resp.StatusCode)
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&portFlag, "port", "p", 0,
		"Port the server is running on (default 9470; env: STRAYLIGHT_PORT)")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			info := map[string]string{
				"version": version,
				"go":      "go1.24",
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(info)
		},
	}
}
