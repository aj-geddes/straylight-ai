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
	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/oauth"
	"github.com/straylight-ai/straylight/internal/oidc"
	"github.com/straylight-ai/straylight/internal/policy"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/sanitizer"
	"github.com/straylight-ai/straylight/internal/server"
	"github.com/straylight-ai/straylight/internal/services"
	"github.com/straylight-ai/straylight/internal/vault"

	"github.com/straylight-ai/straylight/internal/cloud"
	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

const (
	version           = "1.0.4"
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

			// Start background token renewal to prevent AppRole token expiry.
			sup.StartTokenRenewal(ctx, vaultClient)

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
			guard := egress.New()                              // default-deny SSRF denylist (ADR-010)
			eng := policy.New()                                // per-service tool-call gate (ADR-011)
			p := proxy.NewProxyWithGuard(registry, san, guard) // proxy dialer re-checks the resolved IP
			p.SetPolicy(eng)                                   // pre-injection re-check at proxy seam
			mcpHandler := mcp.NewHandler(p, registry)
			mcpHandler.SetPolicy(eng, registry) // uniform dispatch gate at MCP seam
			// NOTE: straylight_exec is intentionally left UNWIRED here. cmdwrap.NewWrapperWithGuard
			// exists and applies an egress pre-flight, but activating exec (SetCommandExecutor) is
			// deferred to issue #14 and MUST land together with a command allowlist and filesystem
			// scoping — otherwise the AI could read the OpenBao unseal key via the exec path
			// (cat <dataDir>/openbao/init.json bypasses the URL-only egress check).
			// See docs/security/THREAT-MODEL.md §4.

			baseURL := fmt.Sprintf("http://localhost:%d", port)
			oauthHandler := oauth.NewHandler(vaultClient, registry, baseURL)

			// ADR-012 Phase 1: configure OpenBao as OIDC trust root and build the
			// public discovery document. The issuer URL is the server's public base URL.
			// External reachability (ingress/tunnel) is a deployment concern.
			issuerURL := baseURL
			oidcDiscovery := buildOIDCDiscovery(logger, vaultClient, issuerURL, baseURL)

			// ADR-012 Phase 2: wire the token-exchange Engine + OpenBaoIdentitySource +
			// three cloud ExchangeAdapters into the cloud Manager. The identity issuer
			// must be configured (buildOIDCDiscovery above) before the Engine is used.
			// Services opt in to the keyless path by setting a WebIdentity/WIF/FIC block
			// in their ServiceConfig; services without that block use the static path.
			//
			// Real cloud clients (issue #10): AWS clients use the ambient credential
			// chain (env vars, instance profiles, IMDS). The keyless path presents an
			// OpenBao OIDC proof to the cloud STS instead of static admin keys. The
			// static AWS path (no WebIdentity block) uses the same ambient caller.
			// GCP and Azure clients post directly to their STS endpoints via HTTPS.
			awsCallerDefault, awsCallerErr := cloud.NewAWSSTSCallerDefault(ctx, "")
			if awsCallerErr != nil {
				logger.Warn("failed to build default AWS STS caller; static+keyless AWS paths unavailable", "error", awsCallerErr)
				awsCallerDefault = nil
			}

			var staticSTSClient cloud.STSClient
			var awsWebIdentityClient tokenexchange.STSWebIdentityClient
			if awsCallerDefault != nil {
				staticSTSClient = cloud.NewAWSStaticSTSClientWithCaller(awsCallerDefault)
				awsWebIdentityClient = cloud.NewAWSWebIdentitySTSClientWithCaller(awsCallerDefault)
			} else {
				staticSTSClient = &unavailableSTSClient{reason: "aws sts caller unavailable at startup (issue #14 tracks exec wiring)"}
				awsWebIdentityClient = &unavailableSTSWebIdentityClient{reason: "aws sts caller unavailable at startup (issue #14 tracks exec wiring)"}
			}

			gcpSTSClient := cloud.NewGCPSTSClient(nil, "")
			azureTokenClient := cloud.NewAzureHTTPTokenClient(nil, "")

			cloudMgr := cloud.BuildKeylessCloudManager(
				vaultClient,
				"straylight",
				awsWebIdentityClient,
				gcpSTSClient,
				azureTokenClient,
				staticSTSClient,
			)

			srv := server.New(server.Config{
				ListenAddress: listenAddr,
				Version:       version,
				VaultStatus:   sup.VaultStatus,
				Registry:      registry,
				OAuthHandler:  oauthHandler,
				MCPHandler:    mcpHandler,
				OIDCDiscovery: oidcDiscovery,
				CloudManager:  cloudMgr,
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

// buildOIDCDiscovery configures OpenBao as an OIDC trust root (ADR-012 Phase 1)
// and builds the public OIDC discovery document for the server. Errors are
// logged as warnings; the server will start with an empty JWKS on failure.
// External reachability of the issuer is a deployment concern.
func buildOIDCDiscovery(logger *slog.Logger, vaultClient *vault.Client, issuerURL, baseURL string) *oidc.Discovery {
	if err := vaultClient.ConfigureIdentityIssuer(issuerURL); err != nil {
		logger.Warn("failed to configure identity issuer", "error", err)
	}

	if err := vaultClient.CreateIdentityRole("straylight", []string{issuerURL}, "1h", nil); err != nil {
		logger.Warn("failed to create identity role", "error", err)
	}

	jwks, err := vaultClient.FetchPublicJWKS()
	if err != nil {
		logger.Warn("failed to fetch public JWKS from vault", "error", err)
		jwks = vault.JWKSet{}
	}

	oidcKeys := make([]oidc.JWKKey, 0, len(jwks.Keys))
	for _, k := range jwks.Keys {
		oidcKeys = append(oidcKeys, oidc.JWKKey{
			Kty: k.Kty,
			Kid: k.Kid,
			Use: k.Use,
			Alg: k.Alg,
			N:   k.N,
			E:   k.E,
			Crv: k.Crv,
			X:   k.X,
			Y:   k.Y,
		})
	}

	return &oidc.Discovery{
		IssuerURL:     issuerURL,
		JWKSURI:       baseURL + "/.well-known/jwks.json",
		SupportedAlgs: []string{"RS256"},
		Keys:          oidcKeys,
	}
}

// ---------------------------------------------------------------------------
// Minimal fallback cloud client stubs
// ---------------------------------------------------------------------------
//
// These stubs are used when the ambient AWS credential chain is unavailable at
// startup (e.g. no IAM role, no env vars). They return a clear structured error
// instead of panicking. In normal deployments with instance profiles or env
// credentials, the real SDK-backed clients above are used.
//
// NOTE: straylight_exec remains UNWIRED (see NOTE comment above); these stubs
// are for the cloud Manager only and are not related to exec wiring (issue #14).

// unavailableSTSWebIdentityClient satisfies tokenexchange.STSWebIdentityClient
// when the AWS caller could not be initialized at startup.
type unavailableSTSWebIdentityClient struct{ reason string }

func (u *unavailableSTSWebIdentityClient) AssumeRoleWithWebIdentity(
	_ context.Context,
	_ tokenexchange.STSAssumeRoleWithWebIdentityInput,
) (*tokenexchange.STSWebIdentityCredentials, error) {
	return nil, fmt.Errorf("cloud: aws web-identity STS client not available: %s", u.reason)
}

// unavailableSTSClient satisfies cloud.STSClient when the AWS caller could not
// be initialized at startup.
type unavailableSTSClient struct{ reason string }

func (u *unavailableSTSClient) AssumeRole(
	_ context.Context,
	_ cloud.STSAssumeRoleInput,
) (*cloud.STSCredentials, error) {
	return nil, fmt.Errorf("cloud: static aws STS client not available: %s", u.reason)
}
