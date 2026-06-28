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
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/straylight-ai/straylight/internal/cmdwrap"
	"github.com/straylight-ai/straylight/internal/config"
	"github.com/straylight-ai/straylight/internal/database"
	"github.com/straylight-ai/straylight/internal/datadir"
	"github.com/straylight-ai/straylight/internal/egress"
	"github.com/straylight-ai/straylight/internal/firewall"
	"github.com/straylight-ai/straylight/internal/lease"
	"github.com/straylight-ai/straylight/internal/mcp"
	"github.com/straylight-ai/straylight/internal/oauth"
	"github.com/straylight-ai/straylight/internal/oidc"
	"github.com/straylight-ai/straylight/internal/policy"
	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/sanitizer"
	"github.com/straylight-ai/straylight/internal/scanner"
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

	// execChildUID/GID is the uid/gid that exec child processes are dropped to
	// via SysProcAttr.Credential (ADR-013 Part A, Option A2). The "straylight-exec"
	// account at 10101 is created in deploy/Dockerfile but has no read access to
	// <dataDir>/openbao (0700 owned by uid 10001). This makes init.json structurally
	// unreadable by exec children regardless of which binary the agent invokes.
	// Requires cap_add: [SETUID, SETGID] in deploy/docker-compose.yml.
	execChildUID = 10101
	execChildGID = 10101
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

			// --- Issue #11: load community template registry (best-effort) ---
			//
			// Community templates live in <dataDir>/templates as *.yaml, *.yml,
			// or *.json files. A missing or unreadable directory is silently
			// ignored. Individual malformed files are logged and skipped; they
			// never block startup. Built-ins always win on ID collision.
			communityDir := filepath.Join(dataDir, "templates")
			communityTemplates, loadErrs := services.LoadCommunityTemplates(communityDir)
			for _, lerr := range loadErrs {
				logger.Warn("community template skipped", "error", lerr)
			}
			mergedTemplates, mergeWarnings := services.MergeTemplates(services.ServiceTemplates, communityTemplates)
			for _, w := range mergeWarnings {
				logger.Warn("community template collision", "detail", w)
			}
			if len(communityTemplates) > 0 {
				logger.Info("community templates loaded",
					"community_count", len(communityTemplates),
					"total_count", len(mergedTemplates),
				)
			}

			san := sanitizer.NewSanitizer()
			guard := egress.New()                              // default-deny SSRF denylist (ADR-010)
			eng := policy.New()                                // per-service tool-call gate (ADR-011)
			p := proxy.NewProxyWithGuard(registry, san, guard) // proxy dialer re-checks the resolved IP
			p.SetPolicy(eng)                                   // pre-injection re-check at proxy seam
			mcpHandler := mcp.NewHandler(p, registry)
			mcpHandler.SetPolicy(eng, registry) // uniform dispatch gate at MCP seam

			// --- Phase 1: wire read_file (firewall) and scan (scanner) ---
			//
			// The firewall blocks the entire <dataDir>/openbao subtree (including
			// init.json) via BlockedDirs and also blocks init.json by name via the
			// default BlockedPatterns. This upholds the THREAT-MODEL §4 invariant:
			// the OpenBao unseal key is unreachable by any MCP tool path.
			fw := firewall.NewFirewall(firewall.FirewallConfig{
				BlockedDirs: []string{filepath.Join(dataDir, "openbao")},
				// BlockedPatterns and StructuredKeyPatterns use DefaultConfig values
				// (NewFirewall fills them when the fields are empty).
			})
			mcpHandler.SetFileReader(fw)
			mcpHandler.SetScanner(scanner.New())

			// --- Phase 2: wire db_query (database.Manager) ---
			//
			// The Manager provisions short-lived read-only dynamic credentials from
			// OpenBao and never returns the password to the AI. The policy engine
			// (ADR-011) already gates db_query in dispatchToolCall. Credentials are
			// revoked on shutdown via the defer chain below.
			dbMgr := database.NewManager(&vaultDBAdapter{vc: vaultClient})
			defer dbMgr.RevokeAll() // invalidate temporary DB users on shutdown
			defer dbMgr.Close()     // stop the lease-renewal goroutine
			mcpHandler.SetDBExecutor(dbMgr)

			// --- Phase 3: wire straylight_exec with privilege separation ---
			//
			// The exec child runs as uid/gid 10101 ("straylight-exec"), which has no
			// read access to <dataDir>/openbao (0700, owned by uid 10001). This makes
			// the OpenBao init.json structurally unreadable by the child process via
			// any binary the agent might choose — the kernel returns EACCES on open(2).
			// (ADR-013 Part A, Option A2: privilege separation.)
			//
			// Runtime requirement: the container must have cap_add: [SETUID, SETGID]
			// alongside cap_drop: ALL in deploy/docker-compose.yml, and the
			// straylight-exec user (uid 10101) must exist in the image.
			//
			// In native (non-container) development runs, syscall.SysProcAttr sets the
			// child to the current uid (os.Getuid()), which is a no-op uid-drop. The
			// init.json protection in that mode relies on filesystem permissions only.
			execUID := uint32(execChildUID)
			execGID := uint32(execChildGID)
			execWrapper := cmdwrap.NewWrapperWithGuard(registry, san, guard)
			execWrapper.SetChildCredential(execUID, execGID)
			execWrapper.SetApprover(cmdwrap.NewAutoApprover())
			mcpHandler.SetCommandExecutor(execWrapper)

			baseURL := fmt.Sprintf("http://localhost:%d", port)
			// ADR-012 Phase 4: wire RefreshGuard into the OAuth handler so concurrent
			// refreshes for the same service single-flight and the rotated refresh token
			// is written back to OpenBao atomically, protecting Slack (single-use RT)
			// and Atlassian (rotating RT) from refresh races.
			oauthRefreshGuard := tokenexchange.NewRefreshGuard()
			oauthHandler := oauth.NewHandlerWithGuard(vaultClient, registry, baseURL, oauthRefreshGuard)

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

			// CloudManager is wired into server.Config so route handlers can reach it,
			// but no route handler dispatches to it yet -- that is pending the
			// straylight_exec wiring in issue #14. The Manager owns a token-exchange
			// Engine that runs a background refresh goroutine; Close is called via
			// defer below so the goroutine does not outlive the serve command.
			cloudMgr := cloud.BuildKeylessCloudManager(
				vaultClient,
				"straylight",
				awsWebIdentityClient,
				gcpSTSClient,
				azureTokenClient,
				staticSTSClient,
			)
			defer cloudMgr.Close() // stops the Engine background refresh goroutine on shutdown

			srv := server.New(server.Config{
				ListenAddress: listenAddr,
				Version:       version,
				VaultStatus:   sup.VaultStatus,
				Registry:      registry,
				OAuthHandler:  oauthHandler,
				MCPHandler:    mcpHandler,
				OIDCDiscovery: oidcDiscovery,
				CloudManager:  cloudMgr,
				DBManager:     dbMgr,
				EgressGuard:   guard,           // issue #11: use the same guard as the proxy
				Templates:     mergedTemplates, // issue #11: built-ins + community catalog
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
				"go":      runtime.Version(),
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
// vaultDBAdapter adapts *vault.Client to satisfy database.VaultClient.
//
// The only mismatch is RenewLease: vault.Client returns *vault.LeaseInfo while
// database.VaultClient expects *lease.LeaseInfo. The two structs are field-for-
// field identical (lease.go mirrors vault/lease.go to avoid a circular import).
// ---------------------------------------------------------------------------

// vaultDBAdapter wraps *vault.Client and satisfies database.VaultClient.
type vaultDBAdapter struct {
	vc *vault.Client
}

func (a *vaultDBAdapter) GetDynamicCredential(enginePath, roleName string) (map[string]interface{}, string, int, error) {
	return a.vc.GetDynamicCredential(enginePath, roleName)
}

func (a *vaultDBAdapter) ConfigureDatabaseConnection(name, plugin, connURL string, allowedRoles []string, extra map[string]interface{}) error {
	return a.vc.ConfigureDatabaseConnection(name, plugin, connURL, allowedRoles, extra)
}

func (a *vaultDBAdapter) CreateDatabaseRole(name, dbName string, creationStatements []string, defaultTTL, maxTTL string) error {
	return a.vc.CreateDatabaseRole(name, dbName, creationStatements, defaultTTL, maxTTL)
}

// RenewLease converts *vault.LeaseInfo to *lease.LeaseInfo (same fields, different types).
func (a *vaultDBAdapter) RenewLease(leaseID string, increment int) (*lease.LeaseInfo, error) {
	info, err := a.vc.RenewLease(leaseID, increment)
	if err != nil {
		return nil, err
	}
	return &lease.LeaseInfo{
		LeaseID:       info.LeaseID,
		LeaseDuration: info.LeaseDuration,
		Renewable:     info.Renewable,
	}, nil
}

func (a *vaultDBAdapter) RevokeLease(leaseID string) error {
	return a.vc.RevokeLease(leaseID)
}

func (a *vaultDBAdapter) RevokeLeasePrefix(prefix string) error {
	return a.vc.RevokeLeasePrefix(prefix)
}

// Compile-time assertion that vaultDBAdapter satisfies database.VaultClient.
var _ database.VaultClient = (*vaultDBAdapter)(nil)

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
