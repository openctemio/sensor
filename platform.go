//go:build platform

// Platform Agent Mode - Included when building with -tags platform
//
// This mode runs the agent as a centrally managed platform agent that:
//   - Registers with the platform using bootstrap tokens
//   - Maintains a K8s-style lease for health monitoring
//   - Long-polls for jobs from the platform
//   - Routes jobs to appropriate executors
//
// Build with: go build -tags platform -o agent .

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	apiclient "github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"

	"github.com/openctemio/agent/internal/executor"
)

// platformModeEnabled indicates platform mode IS available in this build.
const platformModeEnabled = true

var _ = platformModeEnabled // Same pattern as platform_stub.go.

// PlatformAgentConfig contains the configuration for platform agent mode.
type PlatformAgentConfig struct {
	APIBaseURL      string
	BootstrapToken  string
	Name            string
	Region          string
	MaxConcurrent   int
	CredentialsFile string
	Verbose         bool
	Scanners        string
	Tools           string

	// Executor enable flags
	ReconEnabled    bool
	VulnScanEnabled bool
	SecretsEnabled  bool
	AssetsEnabled   bool
	PipelineEnabled bool

	// KeyAutoRenew enables self-renewal of the agent API key before it expires
	// (RFC-014 Phase 2). Off by default; requires the server to issue a key TTL
	// (AGENT_KEY_TTL). When on, the agent rotates its key, swaps it into the live
	// clients, and persists it to the credentials file for the next restart.
	KeyAutoRenew bool
}

// runPlatformAgent runs the agent in platform mode.
func runPlatformAgent(ctx context.Context, cfg *PlatformAgentConfig) {
	if cfg.Verbose {
		fmt.Println("[platform] Starting platform agent mode...")
	}

	// Determine credentials file path
	credsFile := cfg.CredentialsFile
	if credsFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
			os.Exit(1)
		}
		credsFile = filepath.Join(home, ".openctem", "agent-credentials.json")
	}

	// Build capabilities from enabled executors
	capabilities := buildCapabilities(cfg)

	// Build tools list
	var tools []string
	if cfg.Tools != "" {
		tools = strings.Split(cfg.Tools, ",")
	} else if cfg.Scanners != "" {
		tools = strings.Split(cfg.Scanners, ",")
	}

	// Ensure registered (load existing creds or bootstrap)
	creds, err := platform.EnsureRegistered(ctx, &platform.EnsureRegisteredConfig{
		BaseURL:         cfg.APIBaseURL,
		BootstrapToken:  cfg.BootstrapToken,
		CredentialsFile: credsFile,
		Registration: &platform.RegistrationRequest{
			Name:              cfg.Name,
			Capabilities:      capabilities,
			Tools:             tools,
			Region:            cfg.Region,
			MaxConcurrentJobs: cfg.MaxConcurrent,
		},
		Verbose: cfg.Verbose,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to register agent: %v\n", err)
		os.Exit(1)
	}

	if cfg.Verbose {
		fmt.Printf("[platform] Agent ID: %s\n", creds.SensorID)
		fmt.Printf("[platform] API Key prefix: %s...\n", creds.APIPrefix)
	}

	// Create platform client
	client := platform.NewPlatformClient(&platform.ClientConfig{
		BaseURL:  cfg.APIBaseURL,
		APIKey:   creds.APIKey,
		SensorID: creds.SensorID,
		Verbose:  cfg.Verbose,
	})

	// Start lease manager
	leaseManager := platform.NewLeaseManager(client, &platform.LeaseConfig{
		MaxJobs: cfg.MaxConcurrent,
		Verbose: cfg.Verbose,
	})
	go func() {
		if err := leaseManager.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[platform] lease manager failed to start: %v\n", err)
		}
	}()

	// Result pusher — sends scan output back to the platform's ingest API.
	// Without this the executors were constructed with a nil pusher and
	// silently discarded every finding/asset (only a count was reported).
	pusher := &platformResultPusher{
		client: apiclient.New(&apiclient.Config{
			BaseURL:  cfg.APIBaseURL,
			APIKey:   creds.APIKey,
			SensorID: creds.SensorID,
			Verbose:  cfg.Verbose,
		}),
	}

	// Agent API-key auto-renewal (RFC-014 Phase 2). Opt-in; a no-op unless the
	// server issues a key TTL. On each rotation it swaps the new key into BOTH
	// the platform client (lease/poll) and the ingest pusher, then persists it to
	// the same credentials file EnsureRegistered reads on the next restart.
	var keyRenewManager *platform.KeyRenewManager
	if cfg.KeyAutoRenew {
		keyRenewManager = platform.NewKeyRenewManager(client,
			keyRenewConfig(creds, platform.NewFileCredentialStore(credsFile), pusher.client.SetAPIKey, cfg.Verbose))
		if err := keyRenewManager.Start(ctx); err != nil && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[platform] key auto-renew failed to start: %v\n", err)
		} else if cfg.Verbose {
			fmt.Println("[platform] API-key auto-renew enabled")
		}
	}

	// Set up executor router
	router := executor.NewRouter(&executor.RouterConfig{
		ReconEnabled:    cfg.ReconEnabled,
		VulnScanEnabled: cfg.VulnScanEnabled,
		SecretsEnabled:  cfg.SecretsEnabled,
		AssetsEnabled:   cfg.AssetsEnabled,
		PipelineEnabled: cfg.PipelineEnabled,
		Verbose:         cfg.Verbose,
	}, pusher)

	// Register executors based on config
	if cfg.VulnScanEnabled {
		// Use the full default config so the per-tool scanners (nuclei,
		// trivy, semgrep) are actually enabled — a bare {Enabled:true}
		// left them all disabled, so every vulnscan job failed with
		// "scanner not configured".
		vulnCfg := executor.DefaultVulnScanConfig()
		vulnCfg.Verbose = cfg.Verbose
		router.RegisterVulnScan(executor.NewVulnScanExecutor(vulnCfg, pusher))
	}
	if cfg.SecretsEnabled {
		secretExec := executor.NewSecretsExecutor(&executor.SecretsConfig{
			GitleaksEnabled: true,
			Verbose:         cfg.Verbose,
		}, pusher)
		router.RegisterSecrets(secretExec)
	}
	if cfg.ReconEnabled {
		// Register the recon executor so advertised recon capabilities have
		// a handler (otherwise recon jobs were dispatched and rejected).
		reconCfg := executor.DefaultReconConfig()
		router.RegisterRecon(executor.NewReconExecutor(reconCfg, pusher, cfg.Verbose))
	}

	// Tenable runner mode (RFC-007 §3.10): the runner is an agent that scans a
	// LOCAL Nessus/Tenable appliance and pushes CTIS back. Credentials stay on
	// the runner (env), never in the control plane. Registered only when the
	// local appliance is configured.
	if tbURL := os.Getenv("TENABLE_BASE_URL"); tbURL != "" {
		maxHosts, _ := strconv.Atoi(os.Getenv("TENABLE_MAX_TARGET_HOSTS"))
		maxTargets, _ := strconv.Atoi(os.Getenv("TENABLE_MAX_TARGETS"))
		router.RegisterTenable(executor.NewTenableExecutor(&executor.TenableConfig{
			Enabled:        true,
			Engine:         os.Getenv("TENABLE_ENGINE"),
			BaseURL:        tbURL,
			AccessKey:      os.Getenv("TENABLE_ACCESS_KEY"),
			SecretKey:      os.Getenv("TENABLE_SECRET_KEY"),
			TemplateUUID:   os.Getenv("TENABLE_TEMPLATE_UUID"),
			MaxTargetHosts: maxHosts,
			MaxTargets:     maxTargets,
			Verbose:        cfg.Verbose,
		}, pusher))
	}

	// Start job poller
	poller := platform.NewJobPoller(client, router, &platform.PollerConfig{
		MaxConcurrentJobs: cfg.MaxConcurrent,
		PollTimeout:       30 * time.Second,
		Capabilities:      capabilities,
		Verbose:           cfg.Verbose,
	})
	// Wire the lease manager into the poller so per-job counts feed lease
	// renewals and a lease expiry cancels running jobs. Without this the lease
	// always renewed with current_jobs=0 and the expiry safety net was dead.
	poller.SetLeaseManager(leaseManager)

	// On shutdown (ctx cancel), release the lease so the control plane marks
	// the agent gone immediately instead of waiting for the TTL to expire.
	defer func() {
		if keyRenewManager != nil {
			keyRenewManager.Stop()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := leaseManager.Stop(shutdownCtx); err != nil && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[platform] lease release failed: %v\n", err)
		}
	}()

	fmt.Printf("[platform] Agent ready. Polling for jobs (max concurrent: %d)...\n", cfg.MaxConcurrent)
	if err := poller.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: job poller failed to start: %v\n", err)
		os.Exit(1)
	}
}

// buildCapabilities returns capabilities based on enabled executors.
func buildCapabilities(cfg *PlatformAgentConfig) []string {
	var caps []string
	if cfg.VulnScanEnabled {
		caps = append(caps, "sast", "sca", "dast", "container", "iac")
	}
	if cfg.ReconEnabled {
		caps = append(caps, "recon", "subdomain", "dns", "portscan")
	}
	if cfg.SecretsEnabled {
		caps = append(caps, "secrets")
	}
	// CTEM Stage-4 validation (RFC-011). The daemon ALWAYS wraps the command
	// executor with NewValidatingCommandExecutor, which runs a non-intrusive
	// safe-check (TCP reachability re-check) for `validate` commands regardless
	// of which scanners are enabled — so this agent can always serve validation.
	// Without advertising `validate`, the API's availability gate
	// (FindAvailableWithCapacity["validate"]) refuses to dispatch and the whole
	// live validation + confirm-or-downgrade loop stays dormant.
	caps = append(caps, "validate")
	// `validate:nuclei` (RFC-011.2 Phase 2b) — the validate handler routes an
	// ExecutorKind=nuclei command to the nuclei re-verify runner. Advertise it
	// where the vuln-scan (nuclei) image is present. A finding whose template
	// isn't installed is returned as `inconclusive` (never a false downgrade),
	// so advertising it is safe even if a given image lacks the nuclei binary.
	if cfg.VulnScanEnabled {
		caps = append(caps, "validate:nuclei")
	}
	// NOTE: assets/pipeline are intentionally NOT advertised — there is no
	// executor registered for them, so advertising the capability would cause
	// the platform to dispatch jobs this agent can only reject. Re-add here
	// once a corresponding executor is registered in runPlatformAgent.
	return caps
}

// platformResultPusher adapts the SDK ingest client to executor.ResultPusher
// so scan output (the CTIS report the executors build) is actually sent to the
// platform. The executors only call PushCTIS; PushAssets/PushFindings are
// provided for interface completeness.
// keyRenewConfig builds the auto-renew config. The stored key expiry seeds the
// first renewal: without it the renewer cannot tell a fresh key from an
// expiring one and rotates on every restart. Each rotation swaps the key into
// the ingest client (else its pushes 401 on the dead key) and persists the key
// together with its new expiry for the next restart.
func keyRenewConfig(creds *platform.SensorCredentials, store *platform.FileCredentialStore, setIngestKey func(string), verbose bool) *platform.KeyRenewConfig {
	agentID := creds.SensorID
	return &platform.KeyRenewConfig{
		Verbose:             verbose,
		CurrentKeyExpiresAt: creds.ExpiresAt,
		OnRotated: func(newKey string, expiresAt *time.Time) error {
			setIngestKey(newKey)
			prefix := newKey
			if len(prefix) > 12 {
				prefix = prefix[:12]
			}
			return store.Save(&platform.SensorCredentials{
				SensorID:  agentID,
				APIKey:    newKey,
				APIPrefix: prefix,
				ExpiresAt: expiresAt,
			})
		},
	}
}

type platformResultPusher struct {
	client *apiclient.Client
}

func (p *platformResultPusher) PushCTIS(ctx context.Context, report *ctis.Report) error {
	if report == nil {
		return nil
	}
	if len(report.Findings) > 0 {
		if _, err := p.client.PushFindings(ctx, report); err != nil {
			return err
		}
	}
	if len(report.Assets) > 0 {
		if _, err := p.client.PushAssets(ctx, report); err != nil {
			return err
		}
	}
	return nil
}

func (p *platformResultPusher) PushAssets(ctx context.Context, assets []ctis.Asset) error {
	if len(assets) == 0 {
		return nil
	}
	_, err := p.client.PushAssets(ctx, &ctis.Report{Assets: assets})
	return err
}

func (p *platformResultPusher) PushFindings(ctx context.Context, findings []ctis.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	_, err := p.client.PushFindings(ctx, &ctis.Report{Findings: findings})
	return err
}
