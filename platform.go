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
	"strings"
	"time"

	apiclient "github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"

	"github.com/openctemio/agent/internal/executor"
)

// platformModeEnabled indicates platform mode IS available in this build.
const platformModeEnabled = true

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
		fmt.Printf("[platform] Agent ID: %s\n", creds.AgentID)
		fmt.Printf("[platform] API Key prefix: %s...\n", creds.APIPrefix)
	}

	// Create platform client
	client := platform.NewPlatformClient(&platform.ClientConfig{
		BaseURL: cfg.APIBaseURL,
		APIKey:  creds.APIKey,
		AgentID: creds.AgentID,
		Verbose: cfg.Verbose,
	})

	// Start lease manager
	leaseManager := platform.NewLeaseManager(client, &platform.LeaseConfig{
		MaxJobs: cfg.MaxConcurrent,
		Verbose: cfg.Verbose,
	})
	go leaseManager.Start(ctx)

	// Result pusher — sends scan output back to the platform's ingest API.
	// Without this the executors were constructed with a nil pusher and
	// silently discarded every finding/asset (only a count was reported).
	pusher := &platformResultPusher{
		client: apiclient.New(&apiclient.Config{
			BaseURL: cfg.APIBaseURL,
			APIKey:  creds.APIKey,
			AgentID: creds.AgentID,
			Verbose: cfg.Verbose,
		}),
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := leaseManager.Stop(shutdownCtx); err != nil && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[platform] lease release failed: %v\n", err)
		}
	}()

	fmt.Printf("[platform] Agent ready. Polling for jobs (max concurrent: %d)...\n", cfg.MaxConcurrent)
	poller.Start(ctx)
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
