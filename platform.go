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

	// Set up executor router
	router := executor.NewRouter(&executor.RouterConfig{
		ReconEnabled:    cfg.ReconEnabled,
		VulnScanEnabled: cfg.VulnScanEnabled,
		SecretsEnabled:  cfg.SecretsEnabled,
		AssetsEnabled:   cfg.AssetsEnabled,
		PipelineEnabled: cfg.PipelineEnabled,
		Verbose:         cfg.Verbose,
	}, nil)

	// Register executors based on config
	if cfg.VulnScanEnabled {
		vulnExec := executor.NewVulnScanExecutor(&executor.VulnScanConfig{
			Enabled: true,
			Verbose: cfg.Verbose,
		}, nil)
		router.RegisterVulnScan(vulnExec)
	}
	if cfg.SecretsEnabled {
		secretExec := executor.NewSecretsExecutor(&executor.SecretsConfig{
			GitleaksEnabled: true,
			Verbose:         cfg.Verbose,
		}, nil)
		router.RegisterSecrets(secretExec)
	}

	// Start job poller
	poller := platform.NewJobPoller(client, router, &platform.PollerConfig{
		MaxConcurrentJobs: cfg.MaxConcurrent,
		PollTimeout:       30 * time.Second,
		Capabilities:      capabilities,
		Verbose:           cfg.Verbose,
	})

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
	if cfg.AssetsEnabled {
		caps = append(caps, "assets")
	}
	if cfg.PipelineEnabled {
		caps = append(caps, "pipeline")
	}
	return caps
}
