// OpenCTEM Agent - Universal Security Scanner/Collector Agent
//
// This agent supports multiple deployment modes:
//
//  1. ONE-SHOT MODE (CI/CD):
//     agent -tool semgrep -target ./src -push
//
//  2. DAEMON MODE (Continuous):
//     agent -daemon -config config.yaml
//
//  3. SERVER-CONTROLLED MODE:
//     agent -daemon -enable-commands -config config.yaml
//
// For more details, see: docs/architecture/deployment-modes.md
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/agent/internal/gate"
	"github.com/openctemio/agent/internal/git"
	"github.com/openctemio/agent/internal/output"
	"github.com/openctemio/agent/internal/tools"
	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/gitenv"
	"github.com/openctemio/sdk-go/pkg/handler"
	"github.com/openctemio/sdk-go/pkg/retry"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/scanners"
	"github.com/openctemio/sdk-go/pkg/scanners/gitleaks"
	"github.com/openctemio/sdk-go/pkg/scanners/semgrep"
	"github.com/openctemio/sdk-go/pkg/scanners/trivy"
	"github.com/openctemio/sdk-go/pkg/strategy"
)

const appName = "OpenCTEM Agent"

// Version is set via ldflags at build time: -ldflags="-X main.Version=..."
// Example: go build -ldflags="-X main.Version=v1.0.0" .
var Version = "v0.1.0"

// Config represents the agent configuration.
type Config struct {
	// Agent settings
	Agent struct {
		Name              string        `yaml:"name"`
		Region            string        `yaml:"region"` // Deployment region (e.g., "us-east-1", "ap-southeast-1")
		ScanInterval      time.Duration `yaml:"scan_interval"`
		CollectInterval   time.Duration `yaml:"collect_interval"`
		HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
		Verbose           bool          `yaml:"verbose"`

		// Server control
		EnableCommands      bool          `yaml:"enable_commands"`
		CommandPollInterval time.Duration `yaml:"command_poll_interval"`
	} `yaml:"agent"`

	// API configuration (uses 'server' in yaml for backward compatibility)
	API struct {
		BaseURL string        `yaml:"base_url"`
		APIKey  string        `yaml:"api_key"`
		AgentID string        `yaml:"agent_id"` // For tenant tracking
		Timeout time.Duration `yaml:"timeout"`
	} `yaml:"server"`

	// Retry Queue (for network resilience)
	RetryQueue struct {
		Enabled     bool          `yaml:"enabled"`
		Dir         string        `yaml:"dir"`          // Queue directory (default: ~/.openctem/retry-queue)
		Interval    time.Duration `yaml:"interval"`     // Retry check interval (default: 5m)
		MaxAttempts int           `yaml:"max_attempts"` // Max retry attempts (default: 10)
		TTL         time.Duration `yaml:"ttl"`          // Item TTL (default: 7d)
	} `yaml:"retry_queue"`

	// Scanners to run
	Scanners []ScannerConfig `yaml:"scanners"`

	// Collectors to run
	Collectors []CollectorConfig `yaml:"collectors"`

	// Targets
	Targets []string `yaml:"targets"`
}

// ScannerConfig configures a scanner.
type ScannerConfig struct {
	Name    string   `yaml:"name"`   // Preset name or "custom"
	Binary  string   `yaml:"binary"` // Binary path (for custom)
	Args    []string `yaml:"args"`   // Command args (for custom)
	Enabled bool     `yaml:"enabled"`
}

// CollectorConfig configures a collector.
type CollectorConfig struct {
	Name         string        `yaml:"name"`  // e.g., "github", "gitlab"
	Token        string        `yaml:"token"` // API token
	Owner        string        `yaml:"owner"` // Org/user
	Repo         string        `yaml:"repo"`  // Repository (optional - all if empty)
	Enabled      bool          `yaml:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval"` // For daemon mode
}

func main() {
	// CLI flags
	configPath := flag.String("config", "", "Path to config file")
	tool := flag.String("tool", "", "Tool to run (semgrep, trivy-fs, gitleaks, etc.)")
	toolsFlag := flag.String("tools", "", "Comma-separated list of tools")
	target := flag.String("target", ".", "Target directory to scan")
	apiURL := flag.String("api-url", "", "API base URL (or API_URL env)")
	apiKey := flag.String("api-key", "", "API key for authentication (or API_KEY env)")
	agentID := flag.String("agent-id", "", "Agent ID for tracking (or AGENT_ID env)")
	push := flag.Bool("push", false, "Push results to API")
	daemon := flag.Bool("daemon", false, "Run in daemon mode")
	enableCommands := flag.Bool("enable-commands", false, "Enable server command polling (daemon mode)")
	standalone := flag.Bool("standalone", false, "Standalone mode - no server communication")
	verbose := flag.Bool("verbose", false, "Verbose output")
	listTools := flag.Bool("list-tools", false, "List available tools")
	showVersion := flag.Bool("version", false, "Show version")
	outputJSON := flag.Bool("json", false, "Output results as JSON")
	outputFile := flag.String("output", "", "Output file path (instead of stdout)")
	createComments := flag.Bool("comments", false, "Create PR/MR inline comments for findings")
	autoDetectCI := flag.Bool("auto-ci", true, "Auto-detect CI environment (GitHub Actions, GitLab CI)")
	checkTools := flag.Bool("check-tools", false, "Check if required tools are installed and show installation instructions")
	installTools := flag.Bool("install-tools", false, "Interactively install missing tools (requires sudo for some tools)")

	// Security gate flags (CI/CD)
	failOn := flag.String("fail-on", "", "Exit with code 1 if findings >= severity (critical, high, medium, low)")
	outputFormat := flag.String("output-format", "", "Output format: json, sarif, table (default: table)")

	// Retry queue flags
	enableRetryQueue := flag.Bool("retry-queue", false, "Enable persistent retry queue for network resilience (or RETRY_QUEUE env)")
	retryQueueDir := flag.String("retry-dir", "", "Retry queue directory (default: ~/.agent/retry-queue, or RETRY_DIR env)")

	// Region flag
	region := flag.String("region", "", "Deployment region (or REGION, AWS_REGION env)")

	// Platform agent flags
	platformMode := flag.Bool("platform", false, "Run as platform agent")
	bootstrapToken := flag.String("bootstrap-token", "", "Bootstrap token for platform agent registration (or BOOTSTRAP_TOKEN env)")
	agentName := flag.String("name", "", "Agent name (auto-generated if not specified)")
	maxConcurrent := flag.Int("max-concurrent", 5, "Maximum concurrent jobs")
	credentialsFile := flag.String("credentials", "", "Path to credentials file for persistent storage (default: ~/.openctem/agent-credentials.json)")

	// Executor enable flags (for platform mode)
	enableRecon := flag.Bool("enable-recon", false, "Enable recon executor (subdomain, dns, portscan, http discovery)")
	enableVulnScan := flag.Bool("enable-vulnscan", true, "Enable vulnerability scan executor (nuclei, trivy, semgrep)")
	enableSecrets := flag.Bool("enable-secrets", false, "Enable secrets executor (gitleaks, trufflehog)")
	enableAssets := flag.Bool("enable-assets", false, "Enable assets executor (cloud asset collection)")
	enablePipeline := flag.Bool("enable-pipeline", false, "Enable pipeline executor (workflow execution)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("%s version %s\n", appName, Version)
		os.Exit(0)
	}

	if *listTools {
		fmt.Println("Available scanners:")
		fmt.Println()
		fmt.Println("  Native scanners (recommended):")
		fmt.Printf("    %-15s - %s\n", "semgrep", "SAST scanner with dataflow/taint tracking")
		fmt.Printf("    %-15s - %s\n", "gitleaks", "Secret detection scanner")
		fmt.Printf("    %-15s - %s\n", "trivy", "SCA vulnerability scanner (filesystem)")
		fmt.Printf("    %-15s - %s\n", "trivy-config", "IaC misconfiguration scanner")
		fmt.Printf("    %-15s - %s\n", "trivy-image", "Container image scanner")
		fmt.Printf("    %-15s - %s\n", "trivy-full", "Full scanner (vuln + misconfig + secret)")
		fmt.Println()
		fmt.Println("  Preset scanners:")
		for _, name := range core.ListPresetScanners() {
			cfg := core.PresetScanners[name]
			fmt.Printf("    %-15s - %s\n", name, strings.Join(cfg.Capabilities, ", "))
		}
		fmt.Println()
		fmt.Println("Usage examples:")
		fmt.Println("  agent -tool semgrep -target ./src -push")
		fmt.Println("  agent -tools semgrep,gitleaks,trivy -target . -push")
		fmt.Println("  agent -daemon -config agent.yaml")
		fmt.Println()
		fmt.Println("Check tool installation:")
		fmt.Println("  agent -check-tools")
		fmt.Println("  agent -install-tools")
		os.Exit(0)
	}

	if *checkTools || *installTools {
		tools.CheckAndReport(context.Background(), os.Stdout, *installTools)
		os.Exit(0)
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Platform mode - run as managed platform agent
	if *platformMode {
		runPlatformAgent(ctx, &PlatformAgentConfig{
			APIBaseURL:      getEnvOrFlag(*apiURL, "API_URL"),
			BootstrapToken:  getEnvOrFlag(*bootstrapToken, "BOOTSTRAP_TOKEN"),
			Name:            getEnvOrFlag(*agentName, "AGENT_NAME"),
			Region:          getEnvOrFlag(*region, "REGION"),
			MaxConcurrent:   *maxConcurrent,
			CredentialsFile: *credentialsFile,
			Verbose:         *verbose,
			Scanners:        *tool,
			Tools:           *toolsFlag,
			// Executor enable flags
			ReconEnabled:    *enableRecon,
			VulnScanEnabled: *enableVulnScan,
			SecretsEnabled:  *enableSecrets,
			AssetsEnabled:   *enableAssets,
			PipelineEnabled: *enablePipeline,
		})
		return
	}

	// Load config or use CLI flags
	var cfg Config
	if *configPath != "" {
		if err := loadConfig(*configPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Build config from CLI flags
		cfg.Agent.Verbose = *verbose
		cfg.Agent.ScanInterval = 1 * time.Hour
		cfg.Agent.HeartbeatInterval = 1 * time.Minute
		cfg.Agent.EnableCommands = *enableCommands
		cfg.Agent.CommandPollInterval = 30 * time.Second

		// API config from flags or env
		cfg.API.BaseURL = getEnvOrFlag(*apiURL, "API_URL")
		cfg.API.APIKey = getEnvOrFlag(*apiKey, "API_KEY")
		cfg.API.AgentID = getEnvOrFlag(*agentID, "AGENT_ID")
		cfg.Targets = []string{*target}

		// Parse tools
		if *tool != "" {
			cfg.Scanners = []ScannerConfig{{Name: *tool, Enabled: true}}
		} else if *toolsFlag != "" {
			for t := range strings.SplitSeq(*toolsFlag, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					cfg.Scanners = append(cfg.Scanners, ScannerConfig{Name: t, Enabled: true})
				}
			}
		}

		// Retry queue config from flags or env
		cfg.RetryQueue.Enabled = *enableRetryQueue || getEnvOrFlag("", "RETRY_QUEUE") == "true"
		cfg.RetryQueue.Dir = getEnvOrFlag(*retryQueueDir, "RETRY_DIR")
		cfg.RetryQueue.Interval = retry.DefaultRetryInterval
		cfg.RetryQueue.MaxAttempts = retry.DefaultMaxAttempts
		cfg.RetryQueue.TTL = retry.DefaultTTL
	}

	// Override config file values with CLI flags and env vars (if specified)
	// Priority: CLI flag > env var > config file
	if url := getEnvOrFlag(*apiURL, "API_URL"); url != "" {
		cfg.API.BaseURL = url
	}
	if key := getEnvOrFlag(*apiKey, "API_KEY"); key != "" {
		cfg.API.APIKey = key
	}
	if aid := getEnvOrFlag(*agentID, "AGENT_ID"); aid != "" {
		cfg.API.AgentID = aid
	}
	if r := getEnvOrFlag(*region, "REGION"); r != "" {
		cfg.Agent.Region = r
	}
	if *target != "." || len(cfg.Targets) == 0 {
		cfg.Targets = []string{*target}
	}
	if *verbose {
		cfg.Agent.Verbose = true
	}
	if *enableCommands {
		cfg.Agent.EnableCommands = true
	}

	// Validate required fields
	if len(cfg.Scanners) == 0 && len(cfg.Collectors) == 0 && !cfg.Agent.EnableCommands {
		fmt.Fprintf(os.Stderr, "Error: No scanners or collectors configured.\n")
		fmt.Fprintf(os.Stderr, "Use -tool, -tools, or -config to specify what to run.\n")
		fmt.Fprintf(os.Stderr, "Use -list-tools to see available scanners.\n")
		os.Exit(1)
	}

	// Create API client (unless standalone)
	var apiClient *client.Client
	var pusher core.Pusher
	if !*standalone && cfg.API.BaseURL != "" && cfg.API.APIKey != "" {
		clientCfg := &client.Config{
			BaseURL: cfg.API.BaseURL,
			APIKey:  cfg.API.APIKey,
			AgentID: cfg.API.AgentID,
			Timeout: cfg.API.Timeout,
			Verbose: cfg.Agent.Verbose,

			// Retry queue configuration
			EnableRetryQueue: cfg.RetryQueue.Enabled,
			RetryQueueDir:    cfg.RetryQueue.Dir,
			RetryInterval:    cfg.RetryQueue.Interval,
			RetryMaxAttempts: cfg.RetryQueue.MaxAttempts,
			RetryTTL:         cfg.RetryQueue.TTL,
		}
		apiClient = client.New(clientCfg)
		pusher = apiClient

		// Test connection
		if err := pusher.TestConnection(ctx); err != nil {
			// Use SDK error helpers for better error messages
			if client.IsAuthenticationError(err) {
				fmt.Fprintf(os.Stderr, "Error: Invalid API key - authentication failed\n")
				os.Exit(1)
			} else if client.IsAuthorizationError(err) {
				fmt.Fprintf(os.Stderr, "Error: Access denied - check your API key permissions\n")
				os.Exit(1)
			} else if client.IsRateLimitError(err) {
				fmt.Printf("Warning: Rate limited - will retry with backoff\n")
			} else {
				fmt.Printf("Warning: Could not connect to OpenCTEM API: %v\n", err)
			}
		} else if cfg.Agent.Verbose {
			fmt.Println("✓ Connected to API")
			if cfg.API.AgentID != "" {
				fmt.Printf("  Agent ID: %s\n", cfg.API.AgentID)
			}
		}

		// Show retry queue status
		if cfg.RetryQueue.Enabled && cfg.Agent.Verbose {
			fmt.Println("Retry queue: enabled")
			if cfg.RetryQueue.Dir != "" {
				fmt.Printf("  Directory: %s\n", cfg.RetryQueue.Dir)
			} else {
				fmt.Println("  Directory: ~/.agent/retry-queue (default)")
			}
		}
	} else if *push && !*standalone {
		fmt.Fprintf(os.Stderr, "Warning: -push specified but no API credentials provided.\n")
		fmt.Fprintf(os.Stderr, "Use -api-url and -api-key, or set API_URL and API_KEY env vars.\n")
	}

	// Determine mode and run
	if *daemon {
		runDaemon(ctx, &cfg, apiClient, pusher)
	} else {
		runOnce(ctx, &cfg, apiClient, pusher, *push, *outputJSON, *outputFile, *createComments, *autoDetectCI, *failOn, *outputFormat)
	}
}

func getEnvOrFlag(flagVal, envName string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envName)
}

func loadConfig(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Expand environment variables in config
	expanded := os.ExpandEnv(string(data))

	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	return nil
}

func runOnce(ctx context.Context, cfg *Config, apiClient *client.Client, pusher core.Pusher, push, outputJSON bool, outputFile string, createComments, autoDetectCI bool, failOn, outputFormat string) {
	parsers := core.NewParserRegistry()
	// Register gitleaks parser for native JSON format (array of findings)
	parsers.Register(&gitleaks.Parser{})
	// Register semgrep parser for native JSON format
	parsers.Register(&semgrep.Parser{})
	// Register trivy parser for native JSON format
	parsers.Register(&trivy.Parser{})
	var allReports []*ctis.Report

	// Process retry queue at start (best effort)
	if apiClient != nil && cfg.RetryQueue.Enabled {
		if cfg.Agent.Verbose {
			fmt.Println("Processing pending retry queue items...")
		}
		// Use a short timeout for startup retry to avoid delaying the main scan too much
		startRetryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := apiClient.ProcessRetryQueueNow(startRetryCtx); err != nil && cfg.Agent.Verbose {
			fmt.Printf("Warning: Startup retry queue processing incomplete: %v\n", err)
		}
		cancel()
	}

	// Auto-detect CI environment
	var ciEnv gitenv.GitEnv
	if autoDetectCI {
		ciEnv = gitenv.DetectWithVerbose(cfg.Agent.Verbose)
		if ciEnv != nil && cfg.Agent.Verbose {
			fmt.Printf("[CI] Detected: %s\n", ciEnv.Provider())
			if ciEnv.ProjectName() != "" {
				fmt.Printf("[CI] Repository: %s\n", ciEnv.ProjectName())
			}
			if ciEnv.CommitBranch() != "" {
				fmt.Printf("[CI] Branch: %s\n", ciEnv.CommitBranch())
			}
			if ciEnv.MergeRequestID() != "" {
				fmt.Printf("[CI] MR/PR: #%s\n", ciEnv.MergeRequestID())
			}
		}
	}

	// Create scan handler
	var scanHandler handler.ScanHandler
	if push && pusher != nil {
		scanHandler = handler.NewRemoteHandler(&handler.RemoteHandlerConfig{
			Pusher:         pusher,
			Verbose:        cfg.Agent.Verbose,
			CreateComments: createComments,
			MaxComments:    10,
		})
	} else {
		scanHandler = handler.NewConsoleHandler(cfg.Agent.Verbose)
	}

	for _, scannerCfg := range cfg.Scanners {
		if !scannerCfg.Enabled {
			continue
		}

		// Get or create scanner
		scanner, err := getScanner(scannerCfg, cfg.Agent.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating scanner %s: %v\n", scannerCfg.Name, err)
			continue
		}

		// Check if installed
		installed, version, err := scanner.IsInstalled(ctx)
		if err != nil || !installed {
			fmt.Fprintf(os.Stderr, "Scanner %s not installed: %v\n", scanner.Name(), err)
			continue
		}

		if cfg.Agent.Verbose {
			fmt.Printf("[%s] Version: %s\n", scanner.Name(), version)
		}

		// Notify handler of scan start
		scanInfo, err := scanHandler.OnStart(ciEnv, scanner.Name(), "sast")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Handler OnStart failed: %v\n", scanner.Name(), err)
		}
		_ = scanInfo // May contain LastCommitSha for baseline

		// Scan each target
		for _, target := range cfg.Targets {
			fmt.Printf("[%s] Scanning %s...\n", scanner.Name(), target)

			// Determine scan strategy based on CI context
			scanCtx := &strategy.ScanContext{
				GitEnv:   ciEnv,
				RepoPath: target,
				Verbose:  cfg.Agent.Verbose,
			}
			scanStrategy, changedFiles := strategy.DetermineStrategy(scanCtx)

			if cfg.Agent.Verbose {
				fmt.Printf("[%s] Strategy: %s\n", scanner.Name(), scanStrategy.String())
				if scanStrategy == strategy.ChangedFileOnly {
					fmt.Printf("[%s] Changed files: %d\n", scanner.Name(), len(changedFiles))
				}
			}

			result, err := scanner.Scan(ctx, target, &core.ScanOptions{
				TargetDir: target,
				Verbose:   cfg.Agent.Verbose,
			})

			if err != nil {
				if hErr := scanHandler.OnError(err); hErr != nil {
					fmt.Fprintf(os.Stderr, "[%s] OnError handler failed: %v\n", scanner.Name(), hErr)
				}
				fmt.Fprintf(os.Stderr, "[%s] Scan failed: %v\n", scanner.Name(), err)
				continue
			}

			fmt.Printf("[%s] Completed in %dms\n", scanner.Name(), result.DurationMs)

			// Parse results
			parser := parsers.FindParser(result.RawOutput)
			if parser == nil {
				parser = parsers.Get("sarif")
			}

			if parser == nil {
				fmt.Fprintf(os.Stderr, "[%s] No parser available\n", scanner.Name())
				continue
			}

			// Detect asset - prefer CI environment info over local git
			var assetType ctis.AssetType
			var assetValue string
			var branch string
			var branchInfo *ctis.BranchInfo

			if ciEnv != nil && ciEnv.ProjectName() != "" {
				assetType = ctis.AssetTypeRepository
				// Use CanonicalRepoName for unique asset identification across providers
				// Format: github.com/owner/repo or gitlab.com/namespace/project
				assetValue = ciEnv.CanonicalRepoName()
				if assetValue == "" {
					// Fallback to ProjectName if CanonicalRepoName is not available
					assetValue = ciEnv.ProjectName()
				}
				branch = ciEnv.CommitBranch()

				// Build full BranchInfo from CI environment for branch-aware lifecycle
				branchInfo = buildBranchInfo(ciEnv)
			} else {
				assetType, assetValue = detectAsset(target)
				branch = git.DetectBranch(target)
			}

			if cfg.Agent.Verbose && assetValue != "" {
				fmt.Printf("[%s] Asset: %s (%s)\n", scanner.Name(), assetValue, assetType)
				if branch != "" {
					fmt.Printf("[%s] Branch: %s\n", scanner.Name(), branch)
				}
			}

			report, err := parser.Parse(ctx, result.RawOutput, &core.ParseOptions{
				ToolName:   scanner.Name(),
				AssetType:  assetType,
				AssetValue: assetValue,
				Branch:     branch,
				BranchInfo: branchInfo,
				BasePath:   target, // For reading snippets from source files
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Parse error: %v\n", scanner.Name(), err)
				continue
			}

			allReports = append(allReports, report)

			// Output summary (unless JSON mode)
			if !outputJSON {
				printSummary(scanner.Name(), report)
			}

			// Handle findings via handler (push + PR comments)
			if len(report.Findings) > 0 {
				err = scanHandler.HandleFindings(handler.HandleFindingsParams{
					Report:       report,
					Strategy:     scanStrategy,
					ChangedFiles: changedFiles,
					GitEnv:       ciEnv,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] HandleFindings failed: %v\n", scanner.Name(), err)
				}
			}
		}

		// Notify handler of scan completion
		if err := scanHandler.OnCompleted(); err != nil {
			fmt.Fprintf(os.Stderr, "OnCompleted handler failed: %v\n", err)
		}
	}

	// Process retry queue at end (best effort) to flush any failed pushes from this run
	if apiClient != nil && cfg.RetryQueue.Enabled {
		if cfg.Agent.Verbose {
			fmt.Println("Processing remaining retry queue items...")
		}
		// Use a reasonable timeout for shutdown retry
		// We use a new context here to ensure we try to flush even if main ctx is cancelled (best effort)
		endRetryCtx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		if err := apiClient.ProcessRetryQueueNow(endRetryCtx); err != nil && cfg.Agent.Verbose {
			fmt.Printf("Warning: Shutdown retry queue processing incomplete: %v\n", err)
		}
		cancel()
	}

	// Output based on format
	format := outputFormat
	if format == "" && outputJSON {
		format = "json"
	}

	if format != "" && len(allReports) > 0 {
		var data []byte
		var err error

		switch format {
		case "sarif":
			data, err = output.ToSARIF(allReports)
		case "json":
			data, err = output.ToJSON(allReports)
		default:
			// table format is default, already printed via printSummary
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
			os.Exit(1)
		}

		if data != nil {
			if outputFile != "" {
				if err := os.WriteFile(outputFile, data, 0600); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("Results written to %s\n", outputFile)
			} else {
				fmt.Println(string(data))
			}
		}
	}

	// Security gate: check if findings exceed threshold
	if failOn != "" && len(allReports) > 0 {
		// Fetch suppression rules from platform if connected
		var suppressions []client.SuppressionRule
		if apiClient != nil && push {
			rules, err := apiClient.GetSuppressions(ctx)
			if err != nil {
				if cfg.Agent.Verbose {
					fmt.Printf("[gate] Warning: could not fetch suppressions: %v\n", err)
				}
			} else {
				suppressions = rules
				if cfg.Agent.Verbose && len(rules) > 0 {
					fmt.Printf("[gate] Fetched %d suppression rules\n", len(rules))
				}
			}
		}

		var exitCode int
		if len(suppressions) > 0 {
			exitCode = gate.CheckAndPrintWithSuppressions(allReports, failOn, cfg.Agent.Verbose, suppressions)
		} else {
			exitCode = gate.CheckAndPrint(allReports, failOn, cfg.Agent.Verbose)
		}

		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}
}

func runDaemon(ctx context.Context, cfg *Config, apiClient *client.Client, pusher core.Pusher) {
	// Create agent
	agentName := cfg.Agent.Name
	if agentName == "" {
		hostname, _ := os.Hostname()
		agentName = fmt.Sprintf("agent-%s", hostname)
	}

	agent := core.NewBaseAgent(&core.BaseAgentConfig{
		Name:              agentName,
		Version:           Version,
		Region:            cfg.Agent.Region,
		ScanInterval:      cfg.Agent.ScanInterval,
		CollectInterval:   cfg.Agent.CollectInterval,
		HeartbeatInterval: cfg.Agent.HeartbeatInterval,
		Targets:           cfg.Targets,
		Verbose:           cfg.Agent.Verbose,
	}, pusher)

	// Add scanners
	for _, scannerCfg := range cfg.Scanners {
		if !scannerCfg.Enabled {
			continue
		}

		scanner, err := getScanner(scannerCfg, cfg.Agent.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating scanner %s: %v\n", scannerCfg.Name, err)
			continue
		}

		// Check if installed
		installed, _, err := scanner.IsInstalled(ctx)
		if err != nil || !installed {
			fmt.Fprintf(os.Stderr, "Warning: Scanner %s not installed, skipping\n", scannerCfg.Name)
			continue
		}

		if err := agent.AddScanner(scanner); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding scanner %s: %v\n", scannerCfg.Name, err)
			continue
		}

		fmt.Printf("  Added scanner: %s\n", scanner.Name())
	}

	// Add collectors
	for _, collectorCfg := range cfg.Collectors {
		if !collectorCfg.Enabled {
			continue
		}

		collector, err := getCollector(collectorCfg, cfg.Agent.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating collector %s: %v\n", collectorCfg.Name, err)
			continue
		}

		if err := agent.AddCollector(collector); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding collector %s: %v\n", collectorCfg.Name, err)
			continue
		}

		fmt.Printf("  Added collector: %s\n", collector.Name())
	}

	// Start retry worker if enabled
	if cfg.RetryQueue.Enabled && apiClient != nil {
		if err := apiClient.StartRetryWorker(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not start retry worker: %v\n", err)
		} else if cfg.Agent.Verbose {
			fmt.Println("  Retry worker: started")
		}
	}

	// Start command poller if enabled
	var poller *core.CommandPoller
	if cfg.Agent.EnableCommands && apiClient != nil {
		executor := core.NewDefaultCommandExecutor(pusher)

		// Add scanners to executor
		for _, scannerCfg := range cfg.Scanners {
			if !scannerCfg.Enabled {
				continue
			}
			scanner, _ := getScanner(scannerCfg, cfg.Agent.Verbose)
			if scanner != nil {
				executor.AddScanner(scanner)
			}
		}

		// Add collectors to executor
		for _, collectorCfg := range cfg.Collectors {
			if !collectorCfg.Enabled {
				continue
			}
			collector, _ := getCollector(collectorCfg, cfg.Agent.Verbose)
			if collector != nil {
				executor.AddCollector(collector)
			}
		}

		pollInterval := cfg.Agent.CommandPollInterval
		if pollInterval == 0 {
			pollInterval = 30 * time.Second
		}

		poller = core.NewCommandPoller(apiClient, executor, &core.CommandPollerConfig{
			PollInterval:  pollInterval,
			MaxConcurrent: 5,
			AllowedTypes:  []string{"scan", "collect", "health_check"},
			Verbose:       cfg.Agent.Verbose,
		})

		// Start poller in background
		go func() {
			if err := poller.Start(ctx); err != nil && err != context.Canceled {
				fmt.Fprintf(os.Stderr, "Command poller error: %v\n", err)
			}
		}()

		fmt.Printf("  Command polling: enabled (interval: %s)\n", pollInterval)
	}

	// Start agent
	if err := agent.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start agent: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n%s started\n", agentName)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Mode: %s\n", getMode(cfg))
	fmt.Printf("  Targets: %v\n", cfg.Targets)
	if cfg.Agent.ScanInterval > 0 && len(cfg.Targets) > 0 {
		fmt.Printf("  Scan interval: %s\n", cfg.Agent.ScanInterval)
	}
	fmt.Printf("  Heartbeat: %s\n", cfg.Agent.HeartbeatInterval)
	if cfg.API.AgentID != "" {
		fmt.Printf("  Agent ID: %s\n", cfg.API.AgentID)
	}
	if cfg.Agent.Region != "" {
		fmt.Printf("  Region: %s\n", cfg.Agent.Region)
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("\nPress Ctrl+C to stop.")

	// Wait for shutdown
	<-ctx.Done()

	// Stop poller
	if poller != nil {
		poller.Stop()
	}

	// Stop retry worker and show final stats
	if cfg.RetryQueue.Enabled && apiClient != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)

		// Show retry queue stats before shutdown
		if stats, err := apiClient.GetRetryQueueStats(shutdownCtx); err == nil && stats != nil {
			if stats.TotalItems > 0 {
				fmt.Printf("\nRetry queue stats:\n")
				fmt.Printf("  Total items: %d\n", stats.TotalItems)
				fmt.Printf("  Pending: %d\n", stats.PendingItems)
				fmt.Printf("  Processing: %d\n", stats.ProcessingItems)
				fmt.Printf("  Failed: %d\n", stats.FailedItems)
			}
		}

		// Process any remaining items before shutdown
		if cfg.Agent.Verbose {
			fmt.Println("Processing remaining retry queue items...")
		}
		if err := apiClient.ProcessRetryQueueNow(shutdownCtx); err != nil && cfg.Agent.Verbose {
			fmt.Printf("Warning: Error processing retry queue: %v\n", err)
		}

		// Stop the worker
		if err := apiClient.StopRetryWorker(shutdownCtx); err != nil && cfg.Agent.Verbose {
			fmt.Printf("Warning: Error stopping retry worker: %v\n", err)
		}

		shutdownCancel()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := agent.Stop(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "Shutdown error: %v\n", err)
	}

	// Close the API client (flushes any remaining data)
	if apiClient != nil {
		if err := apiClient.Close(); err != nil && cfg.Agent.Verbose {
			fmt.Printf("Warning: Error closing client: %v\n", err)
		}
	}

	fmt.Println("Agent stopped.")
}

func getMode(cfg *Config) string {
	if cfg.Agent.EnableCommands && len(cfg.Targets) > 0 {
		return "Hybrid (scheduled + server-controlled)"
	} else if cfg.Agent.EnableCommands {
		return "Server-Controlled"
	} else {
		return "Standalone"
	}
}

func getScanner(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
	// Try native scanners first (better support for dataflow, native JSON, etc.)
	switch cfg.Name {
	case "semgrep":
		scanner := scanners.Semgrep()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "gitleaks":
		scanner := scanners.Gitleaks()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		// Wrap gitleaks in adapter to implement core.Scanner
		return &gitleaksAdapter{scanner}, nil

	case "trivy", "trivy-fs":
		scanner := scanners.TrivyFS()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "trivy-config":
		scanner := scanners.TrivyConfig()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "trivy-image":
		scanner := scanners.TrivyImage()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "trivy-full":
		scanner := scanners.TrivyFull()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case "nuclei":
		scanner := scanners.Nuclei()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil
	}

	// Fall back to generic preset scanner
	scanner, err := core.NewPresetScanner(cfg.Name)
	if err == nil {
		scanner.SetVerbose(verbose)
		return scanner, nil
	}

	// Custom scanner
	if cfg.Binary != "" {
		return core.NewBaseScanner(&core.BaseScannerConfig{
			Name:        cfg.Name,
			Binary:      cfg.Binary,
			DefaultArgs: cfg.Args,
			Timeout:     30 * time.Minute,
			OKExitCodes: []int{0, 1},
			Verbose:     verbose,
		}), nil
	}

	return nil, fmt.Errorf("unknown scanner: %s (use -list-tools to see available)", cfg.Name)
}

// gitleaksAdapter wraps gitleaks.Scanner to implement core.Scanner interface.
type gitleaksAdapter struct {
	*scanners.GitleaksScanner
}

func (a *gitleaksAdapter) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return a.GitleaksScanner.GenericScan(ctx, target, opts)
}

func getCollector(cfg CollectorConfig, verbose bool) (core.Collector, error) {
	switch cfg.Name {
	case "github":
		return core.NewGitHubCollector(&core.GitHubCollectorConfig{
			Token:   cfg.Token,
			Owner:   cfg.Owner,
			Repo:    cfg.Repo,
			Verbose: verbose,
		}), nil
	case "webhook":
		return core.NewWebhookCollector(&core.WebhookCollectorConfig{
			Verbose: verbose,
		}), nil
	default:
		return nil, fmt.Errorf("unknown collector: %s", cfg.Name)
	}
}

func printSummary(scanner string, report *ctis.Report) {
	fmt.Printf("[%s] Found %d findings\n", scanner, len(report.Findings))

	// Count by severity
	severityCounts := make(map[ctis.Severity]int)
	for _, f := range report.Findings {
		severityCounts[f.Severity]++
	}

	if len(severityCounts) > 0 {
		fmt.Printf("  Severity breakdown:\n")
		for _, sev := range ctis.AllSeverities() {
			if count, ok := severityCounts[sev]; ok {
				fmt.Printf("    %-10s: %d\n", sev, count)
			}
		}
	}
}

// detectAsset detects the asset type and value from a target directory.
// It walks up the directory tree to find the git root and reads the remote URL.
func detectAsset(target string) (ctis.AssetType, string) {
	// Resolve to absolute path
	absPath, err := filepath.Abs(target)
	if err != nil {
		absPath = target
	}

	// Walk up directory tree to find git root
	gitRoot := git.FindRoot(absPath)
	if gitRoot != "" {
		gitConfigPath := filepath.Join(gitRoot, ".git", "config")
		if remoteURL := git.ReadRemoteURL(gitConfigPath); remoteURL != "" {
			return ctis.AssetTypeRepository, git.NormalizeURL(remoteURL)
		}
		// Git repo found but no remote - use git root directory name
		return ctis.AssetTypeRepository, filepath.Base(gitRoot)
	}

	// No git repo found - use target directory name
	dirName := filepath.Base(absPath)
	return ctis.AssetTypeRepository, dirName
}

// buildBranchInfo constructs a BranchInfo from CI environment for branch-aware finding lifecycle.
// This enables auto-resolve (only on default branch) and feature branch expiry features.
func buildBranchInfo(ciEnv gitenv.GitEnv) *ctis.BranchInfo {
	if ciEnv == nil {
		return nil
	}

	branchName := ciEnv.CommitBranch()
	if branchName == "" {
		return nil
	}

	// Use CanonicalRepoName for consistent asset identification across providers.
	// Format: {domain}/{owner}/{repo} (e.g., "github.com/org/repo")
	repoURL := ciEnv.CanonicalRepoName()
	if repoURL == "" {
		// Fallback to ProjectURL if CanonicalRepoName is not available
		repoURL = ciEnv.ProjectURL()
	}

	info := &ctis.BranchInfo{
		Name:          branchName,
		CommitSHA:     ciEnv.CommitSha(),
		RepositoryURL: repoURL,
	}

	// Determine if this is the default branch
	defaultBranch := ciEnv.DefaultBranch()
	if defaultBranch != "" {
		info.IsDefaultBranch = (branchName == defaultBranch)
	}

	// If this is a PR/MR, add PR context
	// Validate mrID as numeric to prevent URL injection attacks
	if mrID := ciEnv.MergeRequestID(); mrID != "" {
		if prNum, err := strconv.Atoi(mrID); err == nil && prNum > 0 {
			info.PullRequestNumber = prNum
			info.BaseBranch = ciEnv.TargetBranch()

			// Build PR URL using validated numeric ID only
			validatedID := strconv.Itoa(prNum)
			projectURL := ciEnv.ProjectURL()
			if projectURL != "" {
				if ciEnv.Provider() == gitenv.ProviderGitHub {
					info.PullRequestURL = projectURL + "/pull/" + validatedID
				} else if ciEnv.Provider() == gitenv.ProviderGitLab {
					info.PullRequestURL = projectURL + "/-/merge_requests/" + validatedID
				}
			}
		}
	}

	return info
}
