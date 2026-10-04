// OpenCTEM Sensor - Universal Security Scanner/Collector Sensor
//
// This sensor supports multiple deployment modes:
//
//  1. ONE-SHOT MODE (CI/CD):
//     openctemio-sensor -tool semgrep -target ./src -push
//
//  2. DAEMON MODE (Continuous):
//     openctemio-sensor -daemon -config sensor.yaml
//
//  3. SERVER-CONTROLLED MODE:
//     openctemio-sensor -daemon -enable-commands -config sensor.yaml
//
// Settings from before the agent -> sensor rename (AGENT_* environment
// variables, -agent-id, the agent: config block) keep working: the SDK
// (pkg/sensorkit) migrates the environment and flags, settings_migration.go
// the config file.
//
// The daemon is the SDK's sensor runtime (sdk-go pkg/sensorkit): this binary
// adds its tools, content and executors; the SDK connects, heartbeats, polls,
// delivers results, renews the key and drains.
//
// For more details, see: docs/architecture/deployment-modes.md
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/gitenv"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sdk-go/pkg/useragent"
	"github.com/openctemio/sensor/internal/connector/tenablesc"
	"github.com/openctemio/sensor/internal/content"
	sensorexec "github.com/openctemio/sensor/internal/executor"
	"github.com/openctemio/sensor/internal/gate"
	"github.com/openctemio/sensor/internal/git"
	"github.com/openctemio/sensor/internal/handler"
	"github.com/openctemio/sensor/internal/output"
	"github.com/openctemio/sensor/internal/recon"
	"github.com/openctemio/sensor/internal/scanners"
	"github.com/openctemio/sensor/internal/scanners/betterleaks"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/scanners/semgrep"
	"github.com/openctemio/sensor/internal/scanners/trivy"
	"github.com/openctemio/sensor/internal/strategy"
	"github.com/openctemio/sensor/internal/tools"
)

const appName = "OpenCTEM Sensor"

// Version is set via ldflags at build time: -ldflags="-X main.Version=..."
// Example: go build -ldflags="-X main.Version=v1.0.0" .
// A release build gets its tag (GoReleaser, docker-publish.yml), `make` a dev
// version "<highest tag>-dev+<sha>" (openctemio/openctem RFC-037). A plain
// `go build` says "dev", never a release number it is not.
var Version = "dev"

// SensorSettings is the sensor: block of the configuration file (agent:
// before the rename; still read, see migrateConfigFile).
type SensorSettings struct {
	Name              string        `yaml:"name"`
	Region            string        `yaml:"region"` // Deployment region (e.g., "us-east-1", "ap-southeast-1")
	ScanInterval      time.Duration `yaml:"scan_interval"`
	CollectInterval   time.Duration `yaml:"collect_interval"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	Verbose           bool          `yaml:"verbose"`

	// Server control
	EnableCommands      bool          `yaml:"enable_commands"`
	CommandPollInterval time.Duration `yaml:"command_poll_interval"`
	// DisableDoorbell turns off the heartbeat doorbell: the daemon then polls
	// for commands every command_poll_interval whatever the platform says.
	DisableDoorbell bool `yaml:"disable_doorbell"`
	// MaxJobs caps the commands the daemon runs at once (1-100; 0 or unset:
	// no cap, the slots follow the resources; -max-concurrent and
	// SENSOR_MAX_JOBS override it, see sensorkit.ResolveMaxJobs).
	MaxJobs int `yaml:"max_jobs"`
}

// daemonOptions are daemon settings that only exist as flags.
type daemonOptions struct {
	protocol   string
	standalone bool
	outbox     sensorkit.OutboxOverrides
	// keyAutoRenew / noKeyAutoRenew force API-key renewal on / off
	// (-key-autorenew, -key-autorenew=false); with neither, sensorkit
	// decides (PLATFORM_KEY_AUTORENEW, else on when the state directory
	// persists). credentialsFile overrides where the renewed key is kept.
	keyAutoRenew    bool
	noKeyAutoRenew  bool
	credentialsFile string
	// tools is the -tools / SENSOR_TOOLS allowlist the scanners came from
	// (empty: they came from elsewhere, no allowlist).
	tools []string
	// localPolicy is the -local-policy file (else SENSOR_LOCAL_POLICY, else
	// /etc/openctem/sensor-policy.yaml when it exists).
	localPolicy string
	// tenableSCConfig is the -tenable-sc-config file (else
	// SENSOR_TENABLE_SC_CONFIG, else the TENABLE_SC_* environment, else
	// /etc/openctem/connectors/tenable-sc.yaml when it exists).
	tenableSCConfig string
}

// Config represents the sensor configuration.
type Config struct {
	// Sensor settings
	Sensor SensorSettings `yaml:"sensor"`

	// API configuration (uses 'server' in yaml for backward compatibility)
	API struct {
		BaseURL  string        `yaml:"base_url"`
		APIKey   string        `yaml:"api_key"`
		SensorID string        `yaml:"sensor_id"` // For tenant tracking (agent_id before the rename; still read)
		Timeout  time.Duration `yaml:"timeout"`
		// Sensor protocol: auto (default; v2 for everything the platform
		// offers, v1 for the rest), v1 or v2 (SENSOR_PROTOCOL).
		Protocol string `yaml:"protocol"`
	} `yaml:"server"`

	// Outbox: undelivered results kept on disk (sdk-go pkg/sensorkit).
	Outbox sensorkit.OutboxSettings `yaml:"outbox"`

	// RetryQueue is the pre-outbox setting. enabled: true turns the outbox on
	// (also for one-shot runs) and dir is imported from once.
	RetryQueue struct {
		Enabled     bool          `yaml:"enabled"`
		Dir         string        `yaml:"dir"`
		Interval    time.Duration `yaml:"interval"`     // ignored
		MaxAttempts int           `yaml:"max_attempts"` // ignored
		TTL         time.Duration `yaml:"ttl"`          // used as the outbox max age when outbox.max_age is unset
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
	// Every request names this binary and its version next to the SDK's
	// (User-Agent "openctemio-sensor/<version> openctem-sdk-go/<version>"),
	// which the platform records per sensor to show who still speaks the
	// deprecated protocol v1 (api RFC-029 §5.3).
	useragent.SetProduct("openctemio-sensor", Version)

	// CLI flags
	configPath := flag.String("config", "", "Path to config file")
	tool := flag.String("tool", "", "Tool to run (semgrep, trivy-fs, betterleaks, etc.)")
	toolsFlag := flag.String("tools", "", "Comma-separated list of tools (or SENSOR_TOOLS env)")
	target := flag.String("target", ".", "Target directory to scan")
	apiURL := flag.String("api-url", "", "API base URL (or API_URL env)")
	apiKey := flag.String("api-key", "", "API key for authentication (or API_KEY env)")
	sensorID := flag.String("sensor-id", "", "Sensor ID for tracking (or SENSOR_ID env)")
	_ = flag.String("agent-id", "", "Deprecated: use -sensor-id (still applied, with a warning)")
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

	// Results delivery
	protocolFlag := flag.String("protocol", "", "Sensor protocol: auto (default; v2 for everything the platform offers, v1 for the rest), v1 or v2 (or SENSOR_PROTOCOL env)")
	outboxDir := flag.String("outbox-dir", "", "Outbox directory for undelivered results (default "+sensorkit.DefaultOutboxDir+", or SENSOR_OUTBOX_DIR env)")
	outboxStatus := flag.Bool("outbox-status", false, "Print the outbox state (pending results, dead letters) and exit")
	outboxRequeue := flag.Bool("outbox-requeue-dead", false, "Move the outbox's dead letters back to pending (after fixing the cause) and exit")
	enableRetryQueue := flag.Bool("retry-queue", false, "Deprecated: turns the outbox on for a one-shot run (or RETRY_QUEUE=true)")
	retryQueueDir := flag.String("retry-dir", "", "Deprecated: an old retry-queue directory to import results from once (or RETRY_DIR env)")

	// Region flag
	region := flag.String("region", "", "Deployment region (or REGION, AWS_REGION env)")

	// Removed platform mode (/api/v1/platform/register|lease|poll, which the
	// API no longer serves). The flags stay defined so an old command line
	// gets an explanation instead of "flag provided but not defined".
	platformMode := flag.Bool("platform", false, "Removed: platform mode is gone; use -daemon -enable-commands")
	for _, name := range removedPlatformFlags {
		flag.String(name, "", "Removed with platform mode; ignored")
	}
	sensorName := flag.String("name", "", "Sensor name, or SENSOR_NAME env (auto-generated if not specified)")
	maxConcurrent := flag.Int("max-concurrent", 0, "Cap on concurrent jobs, 1-100 (or "+sensorkit.EnvMaxJobs+" env, sensor.max_jobs in the config file). Default: no cap (slots follow the CPU, memory and tool costs)")
	credentialsFile := flag.String("credentials", "", "Path to the credentials file the renewed API key is kept in (daemon default: sensor-credentials.json in SENSOR_STATE_DIR, /var/lib/openctem/state, where a ~/.openctem one is moved)")

	for _, name := range removedPlatformBoolFlags {
		flag.Bool(name, false, "Removed with platform mode; ignored")
	}
	keyAutoRenew := flag.Bool("key-autorenew", false, "Renew the sensor API key before expiry and when the platform asks; -key-autorenew=false turns it off (or PLATFORM_KEY_AUTORENEW=true|false). Daemon default: on when the state directory (SENSOR_STATE_DIR, /var/lib/openctem/state) is on a persistent volume, else off. The renewed key is kept in the -credentials file")
	disableDoorbell := flag.Bool("disable-doorbell", false, "Daemon: ignore the heartbeat doorbell and poll for commands on a fixed interval")
	localPolicy := flag.String("local-policy", "", "Daemon: the sensor-local policy file the network owner wrote, read-only (or "+core.EnvLocalPolicy+" env; default "+core.DefaultLocalPolicyPath+" when it exists). Jobs outside it are refused whatever the platform sends; a policy that cannot be loaded stops the sensor")
	tenableSCConfig := flag.String("tenable-sc-config", "", "Daemon: the Tenable.sc connector config the network owner wrote, read-only (or "+tenablesc.EnvConfig+" env, or the TENABLE_SC_* env shorthand; default "+tenablesc.DefaultConfigPath+" when it exists). The Tenable API keys stay on this sensor; a config that cannot be loaded stops the sensor")
	contentStatus := flag.Bool("content-status", false, "Print the managed scanner content (trivy DB, nuclei templates, semgrep rules) and exit")
	contentRefresh := flag.Bool("content-refresh", false, "Refresh the managed scanner content now, print it and exit (-content-force downloads even unchanged content)")
	contentForce := flag.Bool("content-force", false, "With -content-refresh: download even when the source offers the installed version")

	flag.Parse()
	// AGENT_* environment variables and -agent-id: applied to their new
	// names with a warning; both names set to different values exits 2.
	if err := sensorkit.MigrateSettings(flag.CommandLine); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("%s version %s\n", appName, Version)
		os.Exit(0)
	}

	if *listTools {
		fmt.Println("Available scanners:")
		fmt.Println()
		fmt.Println("  Native scanners (recommended), with the state of their binary here:")
		for _, n := range nativeScanners {
			fmt.Printf("    %-15s - %-45s [%s]\n", n.name, n.description, probeTool(n.name).Describe())
		}
		fmt.Println()
		fmt.Println("  Preset scanners:")
		for _, name := range core.ListPresetScanners() {
			cfg := core.PresetScanners[name]
			fmt.Printf("    %-15s - %s\n", name, strings.Join(cfg.Capabilities, ", "))
		}
		fmt.Println()
		fmt.Println("Usage examples:")
		fmt.Println("  openctemio-sensor -tool semgrep -target ./src -push")
		fmt.Println("  openctemio-sensor -tools semgrep,betterleaks,trivy -target . -push")
		fmt.Println("  openctemio-sensor -daemon -config sensor.yaml")
		fmt.Println()
		fmt.Println("Check tool installation:")
		fmt.Println("  openctemio-sensor -check-tools")
		fmt.Println("  openctemio-sensor -install-tools")
		os.Exit(0)
	}

	if *contentStatus || *contentRefresh {
		os.Exit(runContentCommand(getEnvOrFlag(*toolsFlag, "SENSOR_TOOLS"), *contentRefresh, *contentForce, *verbose))
	}

	if *checkTools || *installTools {
		tools.CheckAndReport(context.Background(), os.Stdout, *installTools)
		os.Exit(0)
	}

	// The first SIGINT/SIGTERM cancels ctx: a daemon drains (running scans
	// get a grace period, then go back to the platform); a second one exits
	// at once (130).
	ctx, cancel := sensorkit.SignalContext(context.Background(), os.Stdout)
	defer cancel()

	maxJobsFlag := sensorkit.MaxJobsSetting{Source: "-max-concurrent", Value: *maxConcurrent, Set: flagWasSet(flag.CommandLine, "max-concurrent")}

	if *platformMode {
		fmt.Fprint(os.Stderr, platformModeRemovedMessage)
		os.Exit(2)
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
		cfg.Sensor.Verbose = *verbose
		cfg.Sensor.ScanInterval = 1 * time.Hour
		cfg.Sensor.HeartbeatInterval = 1 * time.Minute
		cfg.Sensor.EnableCommands = *enableCommands
		cfg.Sensor.CommandPollInterval = 30 * time.Second

		// API config from flags or env
		cfg.API.BaseURL = getEnvOrFlag(*apiURL, "API_URL")
		cfg.API.APIKey = getEnvOrFlag(*apiKey, "API_KEY")
		cfg.API.SensorID = getEnvOrFlag(*sensorID, "SENSOR_ID")

	}

	// Override config file values with CLI flags and env vars (if specified)
	// Priority: CLI flag > env var > config file
	if url := getEnvOrFlag(*apiURL, "API_URL"); url != "" {
		cfg.API.BaseURL = url
	}
	if key := getEnvOrFlag(*apiKey, "API_KEY"); key != "" {
		cfg.API.APIKey = key
	}
	if aid := getEnvOrFlag(*sensorID, "SENSOR_ID"); aid != "" {
		cfg.API.SensorID = aid
	}
	if r := getEnvOrFlag(*region, "REGION"); r != "" {
		cfg.Sensor.Region = r
	}
	// -name / SENSOR_NAME: only platform mode read it before, so the
	// daemon silently ignored it and named itself sensor-<hostname>.
	if n := getEnvOrFlag(*sensorName, "SENSOR_NAME"); n != "" {
		cfg.Sensor.Name = n
	}
	if *verbose {
		cfg.Sensor.Verbose = true
	}
	if *enableCommands {
		cfg.Sensor.EnableCommands = true
	}
	if *disableDoorbell {
		cfg.Sensor.DisableDoorbell = true
	}
	maxJobs, err := sensorkit.ResolveMaxJobs(maxJobsFlag,
		sensorkit.MaxJobsSetting{Source: "sensor.max_jobs", Value: cfg.Sensor.MaxJobs, Set: cfg.Sensor.MaxJobs != 0})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	cfg.Sensor.MaxJobs = maxJobs
	// Outbox inspection needs no platform, scanner or credentials.
	if *outboxStatus || *outboxRequeue {
		plan, err := sensorkit.ResolveOutbox(cfg.Outbox, sensorkit.OutboxOverrides{Dir: *outboxDir}, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(sensorkit.OutboxCommand(plan, *outboxRequeue, os.Stdout, os.Stderr))
	}
	cfg.Targets = resolveTargets(cfg.Targets, *target, flagWasSet(flag.CommandLine, "target"),
		*daemon && cfg.Sensor.EnableCommands)

	// A server-controlled daemon is useless without the platform: say so
	// instead of starting a daemon that never polls.
	if *daemon && !*standalone && cfg.Sensor.EnableCommands {
		if err := sensorkit.CheckCredentials(cfg.API.BaseURL, cfg.API.APIKey, daemonCredentialsHelp); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	}

	// The scanners: the config file's, -tool, the optional SENSOR_TOOLS /
	// -tools allowlist, or (a server-controlled daemon given none) every
	// native scanner installed here. The platform learns them from the
	// heartbeat; nobody declares them there.
	scannerList, toolSource := selectScanners(ctx, toolSelection{
		configured:     cfg.Scanners,
		tool:           *tool,
		toolList:       getEnvOrFlag(*toolsFlag, "SENSOR_TOOLS"),
		daemonCommands: *daemon && cfg.Sensor.EnableCommands,
	}, scannerInstalled)
	cfg.Scanners = scannerList
	if toolSource == toolSourceDetected {
		if len(cfg.Scanners) == 0 {
			fmt.Fprintf(os.Stderr, "Warning: no scanner found here (looked for %s); the platform will send this sensor no scans\n", strings.Join(autoDetectTools, ", "))
		} else {
			fmt.Printf("  Tools: %s (detected; set SENSOR_TOOLS to limit)\n", strings.Join(scannerNames(cfg.Scanners), ", "))
		}
	}

	// Validate required fields
	if len(cfg.Scanners) == 0 && len(cfg.Collectors) == 0 && !cfg.Sensor.EnableCommands {
		fmt.Fprintf(os.Stderr, "Error: No scanners or collectors configured.\n")
		fmt.Fprintf(os.Stderr, "Use -tool, -tools, or -config to specify what to run.\n")
		fmt.Fprintf(os.Stderr, "Use -list-tools to see available scanners.\n")
		os.Exit(1)
	}

	// Scan-target switches the SDK would otherwise misread silently: a value
	// it does not recognize (SENSOR_ALLOW_PRIVATE_TARGETS=true) or the sensor
	// and pre-rename names set to different values. Refuse to start rather
	// than refuse every private target later.
	if err := core.CheckEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Results delivery: protocol and outbox (sdk-go pkg/sensorkit).
	protocol, err := sensorkit.ResolveProtocol(*protocolFlag, cfg.API.Protocol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if cfg.Outbox.MaxAge == 0 {
		cfg.Outbox.MaxAge = cfg.RetryQueue.TTL
	}
	outboxOverrides := sensorkit.OutboxOverrides{
		Dir:              *outboxDir,
		LegacyRetryQueue: *enableRetryQueue || cfg.RetryQueue.Enabled,
		LegacyRetryDir:   firstNonEmpty(*retryQueueDir, cfg.RetryQueue.Dir),
	}

	// Determine mode and run
	if *daemon {
		if *push && !*standalone && (cfg.API.BaseURL == "" || cfg.API.APIKey == "") {
			warnPushWithoutCredentials()
		}
		var allowlist []string
		if toolSource == toolSourceList {
			allowlist = scannerNames(cfg.Scanners)
		}
		runDaemon(ctx, &cfg, daemonOptions{
			protocol:        protocol,
			standalone:      *standalone,
			outbox:          outboxOverrides,
			keyAutoRenew:    *keyAutoRenew,
			noKeyAutoRenew:  flagWasSet(flag.CommandLine, "key-autorenew") && !*keyAutoRenew,
			credentialsFile: *credentialsFile,
			tools:           allowlist,
			localPolicy:     *localPolicy,
			tenableSCConfig: *tenableSCConfig,
		})
		return
	}

	obPlan, err := sensorkit.ResolveOutbox(cfg.Outbox, outboxOverrides, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Create API client (unless standalone)
	var apiClient *client.Client
	var pusher core.Pusher
	if !*standalone && cfg.API.BaseURL != "" && cfg.API.APIKey != "" {
		apiClient = client.New(&client.Config{
			BaseURL:  cfg.API.BaseURL,
			APIKey:   cfg.API.APIKey,
			SensorID: cfg.API.SensorID,
			Timeout:  cfg.API.Timeout,
			Verbose:  cfg.Sensor.Verbose,
			Protocol: protocol,
		})
		pusher = apiClient

		// The outbox is off for a one-shot run unless asked for
		// (SENSOR_OUTBOX=on, -retry-queue).
		if err := sensorkit.EnableOutbox(apiClient, obPlan, cfg.Sensor.Verbose, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "Error: outbox: %v\n", err)
			os.Exit(1)
		}
		if cfg.Sensor.Verbose {
			fmt.Printf("  Sensor protocol: %s\n", protocol)
		}

		if err := pusher.TestConnection(ctx); err != nil {
			// Use SDK error helpers for better error messages
			if core.AuthFailureStatus(err) != 0 {
				// A one-shot (CI) run fails fast with a distinct code.
				fmt.Fprintf(os.Stderr, "Error: %s (exit code %d)\n", core.AuthFailureAdvice(err, apiClient.APIKeyHint()), sensorkit.ExitAuthRejected)
				os.Exit(sensorkit.ExitAuthRejected)
			} else if client.IsRateLimitError(err) {
				fmt.Printf("Warning: Rate limited - will retry with backoff\n")
			} else {
				fmt.Printf("Warning: Could not connect to OpenCTEM API: %v\n", err)
			}
		} else if cfg.Sensor.Verbose {
			fmt.Println("✓ Connected to API")
			if cfg.API.SensorID != "" {
				fmt.Printf("  Sensor ID: %s\n", cfg.API.SensorID)
			}
		}
	} else if *push && !*standalone {
		warnPushWithoutCredentials()
	}

	runOnce(ctx, &cfg, apiClient, pusher, *push, *outputJSON, *outputFile, *createComments, *autoDetectCI, *failOn, *outputFormat)
}

// warnPushWithoutCredentials says that -push has nowhere to push to.
func warnPushWithoutCredentials() {
	fmt.Fprintf(os.Stderr, "Warning: -push specified but no API credentials provided.\n")
	fmt.Fprintf(os.Stderr, "Use -api-url and -api-key, or set API_URL and API_KEY env vars.\n")
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// resolveTargets decides what the sensor scans on its own (one-shot run, or a
// daemon's scheduled scans). An explicit -target wins, then the config file's
// targets. Otherwise a one-shot run or a standalone daemon scans the current
// directory, but a server-controlled daemon (-daemon -enable-commands) scans
// nothing by itself: it runs only what the server dispatches. Defaulting it to
// "." made every such daemon scan its working directory with every configured
// scanner at start and hourly — nuclei included, which registers with an
// external interaction server.
func resolveTargets(configured []string, flagTarget string, flagSet, serverControlled bool) []string {
	switch {
	case flagSet:
		return []string{flagTarget}
	case len(configured) > 0:
		return configured
	case serverControlled:
		return nil
	default:
		return []string{flagTarget}
	}
}

// flagWasSet reports whether the named flag was given on the command line.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
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

	return migrateConfigFile([]byte(expanded), cfg)
}

func runOnce(ctx context.Context, cfg *Config, apiClient *client.Client, pusher core.Pusher, push, outputJSON bool, outputFile string, createComments, autoDetectCI bool, failOn, outputFormat string) {
	// Content a daemon on this host installed (internal/content) is used
	// as is; a one-shot run never downloads content itself. Reports carry
	// the content their scan used (tool.properties.content).
	contentMgr, err := newContentManager(cfg.Scanners, cfg.Sensor.Verbose, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	parsers := newParserRegistryWith(contentMgr)
	var allReports []*ctis.Report
	// scanFailures counts scanners that failed to run or whose output could
	// not be parsed. The security gate uses this to fail CLOSED: a broken
	// scan must not produce a green build just because it yielded no reports.
	scanFailures := 0

	// Auto-detect CI environment
	var ciEnv gitenv.GitEnv
	if autoDetectCI {
		ciEnv = gitenv.DetectWithVerbose(cfg.Sensor.Verbose)
		if ciEnv != nil && cfg.Sensor.Verbose {
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

	// PR-scoped gating (RFC-008 Phase 3): in a PR/MR context with a server
	// connection, classify findings as new vs. pre-existing on the base branch so
	// the gate and inline comments focus on what the PR introduces, not
	// pre-existing tech debt. newFingerprints accumulates the new set across
	// scanners; it stays nil when not PR-scoped, preserving the prior behavior
	// (gate/comment on all findings).
	var newFingerprints map[string]bool
	prScopedGate := apiClient != nil && push && ciEnv != nil &&
		ciEnv.MergeRequestID() != "" && ciEnv.TargetBranch() != ""
	if prScopedGate {
		newFingerprints = map[string]bool{}
		if cfg.Sensor.Verbose {
			fmt.Printf("[baseline] PR-scoped gate enabled (base branch %q)\n", ciEnv.TargetBranch())
		}
	}

	// Create scan handler
	var scanHandler handler.ScanHandler
	if push && pusher != nil {
		scanHandler = handler.NewRemoteHandler(&handler.RemoteHandlerConfig{
			Pusher:         pusher,
			Verbose:        cfg.Sensor.Verbose,
			CreateComments: createComments,
			MaxComments:    10,
		})
	} else {
		scanHandler = handler.NewConsoleHandler(cfg.Sensor.Verbose)
	}

	for _, scannerCfg := range cfg.Scanners {
		if !scannerCfg.Enabled {
			continue
		}

		// Get or create scanner
		scanner, err := getScanner(scannerCfg, cfg.Sensor.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating scanner %s: %v\n", scannerCfg.Name, err)
			continue
		}
		scanner = contentMgr.WrapScanner(scanner)

		// Check if installed
		installed, version, err := scanner.IsInstalled(ctx)
		if err != nil || !installed {
			fmt.Fprintf(os.Stderr, "Scanner %s skipped: %s\n", scanner.Name(), unavailableReason(ctx, scannerCfg, err))
			continue
		}

		if cfg.Sensor.Verbose {
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
				Verbose:  cfg.Sensor.Verbose,
			}
			scanStrategy, changedFiles := strategy.DetermineStrategy(scanCtx)

			if cfg.Sensor.Verbose {
				fmt.Printf("[%s] Strategy: %s\n", scanner.Name(), scanStrategy.String())
				if scanStrategy == strategy.ChangedFileOnly {
					fmt.Printf("[%s] Changed files: %d\n", scanner.Name(), len(changedFiles))
				}
			}

			result, err := scanner.Scan(ctx, target, &core.ScanOptions{
				TargetDir: target,
				Verbose:   cfg.Sensor.Verbose,
			})

			if err != nil {
				if hErr := scanHandler.OnError(err); hErr != nil {
					fmt.Fprintf(os.Stderr, "[%s] OnError handler failed: %v\n", scanner.Name(), hErr)
				}
				fmt.Fprintf(os.Stderr, "[%s] Scan failed: %v\n", scanner.Name(), err)
				scanFailures++
				continue
			}

			fmt.Printf("[%s] Completed in %dms\n", scanner.Name(), result.DurationMs)

			// Parse results. No output means the scanner found nothing;
			// output no parser recognizes is a failure, never "0 findings".
			if len(bytes.TrimSpace(result.RawOutput)) == 0 {
				fmt.Printf("[%s] No output: nothing found\n", scanner.Name())
				continue
			}
			parser, err := parsers.ForScanner(scanner.Name(), result.RawOutput)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] %v\n", scanner.Name(), err)
				scanFailures++
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
				// Build branch context for a manual (non-CI) scan so branch-aware
				// lifecycle — including server-side auto-resolve of no-longer-seen
				// findings — can work outside CI. IsDefaultBranch fails safe: it is
				// only true when we positively matched the repo's default branch.
				if branch != "" {
					def := git.DetectDefaultBranch(target)
					branchInfo = &ctis.BranchInfo{
						Name:            branch,
						IsDefaultBranch: def != "" && branch == def,
					}
				}
			}

			if cfg.Sensor.Verbose && assetValue != "" {
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
				scanFailures++
				continue
			}

			// Declare full coverage only for a genuine whole-repo scan on the
			// default branch — the two signals the server requires before it will
			// auto-resolve findings no longer reported. The repo-root guard stops a
			// subdirectory scan from mass-resolving findings it never covered; the
			// default-branch gate is also enforced server-side. Anything else stays
			// empty, which disables auto-resolve (fail safe).
			if branchInfo != nil && branchInfo.IsDefaultBranch && git.IsRepoRoot(target) {
				report.Metadata.CoverageType = "full"
			}

			allReports = append(allReports, report)

			// Output summary (unless JSON mode)
			if !outputJSON {
				printSummary(scanner.Name(), report)
			}

			// Handle findings via handler (push + PR comments)
			if len(report.Findings) > 0 {
				// In a PR context, learn which of this report's findings are new vs.
				// the base branch so comments focus on what the PR introduces.
				var reportNew map[string]bool
				if prScopedGate {
					reportNew = baselineNewSet(ctx, apiClient, assetValue, ciEnv.TargetBranch(),
						report, newFingerprints, cfg.Sensor.Verbose)
				}

				err = scanHandler.HandleFindings(handler.HandleFindingsParams{
					Report:          report,
					Strategy:        scanStrategy,
					ChangedFiles:    changedFiles,
					GitEnv:          ciEnv,
					NewFingerprints: reportNew,
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

	// With an outbox (SENSOR_OUTBOX=on), deliver what is queued before
	// exiting; what cannot be delivered stays on disk for the next run.
	if apiClient != nil {
		sensorkit.FlushOutbox(apiClient, time.Minute, os.Stderr)
		_ = apiClient.Close()
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

	// Security gate: check if findings exceed threshold.
	// Fail CLOSED when the gate is requested but the scan could not produce a
	// trustworthy verdict — any scanner that failed to run/parse, or zero
	// successful reports, must block the build rather than pass silently.
	if failOn != "" && (scanFailures > 0 || len(allReports) == 0) {
		fmt.Fprintf(os.Stderr,
			"\n❌ Security gate ERROR: cannot evaluate threshold %q — %d scanner failure(s), %d report(s) produced. Failing closed.\n",
			failOn, scanFailures, len(allReports))
		os.Exit(gate.ExitCodeError)
	}

	if failOn != "" && len(allReports) > 0 {
		// PR-scoped gate: judge only the findings the PR introduces. Pre-existing
		// findings open on the base branch are not gated (the PR author didn't add
		// them); risk-override (KEV/exploit) and severity rules still apply to the
		// new set. With no baseline this is a no-op and the gate sees all findings.
		gateReports := allReports
		if prScopedGate {
			before := countFindings(allReports)
			gateReports = gate.FilterNewFindings(allReports, newFingerprints)
			if dropped := before - countFindings(gateReports); dropped > 0 {
				fmt.Printf("[gate] PR-scoped: gating on %d new finding(s); %d pre-existing on %q not gated\n",
					countFindings(gateReports), dropped, ciEnv.TargetBranch())
			}
		}

		// Fetch suppression rules from platform if connected
		var suppressions []client.SuppressionRule
		if apiClient != nil && push {
			rules, err := apiClient.GetSuppressions(ctx)
			if err != nil {
				if cfg.Sensor.Verbose {
					fmt.Printf("[gate] Warning: could not fetch suppressions: %v\n", err)
				}
			} else {
				suppressions = rules
				if cfg.Sensor.Verbose && len(rules) > 0 {
					fmt.Printf("[gate] Fetched %d suppression rules\n", len(rules))
				}
			}
		}

		var exitCode int
		if len(suppressions) > 0 {
			exitCode = gate.CheckAndPrintWithSuppressions(gateReports, failOn, cfg.Sensor.Verbose, suppressions)
		} else {
			exitCode = gate.CheckAndPrint(gateReports, failOn, cfg.Sensor.Verbose)
		}

		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}
}

// runDaemon runs the daemon on the SDK's sensor runtime (pkg/sensorkit):
// this function only adds what is this sensor's own (its scanners, parsers,
// scanner content, scan workspace and validation executor).
func runDaemon(ctx context.Context, cfg *Config, opts daemonOptions) {
	sensorName := cfg.Sensor.Name
	if sensorName == "" {
		hostname, _ := os.Hostname()
		sensorName = fmt.Sprintf("sensor-%s", hostname)
	}

	// The sensor-local policy (api RFC-040 §5.7): read once, read-only; the
	// platform cannot change it. One that cannot be loaded stops the sensor.
	localPolicy, err := core.LoadLocalPolicy(core.LocalPolicyOptions{Path: opts.localPolicy})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	// The Tenable.sc connector config: owner-written and read-only, like the
	// local policy. One that exists but cannot be used stops the sensor.
	tenableCfg, tenableWarns, err := tenablesc.Load(tenablesc.LoadOptions{Path: opts.tenableSCConfig})
	for _, w := range tenableWarns {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	if tenableCfg != nil && !cfg.Sensor.EnableCommands {
		fmt.Fprintln(os.Stderr, "Warning: the Tenable.sc connector is configured but commands are off (-enable-commands); it will not run")
	}

	// Scanner content: refreshed, verified and swapped by the sensor; scans
	// run on the version current when they start.
	contentMgr, err := newContentManager(cfg.Scanners, cfg.Sensor.Verbose, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	tools := opts.tools
	if tools == nil {
		tools = []string{} // the scanners came from the config, -tool or detection
	}
	kitOpts := sensorkit.Options{
		Name:                sensorName,
		Version:             Version,
		Region:              cfg.Sensor.Region,
		APIURL:              cfg.API.BaseURL,
		APIKey:              cfg.API.APIKey,
		SensorID:            cfg.API.SensorID,
		Protocol:            opts.protocol,
		Timeout:             cfg.API.Timeout,
		Standalone:          opts.standalone,
		CredentialsHelp:     daemonCredentialsHelp,
		DisableCommands:     !cfg.Sensor.EnableCommands,
		CommandPollInterval: cfg.Sensor.CommandPollInterval,
		DisableDoorbell:     cfg.Sensor.DisableDoorbell,
		MaxJobs:             cfg.Sensor.MaxJobs,
		Tools:               tools,
		Targets:             cfg.Targets,
		ScanInterval:        cfg.Sensor.ScanInterval,
		CollectInterval:     cfg.Sensor.CollectInterval,
		HeartbeatInterval:   cfg.Sensor.HeartbeatInterval,
		Outbox:              cfg.Outbox,
		OutboxOverrides:     opts.outbox,
		LocalPolicy:         localPolicy,
		KeyAutoRenew:        opts.keyAutoRenew,
		NoKeyAutoRenew:      opts.noKeyAutoRenew,
		CredentialsFile:     opts.credentialsFile,
		Verbose:             cfg.Sensor.Verbose,
		// Scheduled scans file their findings on the scanned repository, as
		// one-shot runs do: protocol v2 rejects findings without an asset.
		AssetResolver: func(_, target string) (ctis.AssetType, string) {
			return detectAsset(target)
		},
		// Dispatched scans name the repository of a filesystem target;
		// network scanners' parsers name their assets from the output.
		CommandAssetResolver: func(_, target string) (ctis.AssetType, string) {
			if !filepath.IsAbs(target) {
				return "", ""
			}
			return detectAsset(target)
		},
		UnavailableReason: func(ctx context.Context, name string, checkErr error) string {
			return unavailableReason(ctx, configuredScanner(cfg.Scanners, name), checkErr)
		},
	}
	if contentMgr != nil {
		kitOpts.Content = daemonContent{contentMgr}
	}

	// The scan workspace: filesystem targets of dispatched code scans
	// (betterleaks, semgrep, trivy fs) must resolve inside it.
	var workspace *sensorexec.Workspace
	runsCommands := cfg.Sensor.EnableCommands && !opts.standalone && cfg.API.BaseURL != "" && cfg.API.APIKey != ""
	if runsCommands {
		cwd, _ := os.Getwd()
		ws, wsErr := sensorexec.WorkspaceFromEnv(lookupScanRoots, cwd)
		if wsErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: filesystem scan targets are disabled: %v\n", wsErr)
		}
		workspace = ws
		// Code-scanner targets are confined to the scan workspace; the SDK
		// executor re-checks every target against the same roots (and logs
		// them as the scan workspace).
		policy := core.DefaultScanTargetPolicy()
		policy.AllowedRoots = workspace.Roots()
		kitOpts.ScanTargetPolicy = policy
		if roots := workspace.Roots(); len(roots) > 0 {
			kitOpts.WorkDir = roots[0]
		}
	}

	kit, err := sensorkit.New(kitOpts)
	sensorkit.Exit(err)

	// A daemon that runs commands always serves validation (the validating
	// executor wraps every command).
	if cfg.Sensor.EnableCommands {
		kit.Tools().AddCapabilities("validate")
	}
	// Native-format parsers: betterleaks, semgrep, trivy and nuclei emit
	// their own formats; a scanner whose output no parser reads fails its
	// command rather than reporting 0 findings.
	for _, p := range scannerParsers() {
		kit.AddParser(contentMgr.WrapParser(p))
	}
	// The scanners, in the configured order: every heartbeat reports them
	// (missing ones as not installed), dispatched scans run them under their
	// configured name too ("trivy-fs" runs the "trivy" scanner).
	for _, scannerCfg := range cfg.Scanners {
		if !scannerCfg.Enabled {
			continue
		}
		scanner, err := getScanner(scannerCfg, cfg.Sensor.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating scanner %s: %v\n", scannerCfg.Name, err)
			continue
		}
		var caps []string
		if core.CanonicalScannerName(scannerCfg.Name) == "trivy-image" {
			// A trivy image scan is a container scan whatever its scanner
			// list says.
			caps = append(caps, "container")
		}
		if cfg.Sensor.EnableCommands && scanner.Name() == "nuclei" {
			caps = append(caps, "validate:nuclei")
		}
		kit.AddScanner(contentMgr.WrapScanner(scanner), sensorkit.As(scannerCfg.Name), sensorkit.WithCapabilities(caps...))
	}
	for _, collectorCfg := range cfg.Collectors {
		if !collectorCfg.Enabled {
			continue
		}
		collector, err := getCollector(collectorCfg, cfg.Sensor.Verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating collector %s: %v\n", collectorCfg.Name, err)
			continue
		}
		kit.AddCollector(collector)
	}

	if runsCommands {
		// CTEM Stage-4 `validate` jobs run a non-intrusive safe-check
		// (reachability re-check) here; scan targets are guarded; everything
		// else goes on to the SDK's scanner/collector executor.
		kit.UseCommandMiddleware(func(next core.CommandExecutor) core.CommandExecutor {
			v := sensorexec.NewValidatingCommandExecutor(next, cfg.Sensor.Verbose)
			v.SetWorkspace(workspace)
			v.SetLocalPolicy(localPolicy)
			if contentMgr != nil {
				v.SetNucleiTemplates(contentMgr.NucleiTemplates)
			}
			return v
		}, "validate")
		// The Tenable.sc connector (api RFC-047): connector_sync commands pull
		// from the Tenable.sc instances the owner configured, with keys that
		// never leave this sensor.
		if tenableCfg != nil {
			kit.HandleCommand(tenablesc.CommandTypeSync, tenablesc.NewSyncExecutor(tenableCfg, kit.Client()))
			// connector_scan launches one Tenable.sc scan, only where the
			// owner allowed scans, re-checking every target against the
			// local policy.
			if tenableCfg.AllowsScans() {
				var policy tenablesc.TargetChecker
				if localPolicy != nil {
					policy = localPolicy
				}
				kit.HandleCommand(tenablesc.CommandTypeScan, tenablesc.NewScanExecutor(tenableCfg, kit.Client(), policy))
			}
			if err := kit.Tools().Register(core.ToolSpec{
				Name: tenablesc.ToolName, Kind: core.ToolKindCollector, Version: Version,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
		}
		// refresh_content commands (the platform's "Refresh content") are
		// served when the sensor manages content.
		if contentMgr != nil {
			kit.HandleCommand(core.CommandTypeRefreshContent, &content.CommandExecutor{Manager: contentMgr})
		}
	}

	sensorkit.Exit(kit.Run(ctx))
}

// configuredScanner is the configured scanner named name (the name it was
// added under), or one with just that name.
func configuredScanner(scanners []ScannerConfig, name string) ScannerConfig {
	for _, s := range scanners {
		if s.Enabled && s.Name == name {
			return s
		}
	}
	return ScannerConfig{Name: name, Enabled: true}
}

// lookupScanRoots reads the scan workspace setting: SENSOR_SCAN_ROOTS, or the
// SDK's OPENCTEM_SDK_SCAN_ROOTS when only that is set.
func lookupScanRoots(name string) (string, bool) {
	if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
		return v, true
	}
	return os.LookupEnv(core.EnvScanRoots)
}

func getScanner(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
	// A retired name ("gitleaks" in an older config or CI template) runs its
	// replacement.
	if name := core.CanonicalScannerName(cfg.Name); name != cfg.Name {
		fmt.Fprintf(os.Stderr, "Note: scanner %q was replaced by %q; running %s\n", cfg.Name, name, name)
	}

	// Try native scanners first (better support for dataflow, native JSON, etc.)
	switch core.CanonicalScannerName(cfg.Name) {
	case "semgrep":
		scanner := scanners.Semgrep()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil

	case core.ScannerBetterleaks:
		scanner := scanners.Betterleaks()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		// Wrap betterleaks in adapter to implement core.Scanner
		return &betterleaksAdapter{scanner}, nil

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
		// The operator's rate-limit ceilings (SENSOR_NUCLEI_MAX_*): no scan
		// runs above them.
		limits, err := nuclei.LimitsFromEnv(os.LookupEnv)
		if err != nil {
			return nil, err
		}
		scanner.Limits = limits
		return scanner, nil
	}

	// The recon tools (api RFC-036 EASM discovery): their results are
	// assets, returned as a CTIS report the generic parser reads.
	if name := core.CanonicalScannerName(cfg.Name); recon.IsTool(name) {
		scanner, err := recon.New(name)
		if err != nil {
			return nil, err
		}
		setReconOptions(scanner.Recon(), cfg.Binary, verbose)
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

// betterleaksAdapter wraps betterleaks.Scanner to implement core.Scanner interface.
type betterleaksAdapter struct {
	*scanners.BetterleaksScanner
}

func (a *betterleaksAdapter) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return a.GenericScan(ctx, target, opts)
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
// baselineNewSet classifies a report's findings as new vs. pre-existing relative
// to the PR base branch via the server, and records the new fingerprints in the
// shared accum set (used by the PR-scoped gate). The returned set is what the
// handler uses to scope inline comments to this report's new findings.
//
// It FAILS SAFE: if the diff call fails, every fingerprint in the report is
// treated as new (added to accum) and nil is returned so the handler comments on
// all findings — a classification failure must never hide a finding.
func baselineNewSet(ctx context.Context, c *client.Client, repo, baseBranch string,
	report *ctis.Report, accum map[string]bool, verbose bool) map[string]bool {
	fps := make([]string, 0, len(report.Findings))
	for i := range report.Findings {
		if fp := report.Findings[i].Fingerprint; fp != "" {
			fps = append(fps, fp)
		}
	}
	if len(fps) == 0 {
		// Nothing to match; findings without fingerprints are treated as new by
		// both the handler and the gate filter.
		return map[string]bool{}
	}

	newList, err := c.BaselineDiff(ctx, repo, baseBranch, fps)
	if err != nil {
		if verbose {
			fmt.Printf("[baseline] diff failed, treating all findings as new: %v\n", err)
		}
		for _, fp := range fps {
			accum[fp] = true
		}
		return nil
	}

	set := make(map[string]bool, len(newList))
	for _, fp := range newList {
		set[fp] = true
		accum[fp] = true
	}
	return set
}

// countFindings totals findings across reports (for PR-scoped gate logging).
func countFindings(reports []*ctis.Report) int {
	n := 0
	for _, r := range reports {
		if r != nil {
			n += len(r.Findings)
		}
	}
	return n
}

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

// scannerParsers returns the parsers for every native scanner output format
// the sensor runs. Without nuclei's, a dispatched nuclei scan's JSON Lines
// fell through to the SARIF parser and its findings were lost.
func scannerParsers() []core.Parser {
	return []core.Parser{&betterleaks.Parser{}, &semgrep.Parser{}, &trivy.Parser{}, &nuclei.ReportParser{}}
}

// newParserRegistryWith returns a registry with the built-in SARIF/CTIS
// parsers and scannerParsers, which stamp the content each report's scan
// used (tool.properties.content) when m manages content (nil: plain).
func newParserRegistryWith(m *content.Manager) *core.ParserRegistry {
	r := core.NewParserRegistry()
	for _, p := range scannerParsers() {
		r.Register(m.WrapParser(p))
	}
	return r
}

// Flags of the removed platform mode, still accepted so that a command line
// carrying them reaches the explanation below (or, without -platform, runs
// as before: they never did anything outside platform mode).
var (
	removedPlatformFlags     = []string{"bootstrap-token"}
	removedPlatformBoolFlags = []string{"enable-recon", "enable-vulnscan", "enable-secrets", "enable-assets", "enable-pipeline"}
)

const platformModeRemovedMessage = `Error: -platform mode has been removed.

It spoke /api/v1/platform/register, lease and poll, which the API no longer
serves, so a -platform sensor could never connect. Run the server-controlled
daemon instead (the default command of the sensor image):

  openctemio-sensor -daemon -enable-commands -api-url https://... -api-key ...

or enroll with an enrollment token. -bootstrap-token and -enable-recon,
-enable-vulnscan, -enable-secrets, -enable-assets and -enable-pipeline
belonged to platform mode and are ignored.
`
