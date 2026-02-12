// Package executor provides the modular executor system for platform agents.
// This allows agents to be specialized for different tasks (recon, vulnscan, secrets, assets)
// with enable/disable flags at deployment time.
package executor

import (
	"context"
	"errors"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"
)

// =============================================================================
// ERRORS
// =============================================================================

var (
	// ErrExecutorDisabled is returned when trying to use a disabled executor.
	ErrExecutorDisabled = errors.New("executor is disabled")

	// ErrUnknownJobType is returned when the job type is not recognized.
	ErrUnknownJobType = errors.New("unknown job type")

	// ErrToolNotInstalled is returned when a required tool is not available.
	ErrToolNotInstalled = errors.New("tool not installed")
)

// =============================================================================
// CORE INTERFACES
// =============================================================================

// Executor is the base interface for all executors.
// Each executor handles a specific category of jobs (recon, vulnscan, secrets, assets).
type Executor interface {
	// Name returns the executor's unique identifier.
	Name() string

	// Execute runs a job and returns the result.
	Execute(ctx context.Context, job *platform.JobInfo) (*platform.JobResult, error)

	// Capabilities returns the list of capabilities this executor provides.
	// These are reported to the platform during agent registration.
	Capabilities() []string

	// InstalledTools returns the list of tools that are installed and available.
	InstalledTools() []string

	// IsEnabled returns whether this executor is enabled.
	IsEnabled() bool
}

// CTISProducer is an executor that can produce CTIS reports.
// Used by recon and asset discovery executors.
type CTISProducer interface {
	Executor

	// ProduceCTIS converts job execution results into a CTIS report.
	ProduceCTIS(ctx context.Context, job *platform.JobInfo, result any) (*ctis.Report, error)
}

// AssetProducer is an executor that discovers assets.
// Used by recon executors and cloud collectors.
type AssetProducer interface {
	CTISProducer

	// ProduceAssets extracts assets from tool output.
	ProduceAssets(ctx context.Context, output any) ([]ctis.Asset, error)
}

// FindingProducer is an executor that finds vulnerabilities.
// Used by vuln scanners, secret scanners, etc.
type FindingProducer interface {
	CTISProducer

	// ProduceFindings extracts findings from tool output.
	ProduceFindings(ctx context.Context, output any) ([]ctis.Finding, error)
}

// =============================================================================
// TOOL EXECUTOR INTERFACE
// =============================================================================

// ToolExecutor is the interface for individual tool wrappers.
// Each recon tool (subfinder, dnsx, etc.) implements this interface.
type ToolExecutor interface {
	// Name returns the tool name (e.g., "subfinder", "dnsx").
	Name() string

	// Execute runs the tool with the given options.
	Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error)

	// IsInstalled checks if the tool binary is available.
	IsInstalled(ctx context.Context) (bool, string, error)

	// Capabilities returns what this tool can do.
	Capabilities() []string
}

// ToolOptions contains parameters for tool execution.
type ToolOptions struct {
	// Target is the primary target (domain, IP, URL, etc.)
	Target string

	// Targets is a list of targets (for bulk operations)
	Targets []string

	// OutputFormat specifies the desired output format (json, text, etc.)
	OutputFormat string

	// Timeout is the maximum execution time.
	Timeout int

	// ExtraArgs are additional command-line arguments.
	ExtraArgs []string

	// InputFile is a file containing input data (e.g., list of subdomains)
	InputFile string

	// OutputFile is where to write results (optional)
	OutputFile string

	// RateLimit controls request rate (requests per second)
	RateLimit int

	// Threads controls parallelism
	Threads int

	// Verbose enables detailed output
	Verbose bool
}

// ToolResult contains the output from a tool execution.
type ToolResult struct {
	// Tool is the name of the tool that produced this result.
	Tool string

	// Success indicates if the tool ran successfully.
	Success bool

	// Output is the raw output from the tool.
	Output []byte

	// Parsed is the parsed/structured output (tool-specific).
	Parsed any

	// Error contains error details if Success is false.
	Error string

	// Duration is how long the tool ran (in milliseconds).
	Duration int64

	// ItemCount is the number of items found (subdomains, ports, etc.)
	ItemCount int
}

// =============================================================================
// RESULT PUSHER INTERFACE
// =============================================================================

// ResultPusher handles pushing results back to the API.
type ResultPusher interface {
	// PushCTIS sends a CTIS report to the API.
	PushCTIS(ctx context.Context, report *ctis.Report) error

	// PushAssets sends discovered assets to the API.
	PushAssets(ctx context.Context, assets []ctis.Asset) error

	// PushFindings sends findings to the API.
	PushFindings(ctx context.Context, findings []ctis.Finding) error
}
