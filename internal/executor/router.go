package executor

import (
	"context"
	"fmt"
	"sync"

	"github.com/openctemio/sdk-go/pkg/platform"
)

// =============================================================================
// EXECUTOR ROUTER
// =============================================================================

// Router routes jobs to the appropriate executor based on job type.
// It manages the lifecycle of all executors and aggregates capabilities.
type Router struct {
	mu sync.RWMutex

	// Executors by category
	recon    Executor
	vulnscan Executor
	secrets  Executor
	assets   Executor
	pipeline Executor
	tenable  Executor

	// All registered executors for iteration
	executors map[string]Executor

	// Pusher for results
	pusher ResultPusher

	verbose bool
}

// RouterConfig configures which executors are enabled.
type RouterConfig struct {
	ReconEnabled    bool
	VulnScanEnabled bool
	SecretsEnabled  bool
	AssetsEnabled   bool
	PipelineEnabled bool

	Verbose bool
}

// NewRouter creates a new executor router.
func NewRouter(cfg *RouterConfig, pusher ResultPusher) *Router {
	return &Router{
		executors: make(map[string]Executor),
		pusher:    pusher,
		verbose:   cfg.Verbose,
	}
}

// =============================================================================
// EXECUTOR REGISTRATION
// =============================================================================

// RegisterRecon registers the recon executor.
func (r *Router) RegisterRecon(exec Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recon = exec
	r.executors["recon"] = exec
}

// RegisterVulnScan registers the vulnerability scanning executor.
func (r *Router) RegisterVulnScan(exec Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vulnscan = exec
	r.executors["vulnscan"] = exec
}

// RegisterSecrets registers the secret scanning executor.
func (r *Router) RegisterSecrets(exec Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets = exec
	r.executors["secrets"] = exec
}

// RegisterAssets registers the asset collection executor.
func (r *Router) RegisterAssets(exec Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assets = exec
	r.executors["assets"] = exec
}

// RegisterTenable registers the Tenable scan executor (runner mode).
func (r *Router) RegisterTenable(exec Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenable = exec
	r.executors["tenable"] = exec
}

// RegisterPipeline registers the pipeline executor.
func (r *Router) RegisterPipeline(exec Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pipeline = exec
	r.executors["pipeline"] = exec
}

// =============================================================================
// JOB ROUTING
// =============================================================================

// Route finds the appropriate executor for a job.
func (r *Router) Route(job *platform.JobInfo) (Executor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	jobType := job.Type

	// Tenable is API-based (not a vulnscan CLI tool), so it has its own executor.
	// Commands are dispatched with the generic type "scan" and the scanner as
	// the real discriminator in the payload — route by scanner here so a
	// "scan" command for tenable doesn't fall through to vulnscan.
	if scanner, ok := job.Payload["scanner"].(string); ok && (scanner == "tenable" || scanner == "nessus") {
		if r.tenable == nil || !r.tenable.IsEnabled() {
			return nil, fmt.Errorf("%w: tenable", ErrExecutorDisabled)
		}
		return r.tenable, nil
	}

	if jobType == "" {
		// Try to infer from payload
		if scanner, ok := job.Payload["scanner"].(string); ok {
			jobType = inferJobType(scanner)
		}
	}

	switch jobType {
	case "recon", "subdomain", "dns", "portscan", "http", "crawler":
		if r.recon == nil || !r.recon.IsEnabled() {
			return nil, fmt.Errorf("%w: recon", ErrExecutorDisabled)
		}
		return r.recon, nil

	case "scan", "vulnscan", "sast", "sca", "dast", "container", "iac":
		if r.vulnscan == nil || !r.vulnscan.IsEnabled() {
			return nil, fmt.Errorf("%w: vulnscan", ErrExecutorDisabled)
		}
		return r.vulnscan, nil

	case "secret", "secrets":
		if r.secrets == nil || !r.secrets.IsEnabled() {
			return nil, fmt.Errorf("%w: secrets", ErrExecutorDisabled)
		}
		return r.secrets, nil

	case "tenable", "infra":
		if r.tenable == nil || !r.tenable.IsEnabled() {
			return nil, fmt.Errorf("%w: tenable", ErrExecutorDisabled)
		}
		return r.tenable, nil

	case "collect", "assets", "cloud":
		if r.assets == nil || !r.assets.IsEnabled() {
			return nil, fmt.Errorf("%w: assets", ErrExecutorDisabled)
		}
		return r.assets, nil

	case "pipeline":
		if r.pipeline == nil || !r.pipeline.IsEnabled() {
			return nil, fmt.Errorf("%w: pipeline", ErrExecutorDisabled)
		}
		return r.pipeline, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownJobType, jobType)
	}
}

// Execute routes a job to the appropriate executor and runs it.
func (r *Router) Execute(ctx context.Context, job *platform.JobInfo) (result *platform.JobResult, err error) {
	exec, err := r.Route(job)
	if err != nil {
		return &platform.JobResult{
			JobID:  job.ID,
			Status: "failed",
			Error:  err.Error(),
		}, err
	}

	// Recover from a scanner/parser panic so it becomes a failed job result
	// instead of crashing the whole agent process (which would take down every
	// other in-flight job too).
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("executor panicked: %v", rec)
			result = &platform.JobResult{
				JobID:  job.ID,
				Status: "failed",
				Error:  err.Error(),
			}
		}
	}()

	return exec.Execute(ctx, job)
}

// =============================================================================
// CAPABILITY AGGREGATION
// =============================================================================

// Capabilities returns all capabilities from enabled executors.
func (r *Router) Capabilities() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var caps []string
	seen := make(map[string]bool)

	for _, exec := range r.executors {
		if exec != nil && exec.IsEnabled() {
			for _, cap := range exec.Capabilities() {
				if !seen[cap] {
					caps = append(caps, cap)
					seen[cap] = true
				}
			}
		}
	}

	return caps
}

// InstalledTools returns all installed tools from enabled executors.
func (r *Router) InstalledTools() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var tools []string
	seen := make(map[string]bool)

	for _, exec := range r.executors {
		if exec != nil && exec.IsEnabled() {
			for _, tool := range exec.InstalledTools() {
				if !seen[tool] {
					tools = append(tools, tool)
					seen[tool] = true
				}
			}
		}
	}

	return tools
}

// EnabledExecutors returns the names of all enabled executors.
func (r *Router) EnabledExecutors() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name, exec := range r.executors {
		if exec != nil && exec.IsEnabled() {
			names = append(names, name)
		}
	}
	return names
}

// =============================================================================
// HELPERS
// =============================================================================

// inferJobType tries to determine job type from scanner name.
func inferJobType(scanner string) string {
	switch scanner {
	case "subfinder", "dnsx", "naabu", "httpx", "katana":
		return "recon"
	case "nuclei":
		return "dast"
	case "trivy", "trivy-fs", "trivy-config", "trivy-image":
		return "sca"
	case "semgrep", "codeql":
		return "sast"
	case "gitleaks", "trufflehog":
		return "secrets"
	case "tenable", "nessus":
		return "tenable"
	default:
		return "scan"
	}
}
