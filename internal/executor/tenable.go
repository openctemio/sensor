package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/agent/internal/security/targetguard"
	"github.com/openctemio/sdk-go/pkg/platform"
	"github.com/openctemio/sdk-go/pkg/scanners/tenable"
)

// TenableExecutor runs Tenable (Nessus Pro / Tenable.sc) scans from a runner in
// the customer's environment and pushes results back as CTIS.
//
// It is the agent-side of RFC-007 "runner mode": the runner is an OpenCTEM agent
// with capability `infra` + tool `tenable`. Tenable credentials live ON the
// runner (this config, sourced from local env) and are never held by the control
// plane. The api dispatches a `tenable` job with the target batch + a coverage
// session id; this executor scans the local appliance, parses the .nessus, and
// PushCTIS — so stale findings on the batch's hosts are auto-resolved (scoped by
// tool + session id).
type TenableExecutor struct {
	config *TenableConfig
	pusher ResultPusher
	guard  *targetguard.Guard
}

// TenableConfig configures the Tenable executor. Credentials are agent-local.
type TenableConfig struct {
	Enabled bool
	// Engine: "nessus_pro" (default) | "tenable_sc".
	Engine string
	// BaseURL of the local Nessus/Tenable.sc appliance.
	BaseURL string
	// AccessKey / SecretKey are the appliance API keys (kept on the runner).
	AccessKey string
	SecretKey string
	// TemplateUUID is the default Nessus scan template/policy.
	TemplateUUID string
	// MaxTargetHosts bounds a single CIDR target; MaxTargets bounds the job's
	// target count. 0 → safe defaults (see targetguard). These cap the blast
	// radius if the control plane is compromised (RFC-007 §8 R1).
	MaxTargetHosts int
	MaxTargets     int
	Verbose        bool
}

// NewTenableExecutor builds the executor. It always installs a target guard:
// the runner independently validates dispatched targets and never trusts the
// control plane (RFC-007 §8 R1).
func NewTenableExecutor(cfg *TenableConfig, pusher ResultPusher) *TenableExecutor {
	maxHosts, maxTargets := 0, 0
	if cfg != nil {
		maxHosts, maxTargets = cfg.MaxTargetHosts, cfg.MaxTargets
	}
	return &TenableExecutor{
		config: cfg,
		pusher: pusher,
		guard:  targetguard.New(maxHosts, maxTargets),
	}
}

func (e *TenableExecutor) Name() string { return "tenable" }

// Capabilities advertises infrastructure scanning (the api routes tenable jobs by
// capability/tool — see RFC-007 §3.10).
func (e *TenableExecutor) Capabilities() []string { return []string{"infra"} }

func (e *TenableExecutor) InstalledTools() []string {
	if e.config != nil && e.config.BaseURL != "" {
		return []string{"tenable"}
	}
	return nil
}

func (e *TenableExecutor) IsEnabled() bool { return e.config != nil && e.config.Enabled }

// tenablePayload is the job payload for a tenable scan.
type tenablePayload struct {
	Targets      []string `json:"targets"`
	Target       string   `json:"target"`
	SessionID    string   `json:"session_id"`
	TemplateUUID string   `json:"template_uuid"`
}

// Execute launches a scan on the local appliance, waits for completion, exports
// the .nessus, converts it to CTIS, and pushes it.
func (e *TenableExecutor) Execute(ctx context.Context, job *platform.JobInfo) (*platform.JobResult, error) {
	start := time.Now()
	fail := func(msg string) (*platform.JobResult, error) {
		return &platform.JobResult{
			JobID:           job.ID,
			Status:          "failed",
			CompletedAt:     time.Now(),
			DurationMs:      time.Since(start).Milliseconds(),
			Error:           msg,
			WorkflowContext: job.WorkflowContext,
		}, nil
	}

	if e.config == nil || e.config.BaseURL == "" || e.config.AccessKey == "" || e.config.SecretKey == "" {
		return fail("tenable runner not configured (base URL + API keys required on the runner)")
	}
	// Only Nessus Professional is implemented; Tenable.sc (/rest) is a follow-up.
	if e.config.Engine == "tenable_sc" {
		return fail("tenable.sc engine not yet supported by this runner")
	}

	p := parseTenablePayload(job)
	targets := p.Targets
	if len(targets) == 0 && p.Target != "" {
		targets = []string{p.Target}
	}
	if len(targets) == 0 {
		return fail("no targets in job payload")
	}

	// R1: the runner does NOT trust dispatched targets. Block metadata/loopback/
	// link-local and oversized ranges before any scan is launched — a compromised
	// control plane must not be able to weaponize the runner against sensitive
	// infrastructure (RFC-007 §8 R1).
	if e.guard != nil {
		if err := e.guard.ValidateTargets(ctx, targets); err != nil {
			return fail(fmt.Sprintf("target rejected by runner guard: %v", err))
		}
	}

	client, err := tenable.NewNessusProClient(e.config.BaseURL, tenable.Credentials{
		AccessKey: e.config.AccessKey,
		SecretKey: e.config.SecretKey,
	}, nil)
	if err != nil {
		return fail(fmt.Sprintf("build tenable client: %v", err))
	}

	templateUUID := p.TemplateUUID
	if templateUUID == "" {
		templateUUID = e.config.TemplateUUID
	}
	ref, err := client.Launch(ctx, tenable.LaunchRequest{
		Targets:      targets,
		TemplateUUID: templateUUID,
		Name:         "openctem-" + job.ID,
	})
	if err != nil {
		return fail(fmt.Sprintf("launch scan: %v", err))
	}

	if err := waitForScan(ctx, client, ref); err != nil {
		return fail(err.Error())
	}

	body, err := client.Export(ctx, ref)
	if err != nil {
		return fail(fmt.Sprintf("export results: %v", err))
	}
	defer func() { _ = body.Close() }()

	sessionID := p.SessionID
	if sessionID == "" {
		sessionID = job.ID
	}
	report, err := tenable.Convert(body, tenable.ConvertOptions{
		ScanSessionID: sessionID,
		ToolName:      "tenable",
		MinSeverity:   1,
	})
	if err != nil {
		return fail(fmt.Sprintf("parse .nessus: %v", err))
	}

	if e.pusher != nil {
		if err := e.pusher.PushCTIS(ctx, report); err != nil {
			return fail(fmt.Sprintf("push results: %v", err))
		}
	}

	return &platform.JobResult{
		JobID:           job.ID,
		Status:          "completed",
		CompletedAt:     time.Now(),
		DurationMs:      time.Since(start).Milliseconds(),
		FindingsCount:   len(report.Findings),
		WorkflowContext: job.WorkflowContext,
	}, nil
}

// waitForScan polls until the scan completes, fails, or the context expires.
func waitForScan(ctx context.Context, client tenable.Client, ref tenable.ScanRef) error {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		state, err := client.Poll(ctx, ref)
		if err != nil {
			return fmt.Errorf("poll scan: %w", err)
		}
		switch state {
		case tenable.ScanCompleted:
			return nil
		case tenable.ScanFailed:
			return fmt.Errorf("scan failed on the appliance")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func parseTenablePayload(job *platform.JobInfo) tenablePayload {
	var p tenablePayload
	if job.Payload == nil {
		return p
	}
	if v, ok := job.Payload["targets"].([]any); ok {
		for _, t := range v {
			if s, ok := t.(string); ok {
				p.Targets = append(p.Targets, s)
			}
		}
	}
	if s, ok := job.Payload["target"].(string); ok {
		p.Target = s
	}
	if s, ok := job.Payload["session_id"].(string); ok {
		p.SessionID = s
	}
	if s, ok := job.Payload["template_uuid"].(string); ok {
		p.TemplateUUID = s
	}
	return p
}
