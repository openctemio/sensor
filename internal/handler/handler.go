// Package handler provides lifecycle management for security scanning workflows.
// It follows the Handler pattern: OnStart -> HandleFindings -> OnCompleted/OnError.
package handler

import (
	"context"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/gitenv"
	"github.com/openctemio/sensor/internal/strategy"
)

// ScanHandler manages the lifecycle of a security scan.
type ScanHandler interface {
	// OnStart is called at the beginning of a scan.
	// It should register the scan with the server and return scan info.
	OnStart(gitEnv gitenv.GitEnv, scannerName, scannerType string) (*ScanInfo, error)

	// HandleFindings processes scan findings.
	// It sends findings to the server and optionally creates PR/MR comments.
	HandleFindings(params HandleFindingsParams) error

	// OnCompleted is called when the scan completes successfully.
	OnCompleted() error

	// OnError is called when an error occurs during the scan.
	OnError(err error) error
}

// ScanInfo contains information about a registered scan.
type ScanInfo struct {
	ScanID        string `json:"scan_id"`
	LastCommitSha string `json:"last_commit_sha"`
	ScanURL       string `json:"scan_url"`
}

// HandleFindingsParams contains parameters for handling findings.
type HandleFindingsParams struct {
	// Ctx is the run's context: cancellation, and the command the work is
	// for (core.WithCommandID) when there is one, so the push binds to it.
	// nil means context.Background().
	Ctx context.Context

	Report       *ctis.Report
	Strategy     strategy.ScanStrategy
	ChangedFiles []strategy.ChangedFile
	GitEnv       gitenv.GitEnv

	// NewFingerprints, when non-nil, restricts PR/MR inline comments to findings
	// the PR introduces relative to its base branch (keyed by fingerprint). It is
	// computed by the sensor via Client.BaselineDiff in a PR context. When nil
	// (no PR context, baseline unavailable, or non-PR scan) all findings on
	// changed files are eligible — the prior behavior, preserved for back-compat.
	NewFingerprints map[string]bool
}

// Finding represents a security finding.
type Finding struct {
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Path        string    `json:"path"`
	StartLine   int       `json:"start_line"`
	EndLine     int       `json:"end_line"`
	Snippet     string    `json:"snippet"`
	DataFlow    *DataFlow `json:"data_flow,omitempty"`
}

// DataFlow represents taint tracking information for a finding.
type DataFlow struct {
	TaintSource      []Location `json:"taint_source"`
	IntermediateVars []Location `json:"intermediate_vars"`
	TaintSink        []Location `json:"taint_sink"`
}

// Location represents a code location in dataflow.
type Location struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Content string `json:"content"`
}

// ConsoleHandler is a simple handler that prints to console.
// Useful for local development and testing.
type ConsoleHandler struct {
	Verbose bool
}

// NewConsoleHandler creates a new console handler.
func NewConsoleHandler(verbose bool) *ConsoleHandler {
	return &ConsoleHandler{Verbose: verbose}
}

func (h *ConsoleHandler) OnStart(gitEnv gitenv.GitEnv, scannerName, scannerType string) (*ScanInfo, error) {
	if h.Verbose {
		provider := "local"
		if gitEnv != nil {
			provider = gitEnv.Provider()
		}
		println("[handler] Scan started")
		println("[handler]   Scanner:", scannerName)
		println("[handler]   Type:", scannerType)
		println("[handler]   Provider:", provider)
	}
	return &ScanInfo{}, nil
}

func (h *ConsoleHandler) HandleFindings(params HandleFindingsParams) error {
	if params.Report == nil {
		return nil
	}

	println("[handler] Findings:", len(params.Report.Findings))
	println("[handler] Strategy:", params.Strategy.String())

	if h.Verbose {
		for i, f := range params.Report.Findings {
			println("[handler]  ", i+1, ".", f.Title, "-", f.Severity, "-", f.Location.Path)
		}
	}
	return nil
}

func (h *ConsoleHandler) OnCompleted() error {
	if h.Verbose {
		println("[handler] Scan completed")
	}
	return nil
}

func (h *ConsoleHandler) OnError(err error) error {
	println("[handler] Scan error:", err.Error())
	return nil
}
