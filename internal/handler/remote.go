package handler

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/gitenv"
	"github.com/openctemio/sensor/internal/strategy"
)

// RemoteHandler sends scan results to a remote OpenCTEM server.
// It also creates PR/MR comments for findings on changed files.
type RemoteHandler struct {
	pusher  core.Pusher
	gitEnv  gitenv.GitEnv
	verbose bool

	// Comment settings
	createComments bool
	maxComments    int

	// Accumulated across HandleFindings calls for the sticky PR/MR summary.
	sevCounts     map[string]int
	totalFindings int

	// Baseline (new-vs-base) accounting for the sticky summary. baselineApplied
	// is set when any HandleFindings call carried a NewFingerprints set, so the
	// summary can report how many findings the PR introduces vs. pre-existing.
	baselineApplied bool
	newFindings     int
}

// RemoteHandlerConfig configures the remote handler.
type RemoteHandlerConfig struct {
	Pusher         core.Pusher
	Verbose        bool
	CreateComments bool
	MaxComments    int // Max comments per PR/MR (default 10)
}

// NewRemoteHandler creates a new remote handler.
func NewRemoteHandler(cfg *RemoteHandlerConfig) *RemoteHandler {
	maxComments := cfg.MaxComments
	if maxComments == 0 {
		maxComments = 10
	}

	return &RemoteHandler{
		pusher:         cfg.Pusher,
		verbose:        cfg.Verbose,
		createComments: cfg.CreateComments,
		maxComments:    maxComments,
		sevCounts:      make(map[string]int),
	}
}

// OnStart registers the scan with the server.
func (h *RemoteHandler) OnStart(gitEnv gitenv.GitEnv, scannerName, scannerType string) (*ScanInfo, error) {
	h.gitEnv = gitEnv

	if h.verbose {
		provider := "local"
		if gitEnv != nil {
			provider = gitEnv.Provider()
		}
		fmt.Println("[handler] Scan starting")
		fmt.Printf("[handler]   Scanner: %s (%s)\n", scannerName, scannerType)
		fmt.Printf("[handler]   Provider: %s\n", provider)
		if gitEnv != nil {
			if gitEnv.ProjectName() != "" {
				fmt.Printf("[handler]   Repository: %s\n", gitEnv.ProjectName())
			}
			if gitEnv.CommitBranch() != "" {
				fmt.Printf("[handler]   Branch: %s\n", gitEnv.CommitBranch())
			}
			if gitEnv.CommitSha() != "" {
				fmt.Printf("[handler]   Commit: %s\n", gitEnv.CommitSha())
			}
			if gitEnv.MergeRequestID() != "" {
				fmt.Printf("[handler]   MR/PR: #%s\n", gitEnv.MergeRequestID())
			}
		}
	}

	// Test connection to server
	if h.pusher != nil {
		if err := h.pusher.TestConnection(context.Background()); err != nil {
			if h.verbose {
				fmt.Printf("[handler] Warning: Could not connect to server: %v\n", err)
			}
		}
	}

	return &ScanInfo{}, nil
}

// HandleFindings processes and sends findings to the server.
func (h *RemoteHandler) HandleFindings(params HandleFindingsParams) error {
	if params.Report == nil {
		return nil
	}

	// Accumulate counts across scanners for the sticky PR/MR summary (OnCompleted).
	if params.NewFingerprints != nil {
		h.baselineApplied = true
	}
	for i := range params.Report.Findings {
		f := &params.Report.Findings[i]
		h.totalFindings++
		h.sevCounts[strings.ToLower(string(f.Severity))]++
		// A finding is "new" if there's no baseline, or it's in the new set, or it
		// has no fingerprint to match (treated as new for visibility) — mirroring
		// the comment-filter rule in createMRComments.
		if params.NewFingerprints == nil || f.Fingerprint == "" || params.NewFingerprints[f.Fingerprint] {
			h.newFindings++
		}
	}

	if h.verbose {
		fmt.Printf("[handler] Processing %d findings\n", len(params.Report.Findings))
		fmt.Printf("[handler] Strategy: %s\n", params.Strategy.String())
		if params.Strategy == strategy.ChangedFileOnly {
			fmt.Printf("[handler] Changed files: %d\n", len(params.ChangedFiles))
		}
	}

	// Push findings to server
	if h.pusher != nil && len(params.Report.Findings) > 0 {
		ctx := params.Ctx
		if ctx == nil {
			ctx = context.Background()
		}
		result, err := h.pusher.PushFindings(ctx, params.Report)
		if err != nil {
			if h.verbose {
				fmt.Printf("[handler] Failed to push findings: %v\n", err)
			}
			return fmt.Errorf("failed to push findings: %w", err)
		}

		if h.verbose {
			fmt.Printf("[handler] Pushed: %d created, %d updated\n",
				result.FindingsCreated, result.FindingsUpdated)
		}
	}

	// Create PR/MR comments for findings on changed files
	if h.createComments && params.GitEnv != nil && params.GitEnv.MergeRequestID() != "" {
		h.createMRComments(params)
	}

	return nil
}

// findingKey returns a stable identity for a finding used to dedupe PR/MR
// comments across re-runs. Prefers the fingerprint; falls back to
// rule:path:line so a comment is still idempotent without a fingerprint.
func findingKey(f *ctis.Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	path, line := "", 0
	if f.Location != nil {
		path, line = f.Location.Path, f.Location.StartLine
	}
	return fmt.Sprintf("%s:%s:%d", f.RuleID, path, line)
}

// createMRComments creates inline comments on the PR/MR for findings on changed
// files. It is idempotent: findings already commented on the PR (detected via a
// hidden marker) are skipped, so re-running the scan does not duplicate comments.
func (h *RemoteHandler) createMRComments(params HandleFindingsParams) {
	// Build map of changed file paths
	changedPaths := make(map[string]bool)
	for _, f := range params.ChangedFiles {
		changedPaths[f.Path] = true
		if f.OldPath != "" {
			changedPaths[f.OldPath] = true
		}
	}

	// Idempotency: fetch markers already posted on this PR/MR. Best-effort — on
	// error we proceed (may duplicate) rather than skip commenting entirely.
	existing, err := params.GitEnv.ExistingFindingMarkers()
	if err != nil {
		if h.verbose {
			fmt.Printf("[handler] Could not list existing comments (will not dedupe): %v\n", err)
		}
		existing = map[string]bool{}
	}
	posted := make(map[string]bool) // guard against dupes within this run too

	commentsCreated := 0
	for i := range params.Report.Findings {
		finding := &params.Report.Findings[i]
		if commentsCreated >= h.maxComments {
			if h.verbose {
				fmt.Printf("[handler] Max comments (%d) reached, skipping remaining\n", h.maxComments)
			}
			break
		}

		// Skip if not on a changed file
		if finding.Location == nil || finding.Location.Path == "" {
			continue
		}

		// In ChangedFileOnly mode, only comment on changed files
		if params.Strategy == strategy.ChangedFileOnly && !changedPaths[finding.Location.Path] {
			continue
		}

		// In a PR context with a computed baseline, only comment on findings the
		// PR introduces (skip pre-existing tech debt already open on the base
		// branch). A finding with no fingerprint can't be matched to the baseline,
		// so it is treated as new (commented) for visibility.
		if params.NewFingerprints != nil && finding.Fingerprint != "" &&
			!params.NewFingerprints[finding.Fingerprint] {
			continue
		}

		key := findingKey(finding)
		if existing[key] || posted[key] {
			if h.verbose {
				fmt.Printf("[handler] Skipping already-commented finding: %s\n", key)
			}
			continue
		}

		// Create the comment, embedding a hidden marker for idempotency.
		err := params.GitEnv.CreateMRComment(gitenv.MRCommentOption{
			Title:     formatCommentTitle(finding),
			Body:      formatCommentBody(finding) + gitenv.MarkerComment(key),
			Path:      finding.Location.Path,
			StartLine: finding.Location.StartLine,
			EndLine:   finding.Location.EndLine,
		})

		if err != nil {
			if h.verbose {
				fmt.Printf("[handler] Failed to create comment: %v\n", err)
			}
			continue
		}

		posted[key] = true
		commentsCreated++
	}

	if h.verbose && commentsCreated > 0 {
		fmt.Printf("[handler] Created %d PR/MR comments\n", commentsCreated)
	}
}

// OnCompleted is called when the scan completes successfully.
func (h *RemoteHandler) OnCompleted() error {
	if h.verbose {
		fmt.Println("[handler] Scan completed successfully")
	}

	// Post/update the single sticky security summary comment on the PR/MR so
	// reviewers see the current state at a glance (updated in place each run).
	if h.createComments && h.gitEnv != nil && h.gitEnv.MergeRequestID() != "" {
		if err := h.gitEnv.UpsertSummaryComment(h.buildSummary()); err != nil && h.verbose {
			fmt.Printf("[handler] Failed to upsert summary comment: %v\n", err)
		}
	}
	return nil
}

// buildSummary renders the sticky PR/MR security summary as markdown.
func (h *RemoteHandler) buildSummary() string {
	// With a baseline, "clean" means the PR introduces no new findings even if
	// pre-existing tech debt remains on the changed files.
	if h.baselineApplied && h.newFindings == 0 {
		return "## 🔒 OpenCTEM Security Scan\n\n✅ **No new findings in this PR.**"
	}
	if h.totalFindings == 0 {
		return "## 🔒 OpenCTEM Security Scan\n\n✅ **No security findings.**"
	}
	var b strings.Builder
	b.WriteString("## 🔒 OpenCTEM Security Scan\n\n")
	if h.baselineApplied {
		fmt.Fprintf(&b, "**%d new finding(s)** in this PR (of %d on changed files)\n\n",
			h.newFindings, h.totalFindings)
	} else {
		fmt.Fprintf(&b, "**%d finding(s)**\n\n", h.totalFindings)
	}
	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := h.sevCounts[sev]; n > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", strings.ToUpper(sev[:1])+sev[1:], n)
		}
	}
	b.WriteString("\n*Review the inline comments above for details.*")
	return b.String()
}

// OnError is called when an error occurs during the scan.
func (h *RemoteHandler) OnError(err error) error {
	if h.verbose {
		fmt.Printf("[handler] Scan error: %v\n", err)
	}
	return nil
}

// formatCommentTitle formats the comment title from a ctis.Finding.
func formatCommentTitle(finding *ctis.Finding) string {
	if finding.Title != "" {
		return finding.Title
	}
	if finding.RuleID != "" {
		return finding.RuleID
	}
	return "Security Finding"
}

// formatCommentBody formats the comment body as markdown from a ctis.Finding.
func formatCommentBody(finding *ctis.Finding) string {
	var parts []string

	// Severity badge
	severityEmoji := getSeverityEmoji(finding.Severity)
	parts = append(parts, fmt.Sprintf("**%s %s**", severityEmoji, finding.Severity))
	parts = append(parts, "")

	// Title and description
	if finding.Title != "" {
		parts = append(parts, fmt.Sprintf("### %s", finding.Title))
	}
	if finding.Description != "" {
		parts = append(parts, "", finding.Description)
	}

	// Rule info
	if finding.RuleID != "" {
		parts = append(parts, "", fmt.Sprintf("**Rule:** `%s`", finding.RuleID))
	}

	// Category
	if finding.Category != "" {
		parts = append(parts, fmt.Sprintf("**Category:** %s", finding.Category))
	}

	// Remediation
	if finding.Remediation != nil && finding.Remediation.Recommendation != "" {
		parts = append(parts, "", "**Remediation:**", finding.Remediation.Recommendation)
	}

	// References
	if len(finding.References) > 0 {
		parts = append(parts, "", "**References:**")
		for _, ref := range finding.References {
			parts = append(parts, fmt.Sprintf("- %s", ref))
		}
	}

	parts = append(parts, "", "---", "*Detected by OpenCTEM Security Scanner*")

	return strings.Join(parts, "\n")
}

// getSeverityEmoji returns an emoji for the severity level.
func getSeverityEmoji(severity ctis.Severity) string {
	switch severity {
	case ctis.SeverityCritical:
		return "\U0001F534" // Red circle
	case ctis.SeverityHigh:
		return "\U0001F7E0" // Orange circle
	case ctis.SeverityMedium:
		return "\U0001F7E1" // Yellow circle
	case ctis.SeverityLow:
		return "\U0001F7E2" // Green circle
	default:
		return "\U0001F535" // Blue circle
	}
}
