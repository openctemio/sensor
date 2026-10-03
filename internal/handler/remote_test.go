package handler

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/gitenv"
	"github.com/openctemio/sensor/internal/strategy"
)

// fakeGitEnv records CreateMRComment calls and returns a preset set of existing
// finding markers (to exercise idempotency). In an MR context (MergeRequestID
// non-empty) so createMRComments runs.
type fakeGitEnv struct {
	existing     map[string]bool
	posted       []gitenv.MRCommentOption
	summaryBody  string
	summaryCalls int
}

func (f *fakeGitEnv) Provider() string          { return "fake" }
func (f *fakeGitEnv) IsActive() bool            { return true }
func (f *fakeGitEnv) ProjectID() string         { return "1" }
func (f *fakeGitEnv) ProjectName() string       { return "owner/repo" }
func (f *fakeGitEnv) ProjectURL() string        { return "https://example.test/owner/repo" }
func (f *fakeGitEnv) BlobURL() string           { return "" }
func (f *fakeGitEnv) CanonicalRepoName() string { return "owner/repo" }
func (f *fakeGitEnv) CommitSha() string         { return "abc123" }
func (f *fakeGitEnv) CommitBranch() string      { return "feature/x" }
func (f *fakeGitEnv) CommitTitle() string       { return "" }
func (f *fakeGitEnv) CommitTag() string         { return "" }
func (f *fakeGitEnv) DefaultBranch() string     { return "main" }
func (f *fakeGitEnv) MergeRequestID() string    { return "42" }
func (f *fakeGitEnv) MergeRequestTitle() string { return "PR" }
func (f *fakeGitEnv) SourceBranch() string      { return "feature/x" }
func (f *fakeGitEnv) TargetBranch() string      { return "main" }
func (f *fakeGitEnv) TargetBranchSha() string   { return "def456" }
func (f *fakeGitEnv) JobURL() string            { return "" }

func (f *fakeGitEnv) CreateMRComment(option gitenv.MRCommentOption) error {
	f.posted = append(f.posted, option)
	return nil
}
func (f *fakeGitEnv) ExistingFindingMarkers() (map[string]bool, error) {
	if f.existing == nil {
		return map[string]bool{}, nil
	}
	return f.existing, nil
}
func (f *fakeGitEnv) UpsertSummaryComment(body string) error {
	f.summaryBody = body
	f.summaryCalls++
	return nil
}

func findingAt(rule, path string, line int) ctis.Finding {
	return ctis.Finding{
		Title: rule, RuleID: rule, Severity: ctis.SeverityHigh,
		Location: &ctis.FindingLocation{Path: path, StartLine: line, EndLine: line},
	}
}

func newTestRemoteHandler() *RemoteHandler {
	return NewRemoteHandler(&RemoteHandlerConfig{CreateComments: true, MaxComments: 10})
}

func TestCreateMRComments_SkipsAlreadyCommented(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{existing: map[string]bool{"sqli:app.go:5": true}}

	h.createMRComments(HandleFindingsParams{
		Report: &ctis.Report{Findings: []ctis.Finding{
			findingAt("sqli", "app.go", 5), // already commented -> skip
			findingAt("xss", "view.go", 9), // new -> post
		}},
		Strategy: strategy.AllFiles,
		GitEnv:   f,
	})

	if len(f.posted) != 1 {
		t.Fatalf("expected 1 comment (the new finding), got %d", len(f.posted))
	}
	if f.posted[0].Path != "view.go" {
		t.Fatalf("posted the wrong finding: %+v", f.posted[0])
	}
	// The posted comment must carry a marker so a future run can dedupe it.
	if !containsMarker(f.posted[0].Body, "xss:view.go:9") {
		t.Fatalf("posted comment missing idempotency marker: %q", f.posted[0].Body)
	}
}

func TestCreateMRComments_DedupesWithinRun(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}
	dup := findingAt("sqli", "app.go", 5)

	h.createMRComments(HandleFindingsParams{
		Report:   &ctis.Report{Findings: []ctis.Finding{dup, dup}},
		Strategy: strategy.AllFiles,
		GitEnv:   f,
	})

	if len(f.posted) != 1 {
		t.Fatalf("duplicate findings in one run must post once, got %d", len(f.posted))
	}
}

func TestCreateMRComments_ChangedFileOnly(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}

	h.createMRComments(HandleFindingsParams{
		Report: &ctis.Report{Findings: []ctis.Finding{
			findingAt("a", "changed.go", 1),
			findingAt("b", "untouched.go", 2),
		}},
		Strategy:     strategy.ChangedFileOnly,
		ChangedFiles: []strategy.ChangedFile{{Path: "changed.go"}},
		GitEnv:       f,
	})

	if len(f.posted) != 1 || f.posted[0].Path != "changed.go" {
		t.Fatalf("ChangedFileOnly must comment only on changed files, got %+v", f.posted)
	}
}

func findingWithFP(rule, path string, line int, fp string) ctis.Finding {
	f := findingAt(rule, path, line)
	f.Fingerprint = fp
	return f
}

func TestCreateMRComments_FiltersToNewFingerprints(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}

	h.createMRComments(HandleFindingsParams{
		Report: &ctis.Report{Findings: []ctis.Finding{
			findingWithFP("sqli", "app.go", 5, "fp-new"),         // new -> comment
			findingWithFP("xss", "view.go", 9, "fp-preexisting"), // on base -> skip
		}},
		Strategy:        strategy.AllFiles,
		GitEnv:          f,
		NewFingerprints: map[string]bool{"fp-new": true},
	})

	if len(f.posted) != 1 {
		t.Fatalf("baseline filter must comment only on new findings, got %d", len(f.posted))
	}
	if f.posted[0].Path != "app.go" {
		t.Fatalf("commented the wrong (pre-existing) finding: %+v", f.posted[0])
	}
}

func TestCreateMRComments_NoFingerprintTreatedAsNew(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}

	// A finding without a fingerprint can't be matched to the baseline, so it must
	// still be commented (fail-open for visibility) even when a baseline is set.
	h.createMRComments(HandleFindingsParams{
		Report:          &ctis.Report{Findings: []ctis.Finding{findingAt("nofp", "app.go", 1)}},
		Strategy:        strategy.AllFiles,
		GitEnv:          f,
		NewFingerprints: map[string]bool{"something-else": true},
	})

	if len(f.posted) != 1 {
		t.Fatalf("finding without fingerprint must be commented under a baseline, got %d", len(f.posted))
	}
}

func TestSummary_NewVsBase(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}

	_ = h.HandleFindings(HandleFindingsParams{
		Report: &ctis.Report{Findings: []ctis.Finding{
			findingWithFP("a", "app.go", 1, "fp-new"),
			findingWithFP("b", "app.go", 2, "fp-old"),
		}},
		Strategy:        strategy.AllFiles,
		GitEnv:          f,
		NewFingerprints: map[string]bool{"fp-new": true},
	})
	_, _ = h.OnStart(f, "semgrep", "sast")
	if err := h.OnCompleted(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(f.summaryBody, "1 new finding(s)") ||
		!strings.Contains(f.summaryBody, "in this PR (of 2 on changed files)") {
		t.Fatalf("summary should report new vs base; got: %s", f.summaryBody)
	}
}

func TestSummary_CleanWhenNoNewFindings(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}

	// Pre-existing finding only, none new in this PR.
	_ = h.HandleFindings(HandleFindingsParams{
		Report:          &ctis.Report{Findings: []ctis.Finding{findingWithFP("b", "app.go", 2, "fp-old")}},
		Strategy:        strategy.AllFiles,
		GitEnv:          f,
		NewFingerprints: map[string]bool{}, // non-nil, fp-old not in it
	})
	_, _ = h.OnStart(f, "semgrep", "sast")
	if err := h.OnCompleted(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(f.summaryBody, "No new findings in this PR") {
		t.Fatalf("clean-PR summary expected; got: %s", f.summaryBody)
	}
}

func containsMarker(body, key string) bool {
	return len(gitenv.ExtractMarkers([]string{body})) == 1 && gitenv.ExtractMarkers([]string{body})[key]
}

func TestSummaryComment_PostedOnCompleted(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}

	_ = h.HandleFindings(HandleFindingsParams{
		Report: &ctis.Report{Findings: []ctis.Finding{
			{Title: "a", Severity: ctis.SeverityCritical},
			{Title: "b", Severity: ctis.SeverityHigh},
			{Title: "c", Severity: ctis.SeverityHigh},
		}},
		Strategy: strategy.AllFiles,
		GitEnv:   f,
	})
	// OnStart stores gitEnv (needed for OnCompleted to know the MR context).
	_, _ = h.OnStart(f, "semgrep", "sast")
	if err := h.OnCompleted(); err != nil {
		t.Fatalf("OnCompleted: %v", err)
	}

	if f.summaryCalls != 1 {
		t.Fatalf("expected one sticky summary upsert, got %d", f.summaryCalls)
	}
	if !strings.Contains(f.summaryBody, "3 finding(s)") {
		t.Fatalf("summary should report total; got: %s", f.summaryBody)
	}
	if !strings.Contains(f.summaryBody, "| High | 2 |") {
		t.Fatalf("summary should break down by severity; got: %s", f.summaryBody)
	}
}

func TestSummaryComment_CleanWhenNoFindings(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}
	_, _ = h.OnStart(f, "semgrep", "sast")
	if err := h.OnCompleted(); err != nil {
		t.Fatal(err)
	}
	if f.summaryCalls != 1 || !strings.Contains(f.summaryBody, "No security findings") {
		t.Fatalf("clean summary expected; calls=%d body=%q", f.summaryCalls, f.summaryBody)
	}
}
