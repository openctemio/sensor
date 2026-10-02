package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"
)

// fakeVulnTool returns a fixed result, optionally after the context ends.
type fakeVulnTool struct {
	result    *ToolResult
	waitForCt bool
}

func (t *fakeVulnTool) Name() string { return "semgrep" }
func (t *fakeVulnTool) Execute(ctx context.Context, _ ToolOptions) (*ToolResult, error) {
	if t.waitForCt {
		<-ctx.Done()
	}
	return t.result, nil
}
func (t *fakeVulnTool) IsInstalled(context.Context) (bool, string, error) { return true, "1.0", nil }
func (t *fakeVulnTool) Capabilities() []string                            { return []string{"sast"} }

type failingPusher struct{ err error }

func (p failingPusher) PushCTIS(context.Context, *ctis.Report) error       { return p.err }
func (p failingPusher) PushAssets(context.Context, []ctis.Asset) error     { return p.err }
func (p failingPusher) PushFindings(context.Context, []ctis.Finding) error { return p.err }

func vulnExecutorWith(tool ToolExecutor, pusher ResultPusher) *VulnScanExecutor {
	e := NewVulnScanExecutor(&VulnScanConfig{Enabled: true}, pusher)
	e.tools["semgrep"] = tool
	return e
}

func semgrepJob() *platform.JobInfo {
	return &platform.JobInfo{ID: "job-1", Type: "sast", Payload: map[string]interface{}{"scanner": "semgrep"}}
}

// api RFC-030 B12: a tool run that failed (non-zero exit, no output) was
// reported "completed" with 0 findings, i.e. "scanned clean".
func TestVulnScan_FailedToolRunIsFailed(t *testing.T) {
	e := vulnExecutorWith(&fakeVulnTool{result: &ToolResult{Tool: "semgrep", Success: false, Error: "semgrep: invalid config\n"}}, nil)
	res, err := e.Execute(context.Background(), semgrepJob())
	if err == nil || res == nil || res.Status != "failed" {
		t.Fatalf("got %+v, %v; want failed", res, err)
	}
	if !strings.Contains(res.Error, "invalid config") {
		t.Fatalf("error %q does not carry the tool's message", res.Error)
	}
}

// A run killed by the job timeout is failed even when the tool says success
// on whatever partial output it left.
func TestVulnScan_TimedOutRunIsFailed(t *testing.T) {
	e := vulnExecutorWith(&fakeVulnTool{result: &ToolResult{Tool: "semgrep", Success: true, Output: []byte(`{"results":[]}`)}, waitForCt: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res, err := e.Execute(ctx, semgrepJob())
	if err == nil || res == nil || res.Status != "failed" || !strings.Contains(res.Error, "timed out") {
		t.Fatalf("got %+v, %v; want failed (timed out)", res, err)
	}
}

func TestVulnScan_NilResultIsFailed(t *testing.T) {
	e := vulnExecutorWith(&fakeVulnTool{result: nil}, nil)
	res, err := e.Execute(context.Background(), semgrepJob())
	if err == nil || res == nil || res.Status != "failed" {
		t.Fatalf("got %+v, %v; want failed", res, err)
	}
}

// Findings that did not reach the platform fail the job instead of a
// "completed" that hides the loss.
func TestVulnScan_UndeliveredFindingsFail(t *testing.T) {
	out := `{"results":[{"check_id":"r1","path":"a.go","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","severity":"ERROR","lines":"x"}}],"errors":[]}`
	e := vulnExecutorWith(&fakeVulnTool{result: &ToolResult{Tool: "semgrep", Success: true, Output: []byte(out)}},
		failingPusher{err: errors.New("platform unreachable")})
	job := semgrepJob()
	job.Payload["repo_url"] = "https://github.com/example/app"
	res, err := e.Execute(context.Background(), job)
	if err == nil || res == nil || res.Status != "failed" || !strings.Contains(res.Error, "deliver") {
		t.Fatalf("got %+v, %v; want failed (deliver)", res, err)
	}
}

func TestVulnScan_SuccessfulRunCompletes(t *testing.T) {
	e := vulnExecutorWith(&fakeVulnTool{result: &ToolResult{Tool: "semgrep", Success: true, Output: []byte(`{"results":[],"errors":[]}`)}}, nil)
	res, err := e.Execute(context.Background(), semgrepJob())
	if err != nil || res == nil || res.Status != "completed" {
		t.Fatalf("got %+v, %v; want completed", res, err)
	}
}
