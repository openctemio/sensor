package toolrun

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: the job's identification wins over a configured header of the
// same name, and a line that would read as a flag or break the argv is not
// a valid header line.
func TestIdentityHeaders(t *testing.T) {
	task := tool.Task{Identity: &tool.Identity{UserAgent: "jdoe-research", Headers: map[string]string{"X-Bug-Bounty": "jdoe"}}}
	got := IdentityHeaders(task, []string{"x-bug-bounty: someone", "User-Agent: corp", "X-Scan: 1"})
	want := []string{"X-Scan: 1", "User-Agent: jdoe-research", "X-Bug-Bounty: jdoe"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	if got := IdentityHeaders(tool.Task{}, []string{"X-Scan: 1"}); !slices.Equal(got, []string{"X-Scan: 1"}) {
		t.Fatalf("no identification: %q", got)
	}
	for _, bad := range []string{"-H", "noColon", ": empty", "X: a\nY: b"} {
		if ValidHeaderLine(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidHeaderLine("X-Bug-Bounty: jdoe") {
		t.Error("a plain header refused")
	}
}

// SECURITY: a scan job's identification reaches the task (the tool host
// enforces it there) and is refused for a tool run in this process, which
// would probe without it; a validation hands it over with WithOrgHTTP.
func TestJobIdentificationReachesTheTask(t *testing.T) {
	m := tool.Manifest{Name: "prober", Permissions: tool.Permissions{Network: tool.NetTargets}}
	pol := &core.OrgHTTPPolicy{UserAgent: "jdoe-research", Headers: map[string]string{"X-Bug-Bounty": "jdoe"}}
	ctx, _, err := ApplyJob(context.Background(), m, nil, &core.ScanOptions{OrgHTTP: pol})
	if err != nil {
		t.Fatal(err)
	}
	if task := withJob(ctx, tool.Task{}); task.OrgHTTP != pol {
		t.Fatalf("scan task: %+v", task.OrgHTTP)
	}
	if task := withJob(WithOrgHTTP(context.Background(), pol), tool.Task{}); task.OrgHTTP != pol {
		t.Fatalf("validation task: %+v", task.OrgHTTP)
	}
	if task := withJob(WithOrgHTTP(context.Background(), &core.OrgHTTPPolicy{}), tool.Task{}); task.OrgHTTP != nil {
		t.Fatal("an empty policy is not an identification")
	}
	t.Setenv(EnvRuntime, "in-process")
	if _, _, err := ApplyJob(context.Background(), m, nil, &core.ScanOptions{OrgHTTP: pol}); err == nil || !strings.Contains(err.Error(), "out of process") {
		t.Fatalf("in-process: %v", err)
	}
	// A tool that reaches no target (code scanner) runs in process anyway.
	offline := tool.Manifest{Name: "sast", Permissions: tool.Permissions{Network: tool.NetNone}}
	if _, _, err := ApplyJob(context.Background(), offline, nil, &core.ScanOptions{OrgHTTP: pol}); err != nil {
		t.Fatalf("offline tool in process: %v", err)
	}
}
