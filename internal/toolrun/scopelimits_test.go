package toolrun

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: a job's scope limits reach the task (whose forwarder enforces
// them) and are refused for a tool run in this process, which would bypass
// the forwarder.
func TestApplyJobCarriesScopeLimits(t *testing.T) {
	m := tool.Manifest{Name: "crawler"}
	limits := []scopelimit.Limit{{Host: "a.example", Ports: "443", PathPrefix: "/api"}}
	ctx, _, err := ApplyJob(context.Background(), m, nil, &core.ScanOptions{Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	if task := withJob(ctx, tool.Task{}); len(task.Limits) != 1 || task.Limits[0].PathPrefix != "/api" {
		t.Fatalf("task limits %+v", task.Limits)
	}
	t.Setenv(EnvRuntime, "in-process")
	if _, _, err := ApplyJob(context.Background(), m, nil, &core.ScanOptions{Limits: limits}); err == nil || !strings.Contains(err.Error(), "out of process") {
		t.Fatalf("in-process: %v", err)
	}
}
