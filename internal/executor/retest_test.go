package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
)

// A retest target the validate guard refuses (loopback, cloud metadata)
// fails the command before any tool runs, whatever the local policy says.
func TestRetestNucleiGuardsTargets(t *testing.T) {
	e := NewValidatingCommandExecutor(nil, false)
	for _, target := range []string{"http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data"} {
		task := tool.Task{ID: "r", Targets: []tool.Target{{Ref: "t1", Value: target}},
			Retest: []tool.RetestItem{{Ref: "f", Target: "t1", Kind: tool.RetestFinding, RuleID: "x"}}}
		if _, err := e.RetestNuclei(context.Background(), task); err == nil || !strings.Contains(err.Error(), "validate guard") {
			t.Errorf("%s: %v", target, err)
		}
	}
}

// budgetExecutor resolves one budget for every command, as the SDK's
// executor does for the sensor's own level.
type budgetExecutor struct {
	stubExecutor
	b adapt.HostBudget
}

func (x *budgetExecutor) HostBudget(*core.Command) adapt.HostBudget { return x.b }

// A retest runs under its command's per-host budget, like a
// re-verification: a signed Gentle on a Standard sensor retests at Gentle.
// The lowest limit wins either way: a context without a budget, or with
// more than the sensor's own, runs at the sensor's own.
func TestRetestRunsUnderItsCommandsBudget(t *testing.T) {
	std := adapt.DefaultBudget()
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	fast := adapt.ResolveBudget(adapt.PacingFast, nil, adapt.BudgetCeiling{})
	e := NewValidatingCommandExecutor(&budgetExecutor{b: std}, false)
	for name, tc := range map[string]struct {
		ctx           context.Context
		rps, inflight int
	}{
		"no budget on the context":          {context.Background(), std.RPS, std.Inflight},
		"the command's signed gentle":       {adapt.WithHostBudget(context.Background(), gentle), 5, 2},
		"more than the sensor's own budget": {adapt.WithHostBudget(context.Background(), fast), std.RPS, std.Inflight},
	} {
		opts := e.retestOptions(tc.ctx, nucleiTemplateSet{})
		if opts.Budget.RPS != tc.rps || opts.Budget.Inflight != tc.inflight {
			t.Errorf("%s: the retest runs under %d/s and %d in flight, want %d and %d", name, opts.Budget.RPS, opts.Budget.Inflight, tc.rps, tc.inflight)
		}
		if got := nuclei.ValidateRate(opts); got != min(tc.rps, nucleiValidateRateLimit) {
			t.Errorf("%s: -rate-limit %d, want %d", name, got, min(tc.rps, nucleiValidateRateLimit))
		}
	}
}
