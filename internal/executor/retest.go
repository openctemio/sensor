package executor

import (
	"context"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
)

// RetestNuclei runs one retest task of nuclei findings (the platform's
// retest command, which the kit admitted against the local policy and
// turned into the task): every target passes the validate guard again
// (no loopback, metadata or link-local target, whatever the policy says),
// then the nuclei-validate tool checks each item in its sandboxed child on
// the sensor's managed template set, at most at the re-verification rate
// and the local policy's rate, under the retest command's per-host budget
// (retestBudget). A target the guard refuses fails the command (the
// platform settles its items as unknown).
func (e *ValidatingCommandExecutor) RetestNuclei(ctx context.Context, task tool.Task) (*toolhost.Outcome, error) {
	for _, t := range task.Targets {
		if err := validateScannerTarget(t.Value); err != nil {
			return nil, fmt.Errorf("retest: target refused by the validate guard: %w", err)
		}
	}
	var set nucleiTemplateSet
	release := func() {}
	if e.nucleiTemplates != nil {
		set.dir, set.content, release = e.nucleiTemplates(ctx)
	}
	defer release()
	fmt.Printf("[retest:nuclei] command=%s targets=%d items=%d\n", task.ID, len(task.Targets), len(task.Retest))
	return nuclei.Retest(ctx, e.retestOptions(ctx, set), task)
}

// retestOptions are the options a retest's nuclei run gets.
func (e *ValidatingCommandExecutor) retestOptions(ctx context.Context, set nucleiTemplateSet) nuclei.ValidateOptions {
	return nuclei.ValidateOptions{
		TimeoutSeconds:   120,
		RateLimit:        nucleiValidateRateLimit,
		MaxRateLimit:     e.local.Load().CapRate(validateRateCeiling()),
		Budget:           e.retestBudget(ctx),
		TemplatesDir:     set.dir,
		TemplatesVersion: set.content.Version,
		Verbose:          e.verbose,
	}
}

// retestBudget is the per-host budget a retest runs under: its command's,
// as a re-verification's is (hostBudget of the command). The kit resolves
// it for the retest command (the lowest of the sensor's level, the budget
// of the command's verified statement and the operator's ceiling) and
// passes it on the context. It is never above the sensor's own budget:
// should the context carry none, or more than the sensor's, the sensor's
// own applies, so the lowest limit wins either way.
func (e *ValidatingCommandExecutor) retestBudget(ctx context.Context) adapt.HostBudget {
	own := e.hostBudget(nil)
	b, ok := adapt.HostBudgetFrom(ctx)
	if !ok || b.RPS > own.RPS || b.Inflight > own.Inflight {
		return own
	}
	return b
}
