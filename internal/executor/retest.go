package executor

import (
	"context"
	"fmt"

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
// and the local policy's rate. A target the guard refuses fails the
// command (the platform settles its items as unknown).
func (e *ValidatingCommandExecutor) RetestNuclei(ctx context.Context, task tool.Task) (*toolhost.Outcome, error) {
	for _, t := range task.Targets {
		if err := validateScannerTarget(t.Value); err != nil {
			return nil, fmt.Errorf("retest: target refused by the validate guard: %w", err)
		}
	}
	var set nucleiTemplateSet
	release := func() {}
	if e.nucleiTemplates != nil {
		set.dir, set.content, release = e.nucleiTemplates()
	}
	defer release()
	fmt.Printf("[retest:nuclei] command=%s targets=%d items=%d\n", task.ID, len(task.Targets), len(task.Retest))
	return nuclei.Retest(ctx, nuclei.ValidateOptions{
		TimeoutSeconds:   120,
		RateLimit:        nucleiValidateRateLimit,
		MaxRateLimit:     e.local.Load().CapRate(validateRateCeiling()),
		TemplatesDir:     set.dir,
		TemplatesVersion: set.content.Version,
		Verbose:          e.verbose,
	}, task)
}
