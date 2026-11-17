package main

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// SECURITY: pacing.budget@1 is reported only by a sensor that verifies job
// signatures. A job's budget is read from its verified statement alone, so
// a sensor with no pinned job key runs every job at its own level; it must
// not tell the platform that it honours a signed budget.
func TestHostBudgetCapabilityNeedsVerifiedJobs(t *testing.T) {
	reg := core.NewToolRegistry()
	advertiseHostBudget(reg, false)
	if slices.Contains(reg.CapabilityReport(t.Context()).Capabilities, core.CapabilityHostBudget) {
		t.Fatal("a sensor that does not verify job signatures reports pacing.budget@1")
	}
	advertiseHostBudget(reg, true)
	if !slices.Contains(reg.CapabilityReport(t.Context()).Capabilities, core.CapabilityHostBudget) {
		t.Fatal("a sensor that verifies job signatures does not report pacing.budget@1")
	}
	// The posture is decided once; should it be asked again without a key,
	// the capability is withdrawn.
	advertiseHostBudget(reg, false)
	if slices.Contains(reg.CapabilityReport(t.Context()).Capabilities, core.CapabilityHostBudget) {
		t.Fatal("the capability stayed after it was withdrawn")
	}
}
