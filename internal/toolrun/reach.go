package toolrun

import (
	"context"

	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/reachobs"
)

// recordReach records what a task saw toward its targets into the job's
// reach recorder (sdk-go pkg/reach, api RFC-089): the observations the tool
// attached to its report (taken off the report: they never reach the
// platform as a property), and each target the tool reported unreachable,
// classified by its message. Only outcomes toward the task's own targets
// count (reachobs.Record).
func recordReach(ctx context.Context, targets []string, out *toolhost.Outcome) {
	if out == nil {
		return
	}
	obs := reachobs.Take(out.Report)
	for _, to := range out.Targets {
		if to.State == tool.StateFailed && to.Class == tool.TargetUnreachable {
			if o, ok := reachobs.Failure(to.Value, to.Detail); ok {
				obs = append(obs, o)
			}
		}
	}
	reachobs.Record(ctx, targets, obs)
}
