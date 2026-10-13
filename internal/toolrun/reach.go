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
// count (reachobs.Record), and only for a tool that reaches its targets
// (or resolves their names): a passive tool's failure, a source API that
// timed out, says nothing about a path to the target. The observations are
// taken off every tool's report either way.
func recordReach(ctx context.Context, m tool.Manifest, targets []string, out *toolhost.Outcome) {
	if out == nil {
		return
	}
	obs := reachobs.Take(out.Report)
	if n := m.Permissions.Network; n != tool.NetTargets && n != tool.NetResolver {
		return
	}
	for _, to := range out.Targets {
		if to.State == tool.StateFailed && to.Class == tool.TargetUnreachable {
			if o, ok := reachobs.Failure(to.Value, to.Detail); ok {
				obs = append(obs, o)
			}
		}
	}
	reachobs.Record(ctx, targets, obs)
}
