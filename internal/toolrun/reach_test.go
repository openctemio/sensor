package toolrun

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/reachobs"
)

// reachTool, in the tool child: "up.example" answered, "noroute.example"
// has no route (an unreachable target), and the report also names a host
// outside the task. With "fail.example" among the targets the run fails
// after attaching what it saw.
var reachTool = tool.New(tool.Manifest{
	Name: "echo-reach", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces:    []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetTargets},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var obs []reachobs.Obs
	fail := false
	for _, t := range task.Targets {
		switch t.Value {
		case "up.example":
			obs = append(obs, reachobs.Obs{Target: t.Value, Addr: "203.0.113.5", Port: 443, Class: reach.Reached})
			ctx.TargetDone(t)
		case "noroute.example":
			ctx.TargetError(t, tool.Unreachable(errors.New("dial tcp 10.9.0.5:443: connect: no route to host")))
		case "fail.example":
			fail = true
			obs = append(obs, reachobs.Obs{Target: t.Value, Class: reach.Timeout, Detail: "i/o timeout"})
		}
	}
	obs = append(obs, reachobs.Obs{Target: "outside.example", Class: reach.NoRoute})
	r := ctis.NewReport()
	reachobs.Attach(r, obs)
	if err := ctx.Emit().Report(r); err != nil {
		return err
	}
	if fail {
		return tool.Failed(errors.New("the run failed"))
	}
	return nil
})

func runReach(t *testing.T, targets []string) (reach.Report, *toolhost.Outcome, []byte, error) {
	t.Helper()
	rec := reach.NewRecorder()
	ctx := reach.WithRecorder(context.Background(), rec)
	res, out, err := Run(ctx, reachTool, targets, struct{}{}, toolhost.RunOptions{})
	var raw []byte
	if res != nil {
		raw = res.RawOutput
	}
	return rec.Report(), out, raw, err
}

// What the tool child saw toward its targets reaches the job's recorder:
// its attached observations and its unreachable targets; the property
// never reaches the report the platform gets, and a host outside the task
// is never recorded.
func TestRun_RecordsReachOutcomes(t *testing.T) {
	rep, _, raw, err := runReach(t, []string{"up.example", "noroute.example"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Targets != 2 || rep.Reached != 1 || rep.Classes[reach.NoRoute] != 1 {
		t.Fatalf("summary = %+v", rep.Summary)
	}
	if strings.Contains(string(raw), reachobs.Property) {
		t.Fatalf("the observations reached the report:\n%s", raw)
	}
	for _, u := range rep.UnreachedList {
		if u.Target == "outside.example" {
			t.Fatal("SECURITY: a host outside the task was recorded")
		}
	}
}

// A failed run still records what it saw.
func TestRun_FailedRunRecordsReachOutcomes(t *testing.T) {
	rep, _, _, err := runReach(t, []string{"fail.example"})
	if err == nil {
		t.Fatal("the run did not fail")
	}
	if rep.Unreached != 1 || rep.Classes[reach.Timeout] != 1 {
		t.Fatalf("summary = %+v", rep.Summary)
	}
}
