package toolrun

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

// echoTool reports one finding per target it receives: a target missing
// from its report never reached the child.
var echoTool = tool.New(tool.Manifest{
	Name: "echo-admission", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces:    []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetTargets},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	for _, t := range task.Targets {
		if err := ctx.Emit().Finding(t, ctis.Finding{Type: "misconfiguration", RuleID: "seen", Title: "seen " + t.Value, Severity: "info"}); err != nil {
			return err
		}
		ctx.TargetDone(t)
	}
	return nil
})

func TestMain(m *testing.M) {
	adapter.Dispatch(echoTool)
	os.Exit(m.Run())
}

// fakePolicy refuses the targets in deny and the tools not in allow.
type fakePolicy struct {
	mu      sync.Mutex
	deny    map[string]bool
	allow   map[string]bool
	checked []string
}

func (p *fakePolicy) AllowsTool(name string) bool { return p.allow == nil || p.allow[name] }

func (p *fakePolicy) CheckTarget(_ context.Context, target string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked = append(p.checked, target)
	if p.deny[target] {
		return errors.New("denied by targets.deny")
	}
	return nil
}

func (p *fakePolicy) CapTimeout(d time.Duration) time.Duration { return d }

func (p *fakePolicy) KillSwitchEngaged() bool { return false }

func withAdmission(t *testing.T, p *fakePolicy) {
	t.Helper()
	SetAdmission(p, tool.Daemon)
	t.Cleanup(func() { SetAdmission(nil, "") })
}

// A target the local policy refuses never reaches the tool child; the
// others run, and the report names the refused one.
func TestRefusedTargetNeverReachesTheTool(t *testing.T) {
	p := &fakePolicy{deny: map[string]bool{"refused.example": true}}
	withAdmission(t, p)
	res, out, err := Run(context.Background(), echoTool, []string{"ok.example", "refused.example"}, struct{}{}, toolhost.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(res.RawOutput)
	if !strings.Contains(raw, "seen ok.example") {
		t.Fatalf("the admitted target did not run:\n%s", raw)
	}
	if strings.Contains(raw, "seen refused.example") {
		t.Fatal("the refused target reached the tool")
	}
	if !strings.Contains(raw, `"refused_targets"`) || !strings.Contains(raw, "refused_by_policy") {
		t.Fatalf("the report does not name the refused target:\n%s", raw)
	}
	r := Refused(out)
	if len(r) != 1 || r[0].Value != "refused.example" || r[0].State != tool.StateSkipped {
		t.Fatalf("refused outcomes %+v", r)
	}
	if len(p.checked) != 2 {
		t.Fatalf("policy checked %v", p.checked)
	}
}

// A task with every target refused, or a tool the policy does not allow,
// fails before any child starts.
func TestFullyRefusedTaskFails(t *testing.T) {
	withAdmission(t, &fakePolicy{deny: map[string]bool{"refused.example": true}})
	if _, _, err := Run(context.Background(), echoTool, []string{"refused.example"}, struct{}{}, toolhost.RunOptions{}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("got %v", err)
	}
	withAdmission(t, &fakePolicy{allow: map[string]bool{"nuclei": true}})
	if _, _, err := Run(context.Background(), echoTool, []string{"ok.example"}, struct{}{}, toolhost.RunOptions{}); err == nil || !strings.Contains(err.Error(), "tools.allow") {
		t.Fatalf("got %v", err)
	}
}

// The mode reaches every task's admission.
func TestModeReachesTheTask(t *testing.T) {
	SetAdmission(nil, tool.Runner)
	t.Cleanup(func() { SetAdmission(nil, "") })
	if _, o := current(toolhost.RunOptions{}); o.Mode != tool.Runner {
		t.Fatalf("mode %q", o.Mode)
	}
}
