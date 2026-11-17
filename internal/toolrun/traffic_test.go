package toolrun

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: a tool that sends requests to its targets is never started
// without a per-host budget, on any of the three ways a tool is run, and a
// tool that connects to its targets without a traffic kind is not started
// at all. The refusal comes before the tool host is asked: nothing runs.
func TestToolThatSendsToTargetsIsNotStartedWithoutABudget(t *testing.T) {
	ran := false
	fake := func(name string, network tool.Network) tool.Tool {
		return tool.New(tool.Manifest{Name: name, Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
			Produces:    []string{"finding:misconfiguration"},
			Permissions: tool.Permissions{Network: network}}, func(tool.Context, tool.Task, tool.NoConfig) error {
			ran = true
			return nil
		})
	}
	requests := 0
	for name, kind := range TrafficKinds() {
		if kind != TargetRequests {
			continue
		}
		requests++
		tl := fake(name, tool.NetTargets)
		for _, o := range []toolhost.RunOptions{{}, {HostBudget: &adapt.HostBudget{}}} {
			if _, _, err := Run(context.Background(), tl, []string{"https://a.example.com/"}, nil, o); !errors.Is(err, ErrNoHostBudget) {
				t.Errorf("Run of %s without a budget: %v", name, err)
			}
			if _, _, err := RunRaw(context.Background(), tl, []string{"https://a.example.com/"}, nil, o); !errors.Is(err, ErrNoHostBudget) {
				t.Errorf("RunRaw of %s without a budget: %v", name, err)
			}
			task := tool.Task{Targets: Targets([]string{"https://a.example.com/"}, "")}
			if _, err := RunTask(context.Background(), tl, task, o); !errors.Is(err, ErrNoHostBudget) {
				t.Errorf("RunTask of %s without a budget: %v", name, err)
			}
		}
		if err := requireBudget(tl.Manifest(), toolhost.RunOptions{HostBudget: BudgetFor(adapt.DefaultBudget(), nil)}); err != nil {
			t.Errorf("%s with a budget: %v", name, err)
		}
	}
	if requests < 7 {
		t.Fatalf("only %d tools are listed as sending requests to their targets", requests)
	}
	// A tool that connects to its targets and is not listed is refused.
	if _, _, err := Run(context.Background(), fake("unlisted-scanner", tool.NetTargets), []string{"https://a.example.com/"}, nil,
		toolhost.RunOptions{HostBudget: BudgetFor(adapt.DefaultBudget(), nil)}); err == nil {
		t.Error("an unlisted tool that connects to its targets was started")
	}
	// Tools that send nothing to their targets need none. The port scan is
	// started with the budget and says that it probes ports; nothing else
	// may say so, and the port scan may not leave it out.
	withBudget := toolhost.RunOptions{HostBudget: BudgetFor(adapt.DefaultBudget(), nil)}
	probes := withBudget
	probes.PortProbes = true
	for name, kind := range TrafficKinds() {
		switch kind {
		case NoTargetTraffic:
			if err := requireBudget(fake(name, tool.NetNone).Manifest(), toolhost.RunOptions{}); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if err := requireBudget(fake(name, tool.NetNone).Manifest(), probes); err == nil {
				t.Errorf("%s was started as a port scan", name)
			}
		case TargetPackets:
			m := fake(name, tool.NetTargets).Manifest()
			if err := requireBudget(m, probes); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if err := requireBudget(m, toolhost.RunOptions{PortProbes: true}); !errors.Is(err, ErrNoHostBudget) {
				t.Errorf("%s without a budget: %v", name, err)
			}
			if err := requireBudget(m, withBudget); err == nil {
				t.Errorf("%s was started without saying that it probes ports", name)
			}
		case TargetRequests:
			if err := requireBudget(fake(name, tool.NetTargets).Manifest(), probes); err == nil {
				t.Errorf("%s was started as a port scan: it would leave the budget's requests per second", name)
			}
		}
	}
	if ran {
		t.Fatal("a refused tool ran")
	}
}

// SECURITY: a tool whose manifest says network egress-proxy may reach any
// public host, its targets included: it is not started without a per-host
// budget, listed or not, on any of the ways a tool is run, and starts with
// one. The compiled-in tools of that network (trivy, semgrep, codeql,
// rdap, asn) are started with the scan's budget.
func TestEgressProxyToolIsNotStartedWithoutABudget(t *testing.T) {
	ran := false
	proxied := func(name string) tool.Tool {
		return tool.New(tool.Manifest{Name: name, Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
			Produces:    []string{"finding:misconfiguration"},
			Permissions: tool.Permissions{Network: tool.NetEgressProxy}}, func(tool.Context, tool.Task, tool.NoConfig) error {
			ran = true
			return nil
		})
	}
	for _, name := range []string{"trivy", "rdap", "unlisted-proxied"} {
		tl := proxied(name)
		for _, o := range []toolhost.RunOptions{{}, {HostBudget: &adapt.HostBudget{}}} {
			if _, _, err := Run(context.Background(), tl, []string{"https://a.example.com/"}, nil, o); !errors.Is(err, ErrNoHostBudget) {
				t.Errorf("Run of %s without a budget: %v", name, err)
			}
			if _, _, err := RunRaw(context.Background(), tl, []string{"https://a.example.com/"}, nil, o); !errors.Is(err, ErrNoHostBudget) {
				t.Errorf("RunRaw of %s without a budget: %v", name, err)
			}
			task := tool.Task{Targets: Targets([]string{"https://a.example.com/"}, "")}
			if _, err := RunTask(context.Background(), tl, task, o); !errors.Is(err, ErrNoHostBudget) {
				t.Errorf("RunTask of %s without a budget: %v", name, err)
			}
		}
		if err := requireBudget(tl.Manifest(), toolhost.RunOptions{HostBudget: BudgetFor(adapt.DefaultBudget(), nil)}); err != nil {
			t.Errorf("%s with a budget: %v", name, err)
		}
	}
	if ran {
		t.Fatal("a refused tool ran")
	}
}

// What a setting asked for above the budget and what applies travels with
// the run's budget; the scan's own budget is not written to.
func TestBudgetForCarriesTheClamps(t *testing.T) {
	scan := adapt.ResolveBudget(adapt.PacingFast, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	before := len(scan.Clamped)
	clamps := []adapt.BudgetClamp{{Key: "rate_limit", Asked: 150, To: 5, By: adapt.LimitHostBudget}}
	b := BudgetFor(scan, clamps)
	if len(b.Clamped) != before+1 || b.Clamped[before] != clamps[0] || len(scan.Clamped) != before {
		t.Fatalf("run budget %+v, scan budget %+v", b.Clamped, scan.Clamped)
	}
	s := InProcessRate(scan, clamps)
	if s.Budget == nil || !reflect.DeepEqual(s.Budget.Clamped, b.Clamped) || s.Limited != adapt.PacingLimitedNoForwarder {
		t.Fatalf("in-process outcome %+v", s)
	}
}

func TestCapRate(t *testing.T) {
	for _, tc := range []struct {
		name             string
		rate, def, limit int
		want             int
		clamp            bool
	}{
		{"unset, the default is under the limit", 0, 5, 20, 0, false},
		{"unset, the default is above the limit", 0, 50, 20, 20, false},
		{"set under the limit", 10, 5, 20, 10, false},
		{"set above the limit", 50, 5, 20, 20, true},
	} {
		got, clamps := CapRate("rate", tc.rate, tc.def, tc.limit)
		if got != tc.want || (len(clamps) == 1) != tc.clamp {
			t.Errorf("%s: %d %+v", tc.name, got, clamps)
		}
		if tc.clamp && clamps[0] != (adapt.BudgetClamp{Key: "rate", Asked: tc.rate, To: tc.limit, By: adapt.LimitHostBudget}) {
			t.Errorf("%s: clamp %+v", tc.name, clamps[0])
		}
	}
}
