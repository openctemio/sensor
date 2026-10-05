package nuclei

import (
	"context"
	"net"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// A retest of nuclei findings runs out of process: a finding whose template
// matches again is still present, one whose template ran on the reachable
// target and did not match is fixed, one whose template cannot run is
// unverifiable, and every finding on an unreachable target is unverifiable,
// never fixed.
func TestRetestNucleiFindings(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	bin := fakeNucleiBin(t)
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = up.Close() }()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	down, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	downAddr := down.Addr().String()
	_ = down.Close()

	task := tool.Task{
		ID: "retest-1",
		Targets: []tool.Target{
			{Ref: "t1", Value: "http://" + up.Addr().String()},
			{Ref: "t2", Value: "http://" + downAddr},
		},
		Retest: []tool.RetestItem{
			{Ref: "f-detect", Target: "t1", Kind: tool.RetestFinding, RuleID: "clean-detect"},
			{Ref: "f-nomatch", Target: "t1", Kind: tool.RetestFinding, RuleID: "clean-nomatch"},
			{Ref: "f-notinstalled", Target: "t1", Kind: tool.RetestFinding, RuleID: "not-installed"},
			{Ref: "f-down", Target: "t2", Kind: tool.RetestFinding, RuleID: "clean-nomatch"},
		},
	}
	out, err := Retest(context.Background(), ValidateOptions{Binary: bin, Target: "http://ignored.example", TemplateID: "ignored"}, task)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]tool.Verdict{}
	for _, v := range out.Verdicts {
		got[v.Ref] = v.Verdict
	}
	want := map[string]tool.Verdict{
		"f-detect": tool.StillPresent, "f-nomatch": tool.Fixed, "f-notinstalled": tool.Unverifiable, "f-down": tool.Unverifiable,
	}
	for ref, v := range want {
		if got[ref] != v {
			t.Errorf("%s: %s, want %s (verdicts %+v, stderr %s)", ref, got[ref], v, out.Verdicts, out.Stderr)
		}
	}
	if len(out.Report.Findings) != 0 {
		t.Fatalf("a retest delivered findings: %+v", out.Report.Findings)
	}
}

func TestValidateToolDeclaresRetest(t *testing.T) {
	if !ValidateTool.Manifest().Retest {
		t.Fatal("nuclei-validate must declare retest")
	}
	if _, ok := ValidateTool.(tool.Retester); !ok {
		t.Fatal("nuclei-validate has no retest handler")
	}
}
