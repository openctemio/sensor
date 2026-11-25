package toolrun_test

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/imageprofile"
	"github.com/openctemio/sensor/internal/toolrun"
	"github.com/openctemio/sensor/internal/webguess"
)

func names() []string {
	var out []string
	for _, t := range toolrun.Registered() {
		out = append(out, t.Manifest().Name)
	}
	return out
}

// SECURITY: in the passive profile a compiled-in tool above T0 is not
// registered (so it is neither listed nor runnable); a T0 one is. The
// standard profile registers both.
func TestRegisterCompiledInByProfile(t *testing.T) {
	old := imageprofile.Name
	t.Cleanup(func() { imageprofile.Name = old })
	mk := func(name, tier string) tool.Tool {
		m := webguess.Manifest
		m.Name, m.Tier = name, tool.Tier(tier)
		m.Implements = nil
		return tool.New(m, func(tool.Context, tool.Task, []byte) error { return nil })
	}
	imageprofile.Name = "passive"
	toolrun.RegisterCompiledIn(mk("zz-passive-t1", "T1"))
	toolrun.RegisterCompiledIn(mk("zz-passive-t0", "T0"))
	got := names()
	if slices.Contains(got, "zz-passive-t1") || !slices.Contains(got, "zz-passive-t0") {
		t.Fatalf("passive profile registered %v", got)
	}
	imageprofile.Name = ""
	toolrun.RegisterCompiledIn(mk("zz-std-t1", "T1"))
	if !slices.Contains(names(), "zz-std-t1") {
		t.Fatal("the standard profile did not register a T1 tool")
	}
}

// SECURITY: a binary of the relay profile registers no tool of any tier,
// compiled in or engine-backed: `tools manifests` is empty and the tool
// child has nothing to run.
func TestRelayProfileRegistersNoTool(t *testing.T) {
	old := imageprofile.Name
	t.Cleanup(func() { imageprofile.Name = old })
	mk := func(name, tier string) tool.Tool {
		m := webguess.Manifest
		m.Name, m.Tier = name, tool.Tier(tier)
		m.Implements = nil
		return tool.New(m, func(tool.Context, tool.Task, []byte) error { return nil })
	}
	imageprofile.Name = imageprofile.NameRelay
	toolrun.RegisterCompiledIn(mk("zz-relay-builtin-t0", "T0"))
	toolrun.RegisterCompiledIn(mk("zz-relay-builtin-t1", "T1"))
	toolrun.Register(mk("zz-relay-engine-t0", "T0"))
	toolrun.Register(mk("zz-relay-engine-t2", "T2"))
	for _, n := range names() {
		if len(n) > 9 && n[:9] == "zz-relay-" {
			t.Fatalf("the relay profile registered %s", n)
		}
	}
}
