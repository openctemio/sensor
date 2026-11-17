package main

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// SECURITY: every tool the sensor compiles in says what it sends to its
// targets (internal/toolrun/traffic.go), and that agrees with the network
// class of its manifest: a tool that connects to its targets is paced, by
// the per-host budget or, for the port scan alone, by the level's packets
// per second. A new tool that connects to its targets and is not listed
// fails here (and is refused when it starts).
func TestEveryToolHasATrafficKind(t *testing.T) {
	tools := toolrun.Registered()
	if len(tools) < 15 {
		t.Fatalf("only %d tools are registered in this binary", len(tools))
	}
	kinds := toolrun.TrafficKinds()
	var packets, requests []string
	for _, tl := range tools {
		m := tl.Manifest()
		kind, ok := kinds[m.Name]
		if !ok {
			t.Errorf("%s (network %q) has no traffic kind in internal/toolrun/traffic.go", m.Name, m.Permissions.Network)
			continue
		}
		delete(kinds, m.Name)
		toTargets := m.Permissions.Network == tool.NetTargets
		switch {
		case toTargets && kind == toolrun.NoTargetTraffic:
			t.Errorf("%s connects to its targets (network targets) and is listed as sending them nothing", m.Name)
		case !toTargets && kind != toolrun.NoTargetTraffic:
			t.Errorf("%s (network %q) cannot reach its targets and is listed as sending to them", m.Name, m.Permissions.Network)
		}
		switch kind {
		case toolrun.TargetPackets:
			packets = append(packets, m.Name)
		case toolrun.TargetRequests:
			requests = append(requests, m.Name)
		}
	}
	for name := range kinds {
		t.Errorf("%s is listed in internal/toolrun/traffic.go and is not a tool of this binary", name)
	}
	// The one tool that is not held to the request budget. Another one is
	// a decision to make and to document (docs/REFERENCE.md, "Per-host
	// budget"), not a line to add.
	if !slices.Equal(packets, []string{"naabu"}) {
		t.Errorf("tools paced in packets, not by the request budget: %v, want naabu alone", packets)
	}
	slices.Sort(requests)
	want := []string{"httpx", "katana", "nuclei", "nuclei-validate", "svcdetect", "webguess", "webshot"}
	if !slices.Equal(requests, want) {
		t.Errorf("tools under the per-host budget: %v, want %v (update the docs with the list)", requests, want)
	}
}
