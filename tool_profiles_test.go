package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Every built-in tool declares its resource profile (research/318): the
// envelope its tasks run under and what the governor sizes for. Network-
// bound lookups are light; scanners that hold many connections or large
// rule sets are heavy.
func TestBuiltinResourceProfiles(t *testing.T) {
	want := map[string]string{
		"subfinder": tool.ProfileLight, "dnsx": tool.ProfileLight, "dnsx-enum": tool.ProfileLight,
		"rdap": tool.ProfileLight, "asn": tool.ProfileLight, "nuclei-validate": tool.ProfileLight,
		"httpx": tool.ProfileStandard, "katana": tool.ProfileStandard,
		"nuclei": tool.ProfileHeavy, "naabu": tool.ProfileHeavy, "trivy": tool.ProfileHeavy,
		"betterleaks": tool.ProfileHeavy, "opengrep": tool.ProfileHeavy, "semgrep": tool.ProfileHeavy,
		"codeql": tool.ProfileHeavy,
	}
	for _, tl := range toolrun.Registered() {
		m := tl.Manifest()
		got, ok := want[m.Name]
		if !ok {
			t.Errorf("%s: no expected profile in this test", m.Name)
			continue
		}
		if m.Resources.Profile != got {
			t.Errorf("%s: profile %q, want %q", m.Name, m.Resources.Profile, got)
		}
		if e := m.Resources.Envelope(); e.MemoryMax <= 0 || e.CPU <= 0 || e.Pids <= 0 {
			t.Errorf("%s: envelope %+v", m.Name, e)
		}
	}
	// The code analysers need more memory than the heavy default.
	for _, name := range []string{"codeql", "semgrep", "opengrep"} {
		for _, tl := range toolrun.Registered() {
			if m := tl.Manifest(); m.Name == name && m.Resources.Envelope().MemoryMax <= 4<<30 {
				t.Errorf("%s: memory %d, want above 4 GiB", name, m.Resources.Envelope().MemoryMax)
			}
		}
	}
}
