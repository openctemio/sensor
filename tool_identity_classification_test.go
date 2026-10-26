package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/reachprobe"
	"github.com/openctemio/sensor/internal/recon"
	"github.com/openctemio/sensor/internal/toolrun"
)

// identityClass is how a built-in tool stands toward a job's
// identification (a bug-bounty program's User-Agent and headers, which are
// HTTP): the network it reaches, whether it sends HTTP to the job's
// targets (so must carry the identification), and whether it can.
type identityClass struct {
	network  tool.Network
	httpToTG bool // sends HTTP(S) to the targets: the identification is required
	canSend  bool // declares features.http_identity
}

// SECURITY: every built-in tool's classification toward the job's
// identification, from its descriptor alone (sdk-go
// tool.Manifest.SendsHTTPToTargets, the rule the tool host enforces):
//
//   - a tool that sends HTTP to its targets declares features.http_identity
//     and receives the identification, or its tasks are refused;
//   - DNS resolution (dnsx), passive third-party sources (subfinder, rdap,
//     asn), a TCP connect port scan (naabu), registries and vulnerability
//     databases (trivy, semgrep, codeql) and offline analysis (opengrep,
//     betterleaks) never send HTTP to the program's targets: an
//     identification-carrying job runs them, without the identification.
//
// A new built-in tool without an entry here fails the test.
func TestBuiltinToolIdentityClassification(t *testing.T) {
	want := map[string]identityClass{
		"subfinder":       {tool.NetEgressProxy, false, false},
		"dnsx":            {tool.NetResolver, false, false},
		"dnsx-enum":       {tool.NetResolver, false, false},
		"naabu":           {tool.NetTargets, false, false},
		"httpx":           {tool.NetTargets, true, true},
		"katana":          {tool.NetTargets, true, true},
		"nuclei":          {tool.NetTargets, true, true},
		"nuclei-validate": {tool.NetTargets, true, true},
		"semgrep":         {tool.NetEgressProxy, false, false},
		"opengrep":        {tool.NetNone, false, false},
		"codeql":          {tool.NetEgressProxy, false, false},
		"trivy":           {tool.NetEgressProxy, false, false},
		"betterleaks":     {tool.NetNone, false, false},
		"rdap":            {tool.NetEgressProxy, false, false},
		"asn":             {tool.NetEgressProxy, false, false},
	}
	seen := map[string]bool{}
	for _, tl := range toolrun.Registered() {
		m := tl.Manifest()
		seen[m.Name] = true
		exp, ok := want[m.Name]
		if !ok {
			t.Errorf("%s: a built-in tool without an identification classification here", m.Name)
			continue
		}
		got := identityClass{
			network:  m.Normalized().Permissions.Network,
			httpToTG: m.SendsHTTPToTargets(""),
			canSend:  m.Features != nil && m.Features.HTTPIdentity,
		}
		if got != exp {
			t.Errorf("%s: %+v, want %+v", m.Name, got, exp)
		}
		// Every capability task agrees with the tool as a whole: a tool
		// that sends HTTP to its targets cannot have an exempt capability
		// task, and the reverse.
		for _, im := range m.Implements {
			if m.SendsHTTPToTargets(im.Capability) != exp.httpToTG {
				t.Errorf("%s: its %s task disagrees with the tool's classification", m.Name, im.Capability)
			}
		}
		// Fail closed: a tool that must carry the identification and
		// cannot is a hole, never an accepted classification.
		if exp.httpToTG && !exp.canSend {
			t.Errorf("%s sends HTTP to its targets but cannot send the identification", m.Name)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s is not registered", name)
		}
	}

	// The recon tools that declare features.http_identity apply it
	// themselves (WithIdentity); the sensor refuses a declared tool that
	// cannot rather than probing without it.
	type identityTool interface {
		WithIdentity(*tool.Identity) (core.ReconScanner, error)
	}
	for _, name := range []string{"subfinder", "dnsx", "naabu", "httpx", "katana"} {
		s, err := recon.New(name)
		if err != nil {
			t.Fatal(err)
		}
		_, applies := s.Recon().(identityTool)
		if applies != want[name].canSend {
			t.Errorf("%s: applies the identification %v, its descriptor says %v", name, applies, want[name].canSend)
		}
	}
}

// reach-probe is not a tool-host tool: one TCP connect per admitted
// address and port, no payload, so no HTTP and no identification. It is
// served beside the tool host (addReachProbe) and implements only
// reach.probe@1.
func TestReachProbeSendsNoHTTP(t *testing.T) {
	for _, tl := range toolrun.Registered() {
		if tl.Manifest().Name == reachprobe.Name {
			t.Fatal("reach-probe became a tool-host tool: give it a classification above")
		}
	}
	caps := reachprobe.New(nil).Capabilities()
	if len(caps) != 1 || caps[0] != reachprobe.Capability || reachprobe.Capability != "reach.probe@1" {
		t.Fatalf("reach-probe capabilities %v", caps)
	}
}
