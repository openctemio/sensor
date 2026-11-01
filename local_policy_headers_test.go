package main

import (
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// The example for a sensor's own headers loads, follows the platform's scope,
// and its headers reach the tool host as an HTTPHeaderPolicy.
func TestLocalPolicyHeadersExample(t *testing.T) {
	data, err := os.ReadFile("docs/sensor-policy-headers.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	lp, err := core.ParseLocalPolicy(data, core.LocalPolicyOptions{LookupEnv: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatalf("the example does not load: %v", err)
	}
	var pol toolhost.Policy = lp
	hp, ok := pol.(toolhost.HTTPHeaderPolicy)
	if !ok {
		t.Fatal("the local policy no longer gives the tool host its headers")
	}
	hs := hp.HTTPHeaders()
	if len(hs) != 1 || hs[0].Name != "X-Netops" || hs[0].Value != "dc1" {
		t.Fatalf("headers %+v", hs)
	}
	if r := lp.Report(); r.Summary.Mode != "platform_scope" || r.Schema != "v1" {
		t.Fatalf("the example must not narrow or widen the scope: %+v", r.Summary)
	}
}

// http.identity@1 and its tool-by-tool consequences: nuclei, httpx and katana
// carry the merged headers (sensor-local ones included) on their header flags,
// and none declares features.http_query, so a job's query parameter is
// reported "not applied" for them, never silently sent without effect.
func TestBuiltinHTTPToolsCarryHeadersAndReportQueryNotApplied(t *testing.T) {
	id := &tool.Identity{UserAgent: "dc1-scan", Headers: map[string]string{"X-Netops": "dc1", "ATTT": "is-here"}}
	want := []string{"User-Agent: dc1-scan", "ATTT: is-here", "X-Netops: dc1"}
	for _, name := range []string{"nuclei", "httpx", "katana"} {
		var found bool
		for _, tl := range toolrun.Registered() {
			m := tl.Manifest()
			if m.Name != name {
				continue
			}
			found = true
			if m.Features == nil || !m.Features.HTTPIdentity {
				t.Errorf("%s must declare features.http_identity", name)
			}
			if m.Features != nil && m.Features.HTTPQuery {
				t.Errorf("%s declares features.http_query but has no flag for it", name)
			}
		}
		if !found {
			t.Fatalf("%s is not registered", name)
		}
		// The configured header the identification names is replaced.
		got := toolrun.IdentityHeaders(tool.Task{Identity: id}, []string{"x-netops: tool", "Accept: */*"})
		if len(got) != 4 || got[0] != "Accept: */*" || got[1] != want[0] || got[2] != want[1] || got[3] != want[2] {
			t.Errorf("%s: header lines %q", name, got)
		}
	}
}
