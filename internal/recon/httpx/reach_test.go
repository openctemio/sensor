package httpx

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// httpx -json -probe output: one URL that answered, one with no route,
// one refused, one name with no address.
const probeOutput = `{"url":"https://app.example.com","input":"app.example.com","host_ip":"203.0.113.10","port":"443","scheme":"https","status_code":200,"failed":false}
{"url":"https://10.9.0.5","input":"10.9.0.5","failed":true,"error":"no route to host"}
{"url":"http://app.example.com:8080","input":"app.example.com","failed":true,"error":"connection refused"}
{"url":"https://gone.example.com","input":"gone.example.com","failed":true,"error":"no address found for host"}
{"url":"https://odd.example.com","input":"odd.example.com","failed":true,"error":"something else"}
`

func TestBuildArgs_ProbeReportsFailures(t *testing.T) {
	got := NewScanner().buildArgs("example.com", nil)
	if !slices.Contains(got, "-probe") {
		t.Fatalf("args = %q, want -probe with -json", got)
	}
}

// A URL that did not answer is never a live host.
func TestParseOutput_FailedLinesAreNotLiveHosts(t *testing.T) {
	hosts, _, err := NewScanner().parseOutput([]byte(probeOutput))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].URL != "https://app.example.com" {
		t.Fatalf("live hosts = %+v, want only the URL that answered", hosts)
	}
}

func TestReachObservations(t *testing.T) {
	obs := NewScanner().ReachObservations("app.example.com", &core.ReconResult{RawOutput: []byte(probeOutput)})
	want := []struct {
		class reach.Class
		addr  string
		port  int
	}{
		{reach.Reached, "203.0.113.10", 443},
		{reach.NoRoute, "", 443},
		{reach.PortClosed, "", 8080},
		{reach.DNSFailure, "", 443},
	}
	if len(obs) != len(want) {
		t.Fatalf("observations = %+v, want %d (the unclassified failure left out)", obs, len(want))
	}
	for i, w := range want {
		o := obs[i]
		if o.Class != w.class || o.Addr != w.addr || o.Port != w.port || o.Target != "app.example.com" {
			t.Errorf("obs[%d] = %+v, want %+v", i, o, w)
		}
	}
	if NewScanner().ReachObservations("x", nil) != nil {
		t.Fatal("a nil result made observations")
	}
}
