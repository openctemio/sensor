package naabu

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// Each open port was reached; a host with none is not recorded.
func TestReachObservations(t *testing.T) {
	res := &core.ReconResult{OpenPorts: []core.OpenPort{
		{Host: "app.example.com", IP: "192.0.2.10", Port: 443},
		{Host: "192.0.2.11", Port: 22},
	}}
	obs := NewScanner().ReachObservations("192.0.2.0/24", res)
	if len(obs) != 2 || obs[0].Addr != "192.0.2.10" || obs[1].Addr != "192.0.2.11" || obs[1].Port != 22 {
		t.Fatalf("observations = %+v", obs)
	}
	for _, o := range obs {
		if o.Class != reach.Reached || o.Target != "192.0.2.0/24" {
			t.Fatalf("observation %+v", o)
		}
	}
	if got := NewScanner().ReachObservations("192.0.2.12", &core.ReconResult{}); len(got) != 0 {
		t.Fatalf("no open ports recorded as %+v", got)
	}
}
