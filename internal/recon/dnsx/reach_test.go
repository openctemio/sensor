package dnsx

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
)

func TestReachObservations(t *testing.T) {
	out := []byte(`{"host":"a.example.com","a":["192.0.2.1"]}` + "\n")
	res := &core.ReconResult{RawOutput: out}
	obs := NewScanner().ReachObservations("a.example.com,b.example.com", res)
	if len(obs) != 1 || obs[0].Target != "b.example.com" || obs[0].Class != reach.DNSFailure {
		t.Fatalf("observations = %+v, want b.example.com not resolved", obs)
	}

	// A run that asked only for TXT records says nothing about a name
	// without them.
	s := NewScanner()
	s.RecordTypes = []string{"TXT"}
	if got := s.ReachObservations("a.example.com,b.example.com", res); len(got) != 0 {
		t.Fatalf("TXT-only run recorded %+v", got)
	}
	// A failed run is classified by its error (recon.Scanner), not here.
	if got := NewScanner().ReachObservations("b.example.com", &core.ReconResult{Error: "x"}); len(got) != 0 {
		t.Fatalf("failed run recorded %+v", got)
	}
}
