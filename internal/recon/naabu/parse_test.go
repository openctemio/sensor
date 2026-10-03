package naabu

import (
	"os"
	"testing"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// Real naabu 2.6.1 output (127.0.0.1); naabu repeats a port on retries.
func TestParseOutput_Real(t *testing.T) {
	data, err := os.ReadFile(flagcheck.Testdata("naabu-2.6.1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ports, err := NewScanner().parseOutput(data)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, p := range ports {
		if p.IP != "127.0.0.1" && p.Host != "127.0.0.1" {
			t.Errorf("port %+v has no host", p)
		}
		seen[p.Port] = true
	}
	if !seen[22] || !seen[5432] || len(ports) != 2 {
		t.Fatalf("ports = %+v", ports)
	}
}
