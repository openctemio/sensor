package httpx

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// SECURITY: with the job's identification httpx sends it on every request
// (-H), over a configured header of the same name.
func TestWithIdentity(t *testing.T) {
	s := NewScanner()
	s.Headers = []string{"X-Bug-Bounty: someone", "X-Scan: 1"}
	rs, err := s.WithIdentity(&tool.Identity{UserAgent: "jdoe-research", Headers: map[string]string{"X-Bug-Bounty": "jdoe"}})
	if err != nil {
		t.Fatal(err)
	}
	got := rs.(*Scanner).buildArgs("example.com", nil)
	for _, h := range []string{"X-Scan: 1", "User-Agent: jdoe-research", "X-Bug-Bounty: jdoe"} {
		i := slices.Index(got, h)
		if i < 1 || got[i-1] != "-H" {
			t.Fatalf("args lack -H %q: %q", h, got)
		}
	}
	if slices.Contains(got, "X-Bug-Bounty: someone") {
		t.Fatal("the configured header won over the identification")
	}
	if len(s.Headers) != 2 {
		t.Fatal("the original scanner was changed")
	}
	flagcheck.Check(t, helpFile, got)
}
