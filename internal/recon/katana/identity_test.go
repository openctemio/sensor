package katana

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// SECURITY: with the job's identification katana sends it on every request
// (-H).
func TestWithIdentity(t *testing.T) {
	rs, err := NewScanner().WithIdentity(&tool.Identity{UserAgent: "jdoe-research", Headers: map[string]string{"X-Bug-Bounty": "jdoe"}})
	if err != nil {
		t.Fatal(err)
	}
	got := rs.(*Scanner).buildArgs("https://example.com", nil)
	for _, h := range []string{"User-Agent: jdoe-research", "X-Bug-Bounty: jdoe"} {
		i := slices.Index(got, h)
		if i < 1 || got[i-1] != "-H" {
			t.Fatalf("args lack -H %q: %q", h, got)
		}
	}
	flagcheck.Check(t, helpFile, got)
	if got := NewScanner().buildArgs("https://example.com", nil); slices.Contains(got, "-H") {
		t.Fatalf("no identification, no -H: %q", got)
	}
}
