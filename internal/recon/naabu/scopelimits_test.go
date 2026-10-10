package naabu

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/scopelimit"
)

// A port-limited job scans only the limited ports, not its top-N list
// (the forwarder refuses the others in any case).
func TestWithScopeLimitsScansTheLimitedPorts(t *testing.T) {
	ns, err := NewTop1000Scanner().WithScopeLimits(scopelimit.NewSet([]scopelimit.Limit{
		{Host: "api.example.com", Ports: "443,8000-8100"}, {Host: "10.0.0.5", Ports: "22", Protocol: "tcp"}}))
	if err != nil {
		t.Fatal(err)
	}
	args := ns.(*Scanner).buildArgs("api.example.com", nil)
	i := slices.Index(args, "-p")
	if i < 0 || args[i+1] != "22,443,8000-8100" || slices.Contains(args, "-top-ports") {
		t.Fatalf("args %v", args)
	}
	same, _ := NewTop100Scanner().WithScopeLimits(scopelimit.NewSet([]scopelimit.Limit{{Host: "a.example.com", PathPrefix: "/api"}}))
	if same.(*Scanner).Ports != "top-100" {
		t.Fatal("a path-only limit changed the port list")
	}
}
