package toolrun

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: the job's identification wins over a configured header of the
// same name, and a line that would read as a flag or break the argv is not
// a valid header line.
func TestIdentityHeaders(t *testing.T) {
	task := tool.Task{Identity: &tool.Identity{UserAgent: "jdoe-research", Headers: map[string]string{"X-Bug-Bounty": "jdoe"}}}
	got := IdentityHeaders(task, []string{"x-bug-bounty: someone", "User-Agent: corp", "X-Scan: 1"})
	want := []string{"X-Scan: 1", "User-Agent: jdoe-research", "X-Bug-Bounty: jdoe"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	if got := IdentityHeaders(tool.Task{}, []string{"X-Scan: 1"}); !slices.Equal(got, []string{"X-Scan: 1"}) {
		t.Fatalf("no identification: %q", got)
	}
	for _, bad := range []string{"-H", "noColon", ": empty", "X: a\nY: b"} {
		if ValidHeaderLine(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidHeaderLine("X-Bug-Bounty: jdoe") {
		t.Error("a plain header refused")
	}
}
