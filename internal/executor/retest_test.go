package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// A retest target the validate guard refuses (loopback, cloud metadata)
// fails the command before any tool runs, whatever the local policy says.
func TestRetestNucleiGuardsTargets(t *testing.T) {
	e := NewValidatingCommandExecutor(nil, false)
	for _, target := range []string{"http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data"} {
		task := tool.Task{ID: "r", Targets: []tool.Target{{Ref: "t1", Value: target}},
			Retest: []tool.RetestItem{{Ref: "f", Target: "t1", Kind: tool.RetestFinding, RuleID: "x"}}}
		if _, err := e.RetestNuclei(context.Background(), task); err == nil || !strings.Contains(err.Error(), "validate guard") {
			t.Errorf("%s: %v", target, err)
		}
	}
}
