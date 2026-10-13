package toolrun

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// A command that is not a capability job (a validation) hands its web
// scope to the task through the context; nil changes nothing.
func TestWithWebScope(t *testing.T) {
	ws := &webscope.Scope{DenyPaths: []string{"/admin"}}
	task := withJob(WithWebScope(context.Background(), ws), tool.Task{})
	if task.WebScope != ws {
		t.Fatalf("task web scope %+v", task.WebScope)
	}
	if task := withJob(WithWebScope(context.Background(), nil), tool.Task{}); task.WebScope != nil {
		t.Fatalf("nil scope set %+v", task.WebScope)
	}
}
