package toolrun

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
)

// SetShared puts every later tool task under the shared profile, and keeps
// the policy set before it.
func TestSetShared(t *testing.T) {
	SetAdmission(nil, "")
	SetShared(true)
	t.Cleanup(func() { SetShared(false) })
	h, _ := current(toolhost.RunOptions{})
	if !h.Shared {
		t.Fatal("the tool host is not shared")
	}
}
