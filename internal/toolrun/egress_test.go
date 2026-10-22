package toolrun

import (
	"context"
	"net"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

type nopDialer struct{}

func (nopDialer) Dial(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }

// SECURITY: a tool run in the sensor's process would reach its targets
// directly, so a pooled job is refused there; out of process it runs.
func TestApplyJobRefusesAPooledJobInProcess(t *testing.T) {
	m := tool.Manifest{Name: "t"}
	opts := &core.ScanOptions{Egress: nopDialer{}}
	if _, _, err := ApplyJob(context.Background(), m, nil, opts); err != nil {
		t.Fatalf("out of process: %v", err)
	}
	t.Setenv(EnvRuntime, "in-process")
	_, _, err := ApplyJob(context.Background(), m, nil, opts)
	if r := core.RefusalOf(err); r == nil || r.Rule != core.RefusalEgressUnavailable {
		t.Fatalf("in process: %v", err)
	}
	if _, _, err := ApplyJob(context.Background(), m, nil, &core.ScanOptions{}); err != nil {
		t.Fatalf("no pool: %v", err)
	}
}
