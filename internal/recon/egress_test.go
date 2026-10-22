package recon

import (
	"context"
	"net"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/toolrun"
)

type nopDialer struct{}

func (nopDialer) Dial(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }

// SECURITY: a pooled job never takes a recon tool's direct path: a
// raw-socket scan (naabu SYN) and the in-process runtime refuse it with
// egress_unavailable before anything runs.
func TestReconPooledJobNeverGoesDirect(t *testing.T) {
	opts := &core.ScanOptions{Egress: nopDialer{}}
	syn := naabu.NewScanner()
	syn.ScanType = naabu.ScanTypeSYN
	s := NewScanner(syn)
	_, ran, err := s.outOfProcess(context.Background(), []string{"a.example"}, opts)
	if r := core.RefusalOf(err); !ran || r == nil || r.Rule != core.RefusalEgressUnavailable {
		t.Fatalf("raw-socket scan with a pool: ran=%v err=%v", ran, err)
	}
	if !s.RoutesEgress() {
		t.Fatal("a ported tool out of process does not route egress")
	}

	t.Setenv(toolrun.EnvRuntime, "in-process")
	connect := NewScanner(naabu.NewScanner())
	if connect.RoutesEgress() {
		t.Fatal("the in-process runtime claims to route egress")
	}
	_, ran, err = connect.outOfProcess(context.Background(), []string{"a.example"}, opts)
	if r := core.RefusalOf(err); !ran || r == nil || r.Rule != core.RefusalEgressUnavailable {
		t.Fatalf("in-process with a pool: ran=%v err=%v", ran, err)
	}
	// Without a pool the direct path stays as it was.
	if _, ran, err = connect.outOfProcess(context.Background(), []string{"a.example"}, &core.ScanOptions{}); ran || err != nil {
		t.Fatalf("no pool: ran=%v err=%v", ran, err)
	}
}
