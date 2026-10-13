package reachprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// The sensor's probe passes the SDK's reach conformance suite: it dials
// only what the guard admitted, keeps the rate and size bounds, classifies
// outcomes, reports an unroutable target as not reached, and stops when
// canceled.
func TestConformance_ReachSuite(t *testing.T) {
	conformance.RunReachSuite(t, func(ctx context.Context, g reach.Guard, d reach.DialFunc, targets []string) (reach.ProbeResult, error) {
		return Probe(ctx, g, d, targets, reach.MaxProbeRate)
	})
}

// fakeGuard admits the addresses in allow (literals only) and refuses the
// rest, as the local policy would.
type fakeGuard struct{ allow map[netip.Addr]bool }

func (g fakeGuard) AdmittedAddrs(_ context.Context, host string) ([]netip.Addr, error) {
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || !g.allow[a] {
		return nil, errors.New("refused by targets.allow")
	}
	return []netip.Addr{a}, nil
}

func (g fakeGuard) CheckDial(ctx context.Context, _, address string) ([]net.IP, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := g.AdmittedAddrs(ctx, host)
	if err != nil {
		return nil, err
	}
	return []net.IP{addrs[0].AsSlice()}, nil
}

// recordingDial answers per address: refused, no route, or an error.
type recordingDial struct {
	mu     sync.Mutex
	dialed []string
}

func (d *recordingDial) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	host, _, _ := net.SplitHostPort(address)
	errno := syscall.ECONNREFUSED
	if host == "198.51.100.9" {
		errno = syscall.ENETUNREACH
	}
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

func (d *recordingDial) hosts() map[string]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]bool{}
	for _, a := range d.dialed {
		h, _, _ := net.SplitHostPort(a)
		out[h] = true
	}
	return out
}

// A probe job's outcomes land in the job's recorder; a target the guard
// does not admit is never dialed.
func TestScanTargets_RecordsIntoTheJob(t *testing.T) {
	g := fakeGuard{allow: map[netip.Addr]bool{
		netip.MustParseAddr("198.51.100.7"): true,
		netip.MustParseAddr("198.51.100.9"): true,
	}}
	d := &recordingDial{}
	s := New(func() reach.Guard { return g }).WithDial(d.dial)
	rec := reach.NewRecorder()
	ctx := reach.WithRecorder(context.Background(), rec)
	res, err := s.ScanTargets(ctx, []string{"198.51.100.7", "198.51.100.9", "203.0.113.1"}, &core.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ScannerName != Name || len(res.RawOutput) != 0 {
		t.Fatalf("result %+v: a probe reports no findings", res)
	}
	if d.hosts()["203.0.113.1"] {
		t.Fatal("SECURITY: dialed a target the guard did not admit")
	}
	rep := rec.Report()
	if rep.Classes[reach.PortClosed] != 1 || rep.Classes[reach.NoRoute] != 1 {
		t.Fatalf("job summary = %+v", rep.Summary)
	}
}

// Fail closed: no guard, or a job the probe cannot keep to, never dials.
func TestScanTargets_Refusals(t *testing.T) {
	d := &recordingDial{}
	g := fakeGuard{allow: map[netip.Addr]bool{netip.MustParseAddr("198.51.100.7"): true}}
	if _, err := New(func() reach.Guard { return nil }).WithDial(d.dial).Scan(context.Background(), "198.51.100.7", nil); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("no guard: err = %v", err)
	}
	if _, err := New(nil).WithDial(d.dial).Scan(context.Background(), "198.51.100.7", nil); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("no guard func: err = %v", err)
	}
	ws := &webscope.Scope{}
	for name, opts := range map[string]*core.ScanOptions{
		"tier T0":            {MaxTier: "T0"},
		"another capability": {Capability: "port.scan@1"},
		"web scope":          {WebScope: ws},
		"scope limits":       {Limits: []scopelimit.Limit{{Host: "198.51.100.7", Ports: "443"}}},
	} {
		if _, err := New(func() reach.Guard { return g }).WithDial(d.dial).Scan(context.Background(), "198.51.100.7", opts); err == nil {
			t.Errorf("%s: probe ran", name)
		}
	}
	if len(d.dialed) != 0 {
		t.Fatalf("SECURITY: a refused probe dialed %v", d.dialed)
	}
	for name, opts := range map[string]*core.ScanOptions{
		"its capability": {Capability: Capability, MaxTier: "T1"},
		"no job fields":  nil,
	} {
		if _, err := New(func() reach.Guard { return g }).WithDial(d.dial).Scan(context.Background(), "198.51.100.7", opts); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRateOf(t *testing.T) {
	if r := rateOf(nil); r != reach.MaxProbeRate {
		t.Fatalf("default rate %v", r)
	}
	if r := rateOf(&core.ScanOptions{RateLimit: 3}); r != 3 {
		t.Fatalf("a lower job rate is kept: %v", r)
	}
	if r := rateOf(&core.ScanOptions{RateLimit: 500}); r != reach.MaxProbeRate {
		t.Fatalf("a higher job rate raised the bound: %v", r)
	}
}
