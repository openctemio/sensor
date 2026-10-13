package naabu

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func withPorts(t *testing.T, ports string) *Scanner {
	t.Helper()
	rs, err := NewScanner().WithSettings(scanSettings(t, map[string]any{"ports": ports}))
	if err != nil {
		t.Fatal(err)
	}
	return rs.(*Scanner)
}

// A discover.hosts@1 job probes the ports the platform named with a
// connect scan; a port scan job is unchanged.
func TestWithCapability_HostDiscovery(t *testing.T) {
	rs, err := withPorts(t, "80,443,22").WithCapability("discover.hosts@1")
	if err != nil {
		t.Fatal(err)
	}
	s := rs.(*Scanner)
	if !s.HostDiscoveryMode() || s.Ports != "80,443,22" || s.ServiceVersion {
		t.Fatalf("host discovery scanner = %+v", s)
	}
	got := s.buildArgs("198.51.100.0/24", nil)
	if i := slices.Index(got, "-p"); i < 0 || got[i+1] != "80,443,22" || slices.Contains(got, "-top-ports") {
		t.Fatalf("args = %q", got)
	}
	if got[slices.Index(got, "-s")+1] != string(ScanTypeConnect) {
		t.Fatalf("host discovery must stay a connect scan (no raw sockets): %q", got)
	}
	flagcheck.Check(t, helpFile, got)

	same, _ := NewScanner().WithCapability("scan.ports@1")
	if same.(*Scanner).HostDiscoveryMode() || same.(*Scanner).Ports != "top-100" {
		t.Fatalf("a port scan job changed: %+v", same)
	}
}

// The platform decides the probe: a host discovery job without ports is
// refused, never probed with a set the sensor picks.
func TestWithCapability_HostDiscoveryNeedsPorts(t *testing.T) {
	if _, err := NewScanner().WithCapability("discover.hosts@1"); !errors.Is(err, core.ErrNoProbePorts) {
		t.Fatalf("err = %v, want ErrNoProbePorts", err)
	}
}

// The mode reaches the tool child.
func TestHostDiscovery_TravelsToTheChild(t *testing.T) {
	rs, _ := withPorts(t, "443").WithCapability("discover.hosts@1")
	raw, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	var back Scanner
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.HostDiscoveryMode() || back.Ports != "443" {
		t.Fatalf("decoded = %+v", back)
	}
}
