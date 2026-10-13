package naabu

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// A discover.hosts@1 job probes a few common ports with a connect scan; a
// port scan job is unchanged.
func TestWithCapability_HostDiscovery(t *testing.T) {
	rs, err := NewScanner().WithCapability("discover.hosts@1")
	if err != nil {
		t.Fatal(err)
	}
	s := rs.(*Scanner)
	if !s.HostDiscoveryMode() || s.Ports != DiscoveryPorts || s.TopPorts != 0 || s.ServiceVersion {
		t.Fatalf("host discovery scanner = %+v", s)
	}
	got := s.buildArgs("198.51.100.0/24", nil)
	if i := slices.Index(got, "-p"); i < 0 || got[i+1] != DiscoveryPorts || !slices.Contains(got, "-host") || slices.Contains(got, "-top-ports") {
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

// Ports the job or the scan's settings named are kept.
func TestWithCapability_KeepsJobPorts(t *testing.T) {
	rs, err := NewScanner().WithSettings(scanSettings(t, map[string]any{"ports": "22,443"}))
	if err != nil {
		t.Fatal(err)
	}
	rs, _ = rs.(*Scanner).WithCapability("discover.hosts@1")
	if s := rs.(*Scanner); s.Ports != "22,443" || !s.HostDiscoveryMode() {
		t.Fatalf("scanner = %+v", s)
	}
}

// The mode reaches the tool child.
func TestHostDiscovery_TravelsToTheChild(t *testing.T) {
	rs, _ := NewScanner().WithCapability("discover.hosts@1")
	raw, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	var back Scanner
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.HostDiscoveryMode() || back.Ports != DiscoveryPorts {
		t.Fatalf("decoded = %+v", back)
	}
}

// A host discovery report keeps each answering address with the probe
// that answered, and nothing else.
func TestMarkLive(t *testing.T) {
	r := &ctis.Report{Assets: []ctis.Asset{
		{Type: ctis.AssetTypeIPAddress, Value: "198.51.100.7", Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Ports: []ctis.PortInfo{{Port: 443}, {Port: 22}}}}},
		{Type: ctis.AssetTypeHost, Value: "app.example.com", Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Ports: []ctis.PortInfo{{Port: 80}}}}},
		{Type: ctis.AssetTypeIPAddress, Value: "198.51.100.8"},
	}}
	MarkLive(r)
	if len(r.Assets) != 1 || r.Assets[0].Value != "198.51.100.7" || r.Assets[0].Properties["live_by"] != "tcp:443" {
		t.Fatalf("assets = %+v", r.Assets)
	}
	MarkLive(nil)
}
