package httpx

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// Real httpx 1.12.0 output (https://example.com). "a" and "cname" are
// arrays; decoding them into strings dropped every line.
func TestParseOutput_Real(t *testing.T) {
	data, err := os.ReadFile(flagcheck.Testdata("httpx-1.12.0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	hosts, techs, err := NewScanner().parseOutput(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("live hosts = %d, want 1", len(hosts))
	}
	h := hosts[0]
	if h.URL != "https://example.com" || h.Host != "example.com" || h.StatusCode != 200 || h.Port != 443 ||
		h.Title != "Example Domain" || h.IP != "172.66.147.243" || h.TLSVersion != "tls13" || h.CDN != "cloudflare" {
		t.Fatalf("live host = %+v", h)
	}
	if len(techs) == 0 {
		t.Fatal("no technologies")
	}
}

// The deprecated IP and CNAME strings stay filled for callers built against
// them.
func TestHTTPXOutput_DeprecatedFields(t *testing.T) {
	var o HTTPXOutput
	if err := json.Unmarshal([]byte(`{"url":"https://example.com","host_ip":"192.0.2.1","a":["192.0.2.1"],"cname":["x.example.net","y.example.net"]}`), &o); err != nil {
		t.Fatal(err)
	}
	if len(o.CNAMEs) != 2 || o.HostIP != "192.0.2.1" {
		t.Fatalf("decoded = %+v", o)
	}
	hosts, _, err := NewScanner().parseOutput([]byte(`{"url":"https://example.com","host":"example.com","a":["192.0.2.7"],"cname":["x.example.net"]}` + "\n"))
	if err != nil || len(hosts) != 1 || hosts[0].IP != "192.0.2.7" {
		t.Fatalf("hosts = %+v err = %v", hosts, err)
	}
}

// The real -tls-grab output keeps the leaf certificate, JARM and CDN type.
func TestParseOutput_RealServerFields(t *testing.T) {
	data, err := os.ReadFile(flagcheck.Testdata("httpx-1.12.0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	hosts, _, err := NewScanner().parseOutput(data)
	if err != nil || len(hosts) != 1 {
		t.Fatalf("hosts %d err %v", len(hosts), err)
	}
	h := hosts[0]
	if h.TLS == nil {
		t.Fatal("no TLS leaf")
	}
	l := h.TLS
	if l.FingerprintSHA256 != "85ca6ab068e9bcce88b6c4aa3c47f7d17228134a457f870d3800e6223a0df07a" ||
		l.SubjectCN != "example.com" || l.IssuerOrg != "SSL Corporation" || !l.Wildcard ||
		len(l.SANs) != 2 || l.NotAfter.IsZero() || l.NotBefore.IsZero() || l.SerialNumber == "" {
		t.Errorf("leaf = %+v", l)
	}
	if h.JARM != "27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c" || h.CDNType != "waf" {
		t.Errorf("jarm %q cdn_type %q", h.JARM, h.CDNType)
	}
}

// A TLS block without a SHA-256 fingerprint has no identity: no leaf.
func TestParseOutput_LeafNeedsFingerprint(t *testing.T) {
	hosts, _, err := NewScanner().parseOutput([]byte(`{"url":"https://example.com","tls":{"subject_cn":"example.com"},"favicon":"123","asn":{"as_number":"AS1","as_name":"X","as_country":"US"}}` + "\n"))
	if err != nil || len(hosts) != 1 {
		t.Fatalf("hosts %d err %v", len(hosts), err)
	}
	if hosts[0].TLS != nil {
		t.Errorf("leaf without fingerprint: %+v", hosts[0].TLS)
	}
	if hosts[0].FaviconMMH3 != "123" || hosts[0].ASN == nil || hosts[0].ASN.Number != "AS1" {
		t.Errorf("favicon %q asn %+v", hosts[0].FaviconMMH3, hosts[0].ASN)
	}
}
