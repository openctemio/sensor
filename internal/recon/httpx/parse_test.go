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
