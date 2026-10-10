package asn

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis/capability"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/lookup"
)

// sampleGz is the recorded dataset sample, gzip'd as the source serves it.
func sampleGz(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/ip2asn-sample.tsv")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}

func writeSample(t *testing.T) string {
	t.Helper()
	p := t.TempDir() + "/ip2asn.tsv.gz"
	if err := os.WriteFile(p, sampleGz(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRangePrefixes(t *testing.T) {
	a := netip.MustParseAddr
	cases := []struct {
		start, end string
		max        int
		want       string
	}{
		{"1.0.1.0", "1.0.3.255", 0, "1.0.1.0/24 1.0.2.0/23"},
		{"192.0.2.0", "192.0.2.255", 0, "192.0.2.0/24"},
		{"192.0.2.7", "192.0.2.7", 0, "192.0.2.7/32"},
		{"0.0.0.0", "255.255.255.255", 0, "0.0.0.0/0"},
		{"10.0.0.1", "10.0.0.6", 0, "10.0.0.1/32 10.0.0.2/31 10.0.0.4/31 10.0.0.6/32"},
		{"10.0.0.1", "10.0.0.6", 2, "10.0.0.1/32 10.0.0.2/31"},
		{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 0, "2001:db8::/32"},
		{"192.0.2.9", "192.0.2.1", 0, ""},
	}
	for _, c := range cases {
		var got []string
		for _, p := range RangePrefixes(a(c.start), a(c.end), c.max) {
			got = append(got, p.String())
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s-%s = %v, want %s", c.start, c.end, got, c.want)
		}
	}
}

func TestLookupAndAnnounced(t *testing.T) {
	path := writeSample(t)
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.200"),
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("203.0.113.0")}
	got, err := Lookup(t.Context(), path, addrs)
	if err != nil {
		t.Fatal(err)
	}
	if e := got[addrs[0]]; e.ASN != 64496 || e.Org != "EXAMPLE-NET-A Example Networks" || e.Country != "" {
		t.Fatalf("192.0.2.10 = %+v", e)
	}
	if _, ok := got[addrs[1]]; ok {
		t.Fatal("a not-routed address matched")
	}
	if e := got[addrs[2]]; e.ASN != 64498 || e.Country != "NL" {
		t.Fatalf("v6 = %+v", e)
	}
	ann, err := Announced(t.Context(), path, []int{64496}, 10)
	if err != nil || len(ann[64496]) != 2 || ann[64496][1].String() != "198.51.100.0/25" {
		t.Fatalf("announced %v %v", ann, err)
	}
}

type recorder struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hosts []string
	hits  int
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, req.URL.Host)
	r.mu.Unlock()
	out := req.Clone(req.Context())
	out.URL.Host = strings.TrimPrefix(r.srv.URL, "https://")
	out.Host = ""
	return r.srv.Client().Transport.RoundTrip(out)
}

func datasetServer(t *testing.T) *recorder {
	t.Helper()
	rec := &recorder{}
	gz := sampleGz(t)
	rec.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.hits++
		rec.mu.Unlock()
		if r.URL.Path != "/data/ip2asn-combined.tsv.gz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(gz)
	}))
	t.Cleanup(rec.srv.Close)
	oldClient, oldDataset := lookup.HTTPClient, dataset
	lookup.HTTPClient = func(time.Duration) *http.Client { return &http.Client{Transport: rec} }
	dataset.URL = "https://iptoasn.test/data/ip2asn-combined.tsv.gz"
	t.Cleanup(func() { lookup.HTTPClient, dataset = oldClient, oldDataset })
	return rec
}

func asnTask(t *testing.T, cache string, cfg *Config, values ...string) tool.Task {
	t.Helper()
	l := lookup.Local{CacheDir: cache}
	if cfg != nil {
		l.Config, _ = json.Marshal(cfg)
	}
	raw, _ := json.Marshal(l)
	tt := tool.Task{Capability: "lookup.asn@1", Local: raw}
	for i, v := range values {
		typ := "ip_address"
		if strings.Contains(v, "/") {
			typ = "network"
		}
		tt.Targets = append(tt.Targets, tool.Target{Ref: string(rune('a' + i)), Type: typ, Value: v})
	}
	return tt
}

func TestRunWithRecordedDataset(t *testing.T) {
	rec := datasetServer(t)
	cache := t.TempDir()
	res := testkit.Run(t, Tool, asnTask(t, cache, nil, "192.0.2.10", "198.51.100.200", "203.0.113.0/25", "2001:db8::1"))
	res.RequireStatus(t, tool.StatusOK)
	byValue := map[string]ctis.Asset{}
	for _, a := range res.Report.Assets {
		byValue[a.Value] = a
	}
	if len(byValue) != 3 {
		t.Fatalf("assets %+v", res.Report.Assets)
	}
	ip := byValue["192.0.2.10"]
	if ip.Type != ctis.AssetTypeIPAddress || ip.Technical.IPAddress.ASN != 64496 || ip.Technical.IPAddress.Version != 4 {
		t.Fatalf("ip %+v", ip)
	}
	if ps, _ := ip.Properties["asn_prefixes"].([]any); len(ps) != 1 || ps[0] != "192.0.2.0/24" {
		t.Fatalf("ip prefixes %v", ip.Properties)
	}
	nw := byValue["203.0.113.0/25"]
	if nw.Type != ctis.AssetTypeNetwork || nw.Properties["asn"] != float64(64497) || nw.Properties["country"] != "US" {
		t.Fatalf("network %+v", nw)
	}
	// Off by default: no other announced range.
	if _, ok := byValue["198.51.100.0/25"]; ok {
		t.Fatal("announced ranges reported without include_announced")
	}
	c, _ := capability.Lookup("lookup.asn@1")
	if v, err := c.Check(res.Report, capability.CheckOptions{}); err != nil || len(v) != 0 {
		t.Fatalf("contract: %v %v", v, err)
	}
	// The dataset is downloaded once and reused by the next task.
	res = testkit.Run(t, Tool, asnTask(t, cache, &Config{IncludeAnnounced: true, MaxRanges: 1}, "192.0.2.10"))
	res.RequireStatus(t, tool.StatusOK)
	var nets []string
	for _, a := range res.Report.Assets {
		if a.Type == ctis.AssetTypeNetwork {
			nets = append(nets, a.Value)
		}
	}
	if strings.Join(nets, ",") != "192.0.2.0/24" {
		t.Fatalf("announced (max 1) = %v", nets)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.hits != 1 {
		t.Fatalf("dataset fetched %d times", rec.hits)
	}
	for _, h := range rec.hosts {
		if h != "iptoasn.test" {
			t.Errorf("request to %s", h)
		}
	}
}

// SECURITY: no per-target request leaves the sensor (the lookup is local
// to the cached dataset), and private addresses are not looked up.
func TestRunSendsNothingPerTarget(t *testing.T) {
	rec := datasetServer(t)
	cache := t.TempDir()
	res := testkit.Run(t, Tool, asnTask(t, cache, nil, "10.0.0.1", "127.0.0.1"))
	if res.Report != nil && len(res.Report.Assets) > 0 {
		t.Fatalf("private addresses reported: %+v", res.Report.Assets)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.hits != 0 {
		t.Fatalf("%d requests for private targets", rec.hits)
	}
}

func TestStaleDatasetIsUsedWhenTheSourceIsDown(t *testing.T) {
	rec := datasetServer(t)
	cache := t.TempDir()
	if err := os.WriteFile(cache+"/"+dataset.Name, sampleGz(t), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(cache+"/"+dataset.Name, old, old)
	rec.srv.Close()
	res := testkit.Run(t, Tool, asnTask(t, cache, nil, "192.0.2.10"))
	res.RequireStatus(t, tool.StatusOK)
	if len(res.Report.Assets) != 1 {
		t.Fatalf("assets %+v", res.Report.Assets)
	}
}

func TestConfigFromSettings(t *testing.T) {
	sc := NewScanner()
	if sc.Name() != "asn" || !sc.TakesCapabilityJobs() {
		t.Fatal("scanner identity")
	}
}
