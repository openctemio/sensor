package asn

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/lookup"
)

// world is a fake internet: a handler per host, and a record of the hosts
// and paths asked.
type world struct {
	mu       sync.Mutex
	handlers map[string]func(path string) (int, string, http.Header)
	asked    []string
}

func (w *world) RoundTrip(req *http.Request) (*http.Response, error) {
	w.mu.Lock()
	w.asked = append(w.asked, req.URL.Host+req.URL.Path)
	h := w.handlers[req.URL.Host]
	w.mu.Unlock()
	if h == nil {
		return nil, fmt.Errorf("no route to %s", req.URL.Host)
	}
	code, body, hdr := h(req.URL.Path)
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{StatusCode: code, Status: http.StatusText(code), Header: hdr, Request: req,
		Body: io.NopCloser(strings.NewReader(body))}, nil
}

func (w *world) askedHost(host string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, a := range w.asked {
		if strings.HasPrefix(a, host+"/") {
			n++
		}
	}
	return n
}

const (
	bootV4 = `{"services":[[["192.0.2.0/24","198.51.100.0/24"],["http://insecure.example/","https://rdap.example/"]]]}`
	bootV6 = `{"services":[[["2001:db8::/32"],["https://rdap.example/"]]]}`

	rdapAnswer = `{"name":"EXAMPLE-NET","country":"nl","startAddress":"192.0.2.0","endAddress":"192.0.2.255",
	 "arin_originas0_originautnums":[64496],
	 "entities":[{"roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","Tech Person"]]]},
	  {"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Networks BV"]]]}]}`
)

func fixture(t *testing.T) *world {
	t.Helper()
	w := &world{handlers: map[string]func(string) (int, string, http.Header){
		"iptoasn.test": func(string) (int, string, http.Header) { return 502, "Bad Gateway", nil },
		"iana.example": func(p string) (int, string, http.Header) {
			switch p {
			case "/rdap/ipv4.json":
				return 200, bootV4, nil
			case "/rdap/ipv6.json":
				return 200, bootV6, nil
			}
			return 404, "", nil
		},
		"rdap.example": func(p string) (int, string, http.Header) {
			if p == "/ip/192.0.2.10" || p == "/ip/192.0.2.11" {
				return 200, rdapAnswer, nil
			}
			if p == "/ip/198.51.100.9" {
				return 404, "", nil
			}
			return 503, "", nil
		},
	}}
	oldClient, oldDataset, oldMin := lookup.HTTPClient, dataset, minRows
	oldS, oldJ := lookup.Sleep, lookup.Jitter
	lookup.HTTPClient = func(time.Duration) *http.Client { return &http.Client{Transport: w} }
	dataset.URL = "https://iptoasn.test/data/ip2asn-combined.tsv.gz"
	minRows = 1
	lookup.Sleep = func(context.Context, time.Duration) error { return nil }
	lookup.Jitter = func(max time.Duration) time.Duration { return max }
	t.Cleanup(func() {
		lookup.HTTPClient, dataset, minRows, lookup.Sleep, lookup.Jitter = oldClient, oldDataset, oldMin, oldS, oldJ
	})
	return w
}

func rdapLocal(t *testing.T, cache string, off bool, values ...string) tool.Task {
	t.Helper()
	tt := asnTask(t, cache, nil, values...)
	tt.Local = []byte(fmt.Sprintf(`{"cache_dir":%q,"rdap_bootstrap_url":"https://iana.example/rdap/","asn_rdap_fallback_off":%v}`, cache, off))
	return tt
}

func warned(res *testkit.Result, msg string) (testkit.LogEntry, bool) {
	for _, l := range res.Logs {
		if l.Msg == msg {
			return l, true
		}
	}
	return testkit.LogEntry{}, false
}

// An old cached copy plus a failing source: the task succeeds, warns with
// the copy's age and source, and the copy is kept byte for byte.
func TestOldCopyWithFailingSourceStillAnswers(t *testing.T) {
	w := fixture(t)
	cache := t.TempDir()
	p := cache + "/" + dataset.Name
	gz := sampleGz(t)
	if err := os.WriteFile(p, gz, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-90 * 24 * time.Hour)
	_ = os.Chtimes(p, old, old)
	res := testkit.Run(t, Tool, asnTask(t, cache, nil, "192.0.2.10"))
	res.RequireStatus(t, tool.StatusOK)
	if len(res.Report.Assets) != 2 {
		t.Fatalf("assets %+v", res.Report.Assets)
	}
	l, ok := warned(res, "asn: the routing dataset could not be refreshed; using the cached copy")
	if !ok || fmt.Sprint(l.Attrs["age"]) != "2160h0m0s" || !strings.Contains(fmt.Sprint(l.Attrs["source"]), "iptoasn.test") {
		t.Fatalf("warning %+v %v", l, ok)
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, gz) {
		t.Fatal("the old copy was replaced")
	}
	if w.askedHost("rdap.example") != 0 {
		t.Fatal("RDAP asked although a copy exists")
	}
}

// A corrupt or too small download is not swapped in.
func TestBadDownloadsAreNotSwappedIn(t *testing.T) {
	var full bytes.Buffer
	zw := gzip.NewWriter(&full)
	for i := 1; i <= 20; i++ {
		_, _ = fmt.Fprintf(zw, "10.0.%d.0\t10.0.%d.255\t%d\tNL\tHolder %d\n", i, i, 64500+i, i)
	}
	_ = zw.Close()
	good := full.Bytes()
	var small bytes.Buffer
	sw := gzip.NewWriter(&small)
	_, _ = sw.Write([]byte("192.0.2.0\t192.0.2.255\t64496\tUS\tOne\n"))
	_ = sw.Close()
	oldMin := minRows
	minRows = 10
	t.Cleanup(func() { minRows = oldMin })
	for name, body := range map[string][]byte{
		"not gzip":  []byte("<html>error</html>"),
		"truncated": good[:len(good)-12],
		"too small": small.Bytes(),
		"empty tsv": func() []byte {
			var b bytes.Buffer
			z := gzip.NewWriter(&b)
			_ = z.Close()
			return b.Bytes()
		}(),
	} {
		p := t.TempDir() + "/x.gz"
		_ = os.WriteFile(p, body, 0o600)
		if err := validateDataset(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := t.TempDir() + "/ok.gz"
	_ = os.WriteFile(p, good, 0o600)
	if err := validateDataset(p); err != nil {
		t.Errorf("a good download refused: %v", err)
	}
}

func TestInvalidDownloadKeepsTheCopyThroughTheTool(t *testing.T) {
	w := fixture(t)
	w.handlers["iptoasn.test"] = func(string) (int, string, http.Header) { return 200, "not a dataset", nil }
	cache := t.TempDir()
	p := cache + "/" + dataset.Name
	gz := sampleGz(t)
	_ = os.WriteFile(p, gz, 0o600)
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(p, old, old)
	res := testkit.Run(t, Tool, asnTask(t, cache, nil, "192.0.2.10"))
	res.RequireStatus(t, tool.StatusOK)
	if b, _ := os.ReadFile(p); !bytes.Equal(b, gz) {
		t.Fatal("a bad download replaced the copy")
	}
}

// No copy and a failing source: the registries answer, the reports have the
// dataset's shape.
func TestNoCopyFallsBackToRDAP(t *testing.T) {
	w := fixture(t)
	cache := t.TempDir()
	res := testkit.Run(t, Tool, rdapLocal(t, cache, false, "192.0.2.10", "198.51.100.9"))
	res.RequireStatus(t, tool.StatusOK)
	byValue := map[string]ctis.Asset{}
	for _, a := range res.Report.Assets {
		byValue[a.Value] = a
	}
	ip := byValue["192.0.2.10"]
	if ip.Type != ctis.AssetTypeIPAddress || ip.Technical.IPAddress.ASN != 64496 ||
		ip.Technical.IPAddress.ASNOrg != "Example Networks BV" || ip.Technical.IPAddress.Country != "NL" {
		t.Fatalf("ip %+v", ip)
	}
	if r := byValue["192.0.2.0/24"]; r.Type != ctis.AssetTypeIPRange || r.Technical.IPAddress.ASN != 64496 {
		t.Fatalf("range %+v", r)
	}
	if len(byValue) != 2 { // 198.51.100.9: unknown to the registry, still done
		t.Fatalf("assets %+v", byValue)
	}
	for _, tg := range res.Targets {
		if tg.State != tool.StateDone {
			t.Fatalf("target %+v", tg)
		}
	}
	// The dataset was tried four times (bounded back-off), the insecure
	// registry URL of the bootstrap was never used.
	if n := w.askedHost("iptoasn.test"); n != 4 {
		t.Fatalf("dataset attempts %d", n)
	}
	if w.askedHost("insecure.example") != 0 {
		t.Fatal("a plain-http registry URL was used")
	}
}

// With the registries failing too, the error is transient and names the
// sources and their statuses; addresses RDAP answered are still done.
func TestSourceUnavailableWhenBothFail(t *testing.T) {
	fixture(t)
	res := testkit.Run(t, Tool, rdapLocal(t, t.TempDir(), false, "192.0.2.77"))
	if res.Err == nil || tool.ClassOf(res.Err) != tool.Transient || !res.Err.Retryable {
		t.Fatalf("status %s err %v", res.Status, res.Err)
	}
	for _, want := range []string{"source_unavailable: routing dataset iptoasn.test HTTP 502", "rdap: rdap.example HTTP 503"} {
		if !strings.HasPrefix(res.Err.Detail, "source_unavailable:") || !strings.Contains(res.Err.Detail, want) {
			t.Fatalf("detail %q lacks %q", res.Err.Detail, want)
		}
	}
	// One answered, one not: partial, the answered address is reported.
	res = testkit.Run(t, Tool, rdapLocal(t, t.TempDir(), false, "192.0.2.10", "192.0.2.77"))
	if res.Status != tool.StatusPartial {
		t.Fatalf("status %s err %v", res.Status, res.Err)
	}
	var done, failed int
	for _, tg := range res.Targets {
		switch tg.State {
		case tool.StateDone:
			done++
		default:
			failed++
			if !strings.Contains(tg.Detail, "source_unavailable:") {
				t.Fatalf("target error %+v", tg)
			}
		}
	}
	if done != 1 || failed != 1 || len(res.Report.Assets) == 0 {
		t.Fatalf("done %d failed %d: %+v", done, failed, res.Targets)
	}
}

func TestRDAPFallbackCanBeTurnedOff(t *testing.T) {
	w := fixture(t)
	res := testkit.Run(t, Tool, rdapLocal(t, t.TempDir(), true, "192.0.2.10"))
	if res.Err == nil || tool.ClassOf(res.Err) != tool.Transient || !strings.HasPrefix(res.Err.Detail, "source_unavailable:") {
		t.Fatalf("%s %v", res.Status, res.Err)
	}
	if w.askedHost("rdap.example") != 0 || w.askedHost("iana.example") != 0 {
		t.Fatal("the registries were asked with the fallback off")
	}
}

// SECURITY: a bootstrap that points at a task target does not make the
// sensor contact it.
func TestRDAPNeverContactsATarget(t *testing.T) {
	w := fixture(t)
	w.handlers["iana.example"] = func(p string) (int, string, http.Header) {
		if p == "/rdap/ipv4.json" {
			return 200, `{"services":[[["192.0.2.0/24"],["https://192.0.2.10/"]]]}`, nil
		}
		return 200, bootV6, nil
	}
	w.handlers["192.0.2.10"] = func(string) (int, string, http.Header) { return 200, rdapAnswer, nil }
	res := testkit.Run(t, Tool, rdapLocal(t, t.TempDir(), false, "192.0.2.10"))
	if tool.ClassOf(res.Err) != tool.Transient {
		t.Fatalf("%s %v", res.Status, res.Err)
	}
	if n := w.askedHost("192.0.2.10"); n != 0 {
		t.Fatalf("the target host was contacted %d times", n)
	}
}

// SECURITY: a mirror that is not https is refused, from the sensor's
// settings and again in the child.
func TestMirrorMustBeHTTPS(t *testing.T) {
	fixture(t)
	tt := asnTask(t, t.TempDir(), nil, "192.0.2.10")
	tt.Local = []byte(`{"asn_dataset_url":"http://mirror.example/ip2asn.tsv.gz"}`)
	res := testkit.Run(t, Tool, tt)
	if tool.ClassOf(res.Err) != tool.InvalidInput {
		t.Fatalf("%s %v", res.Status, res.Err)
	}
}

func TestRDAPAnswerParsing(t *testing.T) {
	cases := []struct {
		name, body, addr string
		org              string
		asn              int
		ok               bool
	}{
		{"cidr only, name fallback", `{"name":"NET-X","cidr0_cidrs":[{"v4prefix":"192.0.2.0","length":24}]}`, "192.0.2.5", "NET-X", 0, true},
		{"v6", `{"name":"V6","startAddress":"2001:db8::","endAddress":"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff","country":"ZZ"}`, "2001:db8::1", "V6", 0, true},
		{"range excludes the address", `{"name":"X","startAddress":"192.0.2.0","endAddress":"192.0.2.3"}`, "192.0.2.9", "", 0, false},
		{"no range", `{"name":"X"}`, "192.0.2.9", "", 0, false},
		{"not json", `<html>`, "192.0.2.9", "", 0, false},
	}
	for _, c := range cases {
		e, err := entryFromRDAP(mustAddr(c.addr), []byte(c.body))
		if (err == nil) != c.ok || (c.ok && (e.Org != c.org || e.ASN != c.asn || e.Country != "")) {
			t.Errorf("%s: %+v %v", c.name, e, err)
		}
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
