package rdap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
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

func fixture(t *testing.T, name, base string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.ReplaceAll(string(b), "{{BASE}}", base))
}

func TestParseBootstrap(t *testing.T) {
	bs, err := ParseBootstrap(fixture(t, "dns.json", "https://rdap.test"))
	if err != nil {
		t.Fatal(err)
	}
	if s, err := bs.ServerFor("example.com"); err != nil || s != "https://rdap.test/com/v1/" {
		t.Fatalf("com = %q %v", s, err)
	}
	if s, _ := bs.ServerFor("a.b.example.net"); s != "https://rdap.test/com/v1/" {
		t.Fatalf("net = %q", s)
	}
	// SECURITY: a plain-HTTP service is never used.
	if _, err := bs.ServerFor("example.kg"); err != ErrNoService {
		t.Fatalf("http-only kg: %v", err)
	}
	if _, err := bs.ServerFor("example.org"); err != ErrNoService {
		t.Fatalf("unknown tld: %v", err)
	}
	if _, err := ParseBootstrap([]byte(`{"services":[]}`)); err == nil {
		t.Fatal("empty bootstrap accepted")
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{"Example.COM.": "example.com", "bücher.example": "xn--bcher-kva.example"} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q = %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "localhost", "192.0.2.1:80", "https://example.com/", "a b.com"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseRegistryAndRegistrar(t *testing.T) {
	base := "https://rdap.test"
	r, err := Parse("example.com", base+"/com/v1/", fixture(t, "registry-example.com.json", base))
	if err != nil {
		t.Fatal(err)
	}
	if r.Registrar != "RESERVED-Internet Assigned Numbers Authority" || r.RegistrarIANAID != "376" || r.Handle != "2336799_DOMAIN_COM-VRSN" {
		t.Fatalf("registrar %+v", r)
	}
	if !slices.Equal(r.Nameservers, []string{"elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"}) {
		t.Fatalf("nameservers %v", r.Nameservers)
	}
	if r.RegisteredAt == nil || r.RegisteredAt.Year() != 1995 || r.ExpiresAt == nil || r.ExpiresAt.Year() != 2027 || r.UpdatedAt == nil {
		t.Fatalf("dates %+v", r)
	}
	if len(r.Status) != 3 || r.RegistrarURL != base+"/registrar/domain/EXAMPLE.COM" {
		t.Fatalf("status/link %+v", r)
	}
	more, err := Parse("example.com", r.RegistrarURL, fixture(t, "registrar-example.com.json", base))
	if err != nil {
		t.Fatal(err)
	}
	r.Merge(more)
	if r.RegistrantOrg != "Example Holdings Ltd" || r.RegistrantCountry != "US" {
		t.Fatalf("registrant %+v", r)
	}
	// Registry data wins over the registrar's.
	if r.Registrar != "RESERVED-Internet Assigned Numbers Authority" || len(r.Nameservers) != 2 {
		t.Fatalf("merge overrode registry data: %+v", r)
	}
	// PII: no person name, e-mail, phone or street address reaches the
	// asset.
	b, _ := json.Marshal(Asset("example.com", r))
	for _, pii := range []string{"Jane", "jane@", "5555550100", "REDACTED"} {
		if strings.Contains(string(b), pii) {
			t.Errorf("asset carries %q: %s", pii, b)
		}
	}
}

func TestParseRefusesForeignAnswers(t *testing.T) {
	if _, err := Parse("example.net", "s", fixture(t, "registry-example.com.json", "https://x")); err == nil {
		t.Fatal("an answer for another domain was accepted")
	}
	if _, err := Parse("example.com", "s", []byte(`{"objectClassName":"entity","ldhName":"example.com"}`)); err == nil {
		t.Fatal("a non-domain object was accepted")
	}
	if _, err := Parse("example.com", "s", []byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

// registryBase is where the fixtures say the registry is; the test
// transport sends every request to the TLS test server and records the
// host it was meant for.
const registryBase = "https://rdap.registry.test"

type recorder struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hosts []string
	hits  map[string]int
	// registrarLink replaces the registrar link of the registry answer.
	registrarLink string
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

// rdapServer serves the fixtures over TLS, counts requests by path and
// points the tool at it.
func rdapServer(t *testing.T) *recorder {
	t.Helper()
	rec := &recorder{hits: map[string]int{}}
	rec.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.hits[r.URL.Path]++
		link := rec.registrarLink
		rec.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "openctem-sensor-rdap/") {
			http.Error(w, "no user agent", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/dns.json":
			_, _ = w.Write(fixture(t, "dns.json", registryBase))
		case "/com/v1/domain/example.com":
			b := fixture(t, "registry-example.com.json", registryBase)
			if link != "" {
				b = []byte(strings.ReplaceAll(string(b), registryBase+"/registrar/domain/EXAMPLE.COM", link))
			}
			_, _ = w.Write(b)
		case "/registrar/domain/EXAMPLE.COM", "/rdap/domain/EXAMPLE.COM":
			_, _ = w.Write(fixture(t, "registrar-example.com.json", registryBase))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(rec.srv.Close)
	oldClient, oldBoot, oldInterval := lookup.HTTPClient, bootstrap, requestInterval
	lookup.HTTPClient = func(time.Duration) *http.Client { return &http.Client{Transport: rec} }
	bootstrap.URL = "https://data.iana.test/dns.json"
	requestInterval = 0
	t.Cleanup(func() { lookup.HTTPClient, bootstrap, requestInterval = oldClient, oldBoot, oldInterval })
	return rec
}

func task(t *testing.T, cache string, cfg *Config, values ...string) tool.Task {
	t.Helper()
	l := lookup.Local{CacheDir: cache}
	if cfg != nil {
		l.Config, _ = json.Marshal(cfg)
	}
	raw, _ := json.Marshal(l)
	tt := tool.Task{Capability: "lookup.rdap@1", Local: raw}
	for i, v := range values {
		tt.Targets = append(tt.Targets, tool.Target{Ref: string(rune('a' + i)), Type: "domain", Value: v})
	}
	return tt
}

func TestRunWithRecordedAnswers(t *testing.T) {
	rec := rdapServer(t)
	cache := t.TempDir()
	res := testkit.Run(t, Tool, task(t, cache, nil, "example.com", "missing.com", "example.kg", "not a domain"))
	res.RequireStatus(t, tool.StatusPartial)
	if res.Report == nil || len(res.Report.Assets) != 1 {
		t.Fatalf("report %+v", res.Report)
	}
	a := res.Report.Assets[0]
	d := a.Technical.Domain
	if a.Type != ctis.AssetTypeDomain || a.Value != "example.com" || d.Registrar == "" || len(d.Nameservers) != 2 ||
		d.WHOIS["registrant_org"] != "Example Holdings Ltd" || d.WHOIS["rdap_server"] != registryBase+"/com/v1/" {
		t.Fatalf("asset %+v %+v", a, d)
	}
	// The report keeps to the capability contract (the runtime checks it
	// again on the sensor).
	if c, ok := capability.Lookup("lookup.rdap@1"); !ok {
		t.Fatal("lookup.rdap@1 not in the taxonomy")
	} else if v, err := c.Check(res.Report, capability.CheckOptions{}); err != nil || len(v) != 0 {
		t.Fatalf("contract: %v %v", v, err)
	}
	states := map[string]tool.TargetState{}
	for _, o := range res.Targets {
		states[o.Ref] = o.State
	}
	// Unregistered (404) and no https service: looked up, nothing to say.
	// Not a domain: skipped.
	if states["a"] != tool.StateDone || states["b"] != tool.StateDone || states["c"] != tool.StateDone || states["d"] != tool.StateSkipped {
		t.Fatalf("target states %v", states)
	}
	// The bootstrap is cached across tasks; per-domain answers are not.
	res = testkit.Run(t, Tool, task(t, cache, nil, "example.com"))
	res.RequireStatus(t, tool.StatusOK)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.hits["/dns.json"] != 1 || rec.hits["/com/v1/domain/example.com"] != 2 || rec.hits["/registrar/domain/EXAMPLE.COM"] != 2 {
		t.Fatalf("hits %v", rec.hits)
	}
	for _, h := range rec.hosts {
		if h != "data.iana.test" && h != "rdap.registry.test" {
			t.Errorf("request to %s", h)
		}
	}
}

func TestRunWithoutRegistrar(t *testing.T) {
	rec := rdapServer(t)
	off := false
	res := testkit.Run(t, Tool, task(t, t.TempDir(), &Config{FollowRegistrar: &off}, "example.com"))
	res.RequireStatus(t, tool.StatusOK)
	if res.Report.Assets[0].Technical.Domain.WHOIS["registrant_org"] != "" {
		t.Fatal("registrar asked although follow_registrar is off")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.hits["/registrar/domain/EXAMPLE.COM"] != 0 {
		t.Fatalf("hits %v", rec.hits)
	}
}

// SECURITY: a registry answer that links to the target itself (a
// registrar run by the domain owner), or over plain HTTP, is never
// followed: a passive lookup sends nothing to the target hosts.
func TestRunNeverFollowsALinkToTheTarget(t *testing.T) {
	for _, link := range []string{
		"https://rdap.example.com/registrar/domain/EXAMPLE.COM",
		"https://example.com/rdap/domain/EXAMPLE.COM",
		"http://rdap.registrar.test/registrar/domain/EXAMPLE.COM",
	} {
		rec := rdapServer(t)
		rec.registrarLink = link
		res := testkit.Run(t, Tool, task(t, t.TempDir(), nil, "example.com"))
		res.RequireStatus(t, tool.StatusOK)
		if res.Report.Assets[0].Technical.Domain.WHOIS["registrant_org"] != "" {
			t.Fatalf("%s: followed", link)
		}
		rec.mu.Lock()
		for _, h := range rec.hosts {
			if strings.HasSuffix(h, "example.com") || h == "rdap.registrar.test" {
				t.Errorf("%s: a request went to %s", link, h)
			}
		}
		rec.mu.Unlock()
	}
}

func TestScannerIdentity(t *testing.T) {
	sc := NewScanner()
	if sc.Name() != "rdap" || !sc.TakesCapabilityJobs() || sc.ToolContract() == nil {
		t.Fatal("scanner identity")
	}
	if ok, _, err := sc.IsInstalled(t.Context()); !ok || err != nil {
		t.Fatal("compiled-in tool not installed")
	}
}
