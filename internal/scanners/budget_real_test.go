package scanners

// The per-host budget with the real tools, measured on the target's side.
//
// nuclei, httpx and katana run with the command lines the sensor builds
// for them, against a server in this process on 127.0.0.1 that speaks
// HTTPS, keeps connections alive and offers HTTP/2, and that counts every
// request it receives. Nothing here leaves the machine.
//
// The tools' own flags are the enforcement where no forwarder is in the
// path, and for requests a forwarder cannot count (HTTP/2 streams on a
// tunnel it passes through): these tests assert that the flags the sensor
// derives from the budget keep what one host receives within it.
//
// They need the tools' binaries: NUCLEI_REAL_BIN, HTTPX_REAL_BIN and
// KATANA_REAL_BIN name them; a test without its binary is skipped.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sensor/internal/egressenv"
	"github.com/openctemio/sensor/internal/recon"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/toolrun"
)

// countingSite is an HTTPS target that counts what it receives: when each
// request arrived, how many were in flight and how many came over HTTP/2.
type countingSite struct {
	srv   *httptest.Server
	links int // the pages the root links to (for a crawler)

	mu       sync.Mutex
	arrivals []time.Time
	conns    []time.Time // connections accepted (a TLS probe opens one without a request)
	inflight int
	maxIn    int
	h2       int
}

func newCountingSite(t *testing.T, ip string, links int) *countingSite {
	t.Helper()
	s := &countingSite{links: links}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	if ip != "127.0.0.1" {
		_ = s.srv.Listener.Close()
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
		if err != nil {
			t.Skipf("no listener on %s: %v", ip, err)
		}
		s.srv.Listener = ln
	}
	s.srv.EnableHTTP2 = true
	s.srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.mu.Lock()
			s.conns = append(s.conns, time.Now())
			s.mu.Unlock()
		}
	}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

func (s *countingSite) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.arrivals = append(s.arrivals, time.Now())
	s.inflight++
	s.maxIn = max(s.maxIn, s.inflight)
	if r.ProtoMajor == 2 {
		s.h2++
	}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.inflight--; s.mu.Unlock() }()
	time.Sleep(20 * time.Millisecond)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Path == "/" {
		var b strings.Builder
		b.WriteString("<html><body><h1>fixture</h1>")
		for i := range s.links {
			fmt.Fprintf(&b, `<a href="/p/%d">page %d</a> `, i, i)
		}
		b.WriteString("</body></html>")
		_, _ = w.Write([]byte(b.String()))
		return
	}
	_, _ = fmt.Fprintf(w, "<html><body>page %s</body></html>", r.URL.Path)
}

func (s *countingSite) port() string {
	_, p, _ := net.SplitHostPort(s.srv.Listener.Addr().String())
	return p
}

// measured is what the site counted.
type measured struct {
	total int
	// span is the time from the first request to the last.
	span time.Duration
	// peak1 and peak5 are the most requests in any window of one second
	// and of five seconds.
	peak1, peak5 int
	maxIn, h2    int
	// conns is how many connections the site accepted, connPeak1 the most
	// in any window of one second.
	conns, connPeak1 int
}

func (s *countingSite) measured() measured {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := slices.Clone(s.arrivals)
	slices.SortFunc(a, func(x, y time.Time) int { return x.Compare(y) })
	m := measured{total: len(a), maxIn: s.maxIn, h2: s.h2}
	if len(a) == 0 {
		return m
	}
	m.span = a[len(a)-1].Sub(a[0])
	peak := func(a []time.Time, d time.Duration) int {
		lo, best := 0, 0
		for hi := range a {
			for a[hi].Sub(a[lo]) >= d {
				lo++
			}
			best = max(best, hi-lo+1)
		}
		return best
	}
	m.peak1, m.peak5 = peak(a, time.Second), peak(a, 5*time.Second)
	c := slices.Clone(s.conns)
	slices.SortFunc(c, func(x, y time.Time) int { return x.Compare(y) })
	m.conns, m.connPeak1 = len(c), peak(c, time.Second)
	return m
}

// withinBudget asserts what one host received against budget b.
//
// The tools refill their rate once a second (a bucket of the whole rate),
// so the requests of two seconds can fall in one sliding second: the
// stated tolerance is one refill. Over five seconds, and over the whole
// run, that is the budget's rate times the time plus one refill.
func withinBudget(t *testing.T, name string, m measured, b adapt.HostBudget, wantAtLeast int) {
	t.Helper()
	t.Logf("MEASURED %s, budget %d/s and %d in flight: %d requests in %.1f s (%.1f/s; bound %d = rate x time + one refill), most in any 1 s %d (bound %d), in any 5 s %d (bound %d), %d in flight at most, %d over HTTP/2; %d connections, most in any 1 s %d",
		name, b.RPS, b.Inflight, m.total, m.span.Seconds(), float64(m.total)/max(m.span.Seconds(), 1), b.RPS*int(m.span.Seconds()+1)+b.RPS,
		m.peak1, 2*b.RPS, m.peak5, 6*b.RPS, m.maxIn, m.h2, m.conns, m.connPeak1)
	if m.total < wantAtLeast {
		t.Fatalf("%s: only %d requests arrived, want at least %d: the run did not do its work", name, m.total, wantAtLeast)
	}
	if limit := b.RPS*int(m.span.Seconds()+1) + b.RPS; m.total > limit {
		t.Errorf("%s: %d requests in %.1f s, more than %d", name, m.total, m.span.Seconds(), limit)
	}
	if m.peak1 > 2*b.RPS {
		t.Errorf("%s: %d requests in one second, budget %d/s (tolerance: one refill)", name, m.peak1, b.RPS)
	}
	if m.peak5 > 6*b.RPS {
		t.Errorf("%s: %d requests in five seconds, budget %d/s", name, m.peak5, b.RPS)
	}
	if m.maxIn > b.Inflight {
		t.Errorf("%s: %d requests in flight, budget %d", name, m.maxIn, b.Inflight)
	}
	// Connections count too: a probe that opens a connection without a
	// request (a TLS fingerprint) is traffic to the host all the same.
	if m.connPeak1 > 2*b.RPS {
		t.Errorf("%s: %d connections in one second, budget %d/s (tolerance: one refill)", name, m.connPeak1, b.RPS)
	}
}

// realBin is the binary named by env, or the test is skipped.
func realBin(t *testing.T, env string) string {
	t.Helper()
	bin := os.Getenv(env)
	if bin == "" {
		t.Skipf("%s is not set", env)
	}
	return bin
}

// inProcess runs the scanners in this process, without the tool host: no
// forwarder, so the tools' flags are the only enforcement.
func inProcess(t *testing.T) {
	t.Helper()
	t.Setenv(toolrun.EnvRuntime, "in-process")
	t.Setenv(egressenv.EnvProxy, "")
	off := false
	toolrun.SetPerHostEnforced(&off)
	t.Cleanup(func() { toolrun.SetPerHostEnforced(nil) })
}

// budgetsUnderTest are the budgets the tools are measured under: Standard,
// and a signed Fast on a Standard sensor (which stays Standard).
func budgetsUnderTest() map[string]adapt.HostBudget {
	return map[string]adapt.HostBudget{
		"Standard":                         adapt.DefaultBudget(),
		"signed Fast on a Standard sensor": adapt.ResolveBudget(adapt.PacingStandard, &adapt.JobBudget{Level: "fast"}, adapt.BudgetCeiling{}),
	}
}

// httpx's -rl counts targets, and a target costs its host more than one
// request with the probes that are on: a second request for the favicon,
// and fourteen TLS connections for a JARM fingerprint where httpx dials
// itself.
// The sensor divides the rate by that cost (httpx.Scanner.PacedLimits).
func TestRealHTTPXStaysUnderTheHostBudget(t *testing.T) {
	bin := realBin(t, "HTTPX_REAL_BIN")
	inProcess(t)
	urlsOf := func(site *countingSite, n int) []string {
		var urls []string
		for i := range n {
			urls = append(urls, "https://127.0.0.1:"+site.port()+"/p/"+strconv.Itoa(i))
		}
		return urls
	}
	for name, b := range budgetsUnderTest() {
		t.Run("one request a target, "+name, func(t *testing.T) {
			site := newCountingSite(t, "127.0.0.1", 0)
			hx := httpx.NewScanner()
			hx.Binary = bin
			hx.Favicon, hx.Jarm = false, false
			// A person asks for far more than the budget.
			opts := &core.ScanOptions{RateLimit: 150, Concurrency: 50, HostBudget: b}
			res, err := recon.NewScanner(hx).ScanTargets(context.Background(), urlsOf(site, 150), opts)
			if err != nil {
				t.Fatalf("httpx: %v", err)
			}
			withinBudget(t, "httpx as built (-l of 150 URLs of one host, favicon and JARM off), HTTPS with keep-alive and HTTP/2 offered", site.measured(), b, 150)
			// What was asked and what applied is in the result.
			if res == nil || res.TargetRate == nil || res.TargetRate.Budget == nil || res.TargetRate.Limited != adapt.PacingLimitedNoForwarder {
				t.Fatalf("result target rate %+v", res)
			}
			var keys []string
			for _, c := range res.TargetRate.Budget.Clamped {
				if c.By == adapt.LimitHostBudget {
					keys = append(keys, fmt.Sprintf("%s %d->%d", c.Key, c.Asked, c.To))
				}
			}
			slices.Sort(keys)
			if want := []string{"rate_limit 150->20", "threads 50->8"}; !slices.Equal(keys, want) {
				t.Errorf("clamped %v, want %v", keys, want)
			}
		})
	}
	// The default probes: the favicon (a second request a target) and JARM
	// (fourteen more connections a target). Requests and connections both
	// stay within the budget.
	t.Run("the default probes (favicon and JARM)", func(t *testing.T) {
		b := adapt.DefaultBudget()
		site := newCountingSite(t, "127.0.0.1", 0)
		hx := httpx.NewScanner()
		hx.Binary = bin
		if _, err := recon.NewScanner(hx).ScanTargets(context.Background(), urlsOf(site, 30), &core.ScanOptions{HostBudget: b}); err != nil {
			t.Fatalf("httpx: %v", err)
		}
		m := site.measured()
		withinBudget(t, "httpx as built with its default probes (-l of 30 URLs of one host: 2 requests and a JARM fingerprint each)", m, b, 60)
		if m.conns <= m.total {
			t.Logf("note: %d connections for %d requests: JARM did not open connections of its own here", m.conns, m.total)
		}
	})
}

func TestRealKatanaStaysUnderTheHostBudget(t *testing.T) {
	bin := realBin(t, "KATANA_REAL_BIN")
	inProcess(t)
	for name, b := range budgetsUnderTest() {
		t.Run(name, func(t *testing.T) {
			site := newCountingSite(t, "127.0.0.1", 150)
			kt := katana.NewScanner()
			kt.Binary = bin
			opts := &core.ScanOptions{RateLimit: 150, Concurrency: 50, HostBudget: b}
			if _, err := recon.NewScanner(kt).ScanTargets(context.Background(), []string{"https://127.0.0.1:" + site.port() + "/"}, opts); err != nil {
				t.Fatalf("katana: %v", err)
			}
			withinBudget(t, "katana as built (a crawl of 150 linked pages), HTTPS with keep-alive and HTTP/2 offered", site.measured(), b, 150)
		})
	}
}

// writeBudgetTemplates writes n templates of five GET requests each.
func writeBudgetTemplates(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	for i := range n {
		var paths []string
		for j := range 5 {
			paths = append(paths, fmt.Sprintf(`"{{BaseURL}}/p/%d-%d"`, i, j))
		}
		body := fmt.Sprintf(`id: budget-%d
info:
  name: budget %d
  author: openctem
  severity: info
http:
  - method: GET
    path: [%s]
    matchers:
      - type: word
        words: ["never-matches-%d"]
`, i, i, strings.Join(paths, ", "), i)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("budget-%d.yaml", i)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRealNucleiStaysUnderTheHostBudget(t *testing.T) {
	bin := realBin(t, "NUCLEI_REAL_BIN")
	inProcess(t)
	templates := writeBudgetTemplates(t, 30)
	for name, b := range budgetsUnderTest() {
		t.Run(name, func(t *testing.T) {
			site := newCountingSite(t, "127.0.0.1", 0)
			s := nuclei.NewScanner()
			s.Binary = bin
			// The operator's scanner config asks for far more than the budget.
			s.RateLimit, s.Concurrency = 150, 25
			s.ChooseLimits(true, true)
			opts := &core.ScanOptions{Capability: "vuln.templates@1", CustomTemplateDir: templates, HostBudget: b}
			res, err := s.ScanTargets(context.Background(), []string{"https://127.0.0.1:" + site.port()}, opts)
			if err != nil {
				t.Fatalf("nuclei: %v", err)
			}
			withinBudget(t, "nuclei as built (30 templates of 5 requests, one host), HTTPS with keep-alive and HTTP/2 offered", site.measured(), b, 150)
			if res == nil || res.TargetRate == nil || res.TargetRate.Budget == nil {
				t.Fatalf("result target rate %+v", res)
			}
			var keys []string
			for _, c := range res.TargetRate.Budget.Clamped {
				if c.By == adapt.LimitHostBudget {
					keys = append(keys, fmt.Sprintf("%s %d->%d", c.Key, c.Asked, c.To))
				}
			}
			slices.Sort(keys)
			if want := []string{"concurrency 25->8", "rate_limit 150->20"}; !slices.Equal(keys, want) {
				t.Errorf("clamped %v, want %v", keys, want)
			}
		})
	}
}

// With a forwarder in the path the flags allow a sweep over several hosts
// more than one host's budget in all (three hosts: 30 targets a second, two
// requests each). A list that is almost all one host would send that host
// the whole of it: the forwarder holds it to its budget, on the kept-alive
// HTTPS tunnels httpx opens, and the other hosts keep theirs.
func TestRealHTTPXThroughTheForwarderKeepsEachHostUnderItsBudget(t *testing.T) {
	bin := realBin(t, "HTTPX_REAL_BIN")
	t.Setenv(toolrun.EnvRuntime, "in-process")
	on := true
	toolrun.SetPerHostEnforced(&on)
	t.Cleanup(func() { toolrun.SetPerHostEnforced(nil) })
	b := adapt.DefaultBudget()
	big, small1, small2 := newCountingSite(t, "127.0.0.1", 0), newCountingSite(t, "127.0.0.2", 0), newCountingSite(t, "127.0.0.3", 0)
	scope := egress.Scope{Names: map[string][]netip.Addr{
		"a.example.com": {netip.MustParseAddr("127.0.0.1")},
		"b.example.com": {netip.MustParseAddr("127.0.0.2")},
		"c.example.com": {netip.MustParseAddr("127.0.0.3")},
	}}
	hx := httpx.NewScanner()
	hx.Binary = bin
	pace := hx.PacedLimits(b, 3, true)
	fw := egress.New(scope, egress.Limits{Rate: float64(b.SweepPace(3, true).Rate), PerHostRate: float64(b.RPS), PerHostConns: b.Inflight})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fw.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	t.Setenv(egressenv.EnvProxy, "http://"+ln.Addr().String())

	var urls []string
	for i := range 150 {
		urls = append(urls, "https://a.example.com:"+big.port()+"/p/"+strconv.Itoa(i))
	}
	for i := range 5 {
		urls = append(urls, "https://b.example.com:"+small1.port()+"/p/"+strconv.Itoa(i), "https://c.example.com:"+small2.port()+"/p/"+strconv.Itoa(i))
	}
	if _, err := recon.NewScanner(hx).ScanTargets(context.Background(), urls, &core.ScanOptions{HostBudget: b}); err != nil {
		t.Fatalf("httpx: %v", err)
	}
	m := big.measured()
	t.Logf("MEASURED httpx through the forwarder, flags -rl %d -threads %d for three hosts, 150 of 160 URLs on one host: that host got %d requests in %.1f s (%.1f/s; bound %d = rate x time + 1), most in any 1 s %d, %d in flight at most, %d over HTTP/2; the two small hosts got %d and %d",
		pace.Rate, pace.Concurrency, m.total, m.span.Seconds(), float64(m.total)/max(m.span.Seconds(), 1), b.RPS*int(m.span.Seconds()+1)+1, m.peak1, m.maxIn, m.h2,
		small1.measured().total, small2.measured().total)
	if m.total < 300 || small1.measured().total < 5 || small2.measured().total < 5 {
		t.Fatalf("the run did not reach its targets: %d, %d, %d", m.total, small1.measured().total, small2.measured().total)
	}
	// The forwarder's bucket holds one token: rate x time + 1, and at most
	// half the budget on top in any one second for requests that left
	// evenly spaced and landed bunched (the servers count after a TLS
	// handshake each).
	if m.total > b.RPS*int(m.span.Seconds()+1)+1 {
		t.Errorf("the host with 150 URLs got %d requests in %.1f s, budget %d/s", m.total, m.span.Seconds(), b.RPS)
	}
	if m.peak1 > b.RPS+b.RPS/2+1 {
		t.Errorf("the host with 150 URLs got %d requests in one second, budget %d/s", m.peak1, b.RPS)
	}
	if m.maxIn > b.Inflight {
		t.Errorf("%d requests in flight, budget %d", m.maxIn, b.Inflight)
	}
}
