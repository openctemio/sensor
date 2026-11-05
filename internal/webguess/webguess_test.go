package webguess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/capability"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
	"github.com/openctemio/sdk-go/pkg/webdiff"
	"github.com/openctemio/sdk-go/pkg/webscope"
	"github.com/openctemio/sensor/internal/toolrun"
)

func TestMain(m *testing.M) {
	// This test binary is also the tool child of the out-of-process path.
	executor.RunLauncherIfRequested()
	adapter.Dispatch(toolrun.Registered()...)
	os.Exit(m.Run())
}

// The manifest is valid (MustManifest at init) and implements
// enumerate.web_paths@1 at L2: every standard param of the capability is
// mapped onto a configuration key the schema declares. enumerate.web_params
// is not implemented.
func TestManifestMapsEveryStandardParam(t *testing.T) {
	c, ok := capability.Lookup("enumerate.web_paths@1")
	if !ok {
		t.Fatal("enumerate.web_paths@1 is not in the contract taxonomy")
	}
	im, ok := Manifest.Implementation(c.Ref())
	if !ok {
		t.Fatal("the manifest does not implement enumerate.web_paths@1")
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(Manifest.Config, &schema); err != nil {
		t.Fatal(err)
	}
	for _, p := range c.Params {
		m, ok := im.Params[p.Name]
		if !ok {
			t.Errorf("standard param %s is not mapped", p.Name)
			continue
		}
		if _, ok := schema.Properties[m.ConfigKey(p.Name)]; !ok {
			t.Errorf("param %s maps to %s, which the configuration does not declare", p.Name, m.ConfigKey(p.Name))
		}
	}
	if _, ok := Manifest.Implementation("enumerate.web_params@1"); ok {
		t.Error("enumerate.web_params@1 is implemented")
	}
	if Manifest.Features == nil || !Manifest.Features.WebScope || Manifest.Permissions.Network != tool.NetTargets {
		t.Errorf("features %+v network %s", Manifest.Features, Manifest.Permissions.Network)
	}
	if s, ok := Manifest.Slot(Slot); !ok || s.Kind != "wordlist" || s.Purpose != "web-paths" {
		t.Errorf("slot %+v", s)
	}
}

// SECURITY: the tool refuses to start without a web scope that allows only
// GET and HEAD and caps the requests per host.
func TestRefusesWithoutABoundingScope(t *testing.T) {
	for name, ws := range map[string]*webscope.Scope{
		"none":       nil,
		"no methods": {MaxRequestsPerHost: 100},
		"post":       {Methods: []string{"GET", "POST"}, MaxRequestsPerHost: 100},
		"options":    {Methods: []string{"GET", "HEAD", "OPTIONS"}, MaxRequestsPerHost: 100},
		"no cap":     {Methods: []string{"GET", "HEAD"}},
	} {
		err := checkScope(ws)
		if te := tool.AsError(err); err == nil || te.Class != tool.RefusedByPolicy {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkScope(&webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: 100}); err != nil {
		t.Errorf("a bounding scope: %v", err)
	}
	if err := checkScope(&webscope.Scope{Methods: []string{"GET"}, MaxRequestsPerHost: 100}); err != nil {
		t.Errorf("GET alone: %v", err)
	}
}

// SECURITY: candidates the web scope refuses, the scan excludes or that name
// a state-changing action are never requested.
func TestCandidateFilter(t *testing.T) {
	ws := &webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: 100, DenyPaths: []string{"/admin"}}
	base, _ := originURL("https://app.example.com")
	for c, want := range map[string]bool{
		"/backup.zip": true, "/admin": false, "/Admin/x": false, "/%61dmin": false, "/x/../admin": false, "/admin;x": false,
		"/logout": false, "/users/delete": false, "/private/x": false, "/PRIVATE": false, "/a%2fb": false, "/..;/x": false,
		"/ok/": true, "/.env": true,
		"/\uff41dmin": false, "/\u017fecret": false, "/caf\u00e9": false, "/%ef%bd%81dmin": false, "/a%2541": false,
	} {
		if got := allowedCandidate(ws, []string{"app.example.com"}, []string{"/private"}, base, c); got != want {
			t.Errorf("%s: allowed %v, want %v", c, got, want)
		}
	}
}

// site is a fixture origin: missing paths answer a soft-404 page (200 with
// the path, a time and a token), planted paths answer their own content,
// and every request (method and path) is recorded.
type site struct {
	mu   sync.Mutex
	seen []string
	n    int
}

func (s *site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.seen = append(s.seen, r.Method+" "+r.URL.EscapedPath())
	s.n++
	i := s.n
	s.mu.Unlock()
	switch r.URL.Path {
	case "/":
		_, _ = fmt.Fprint(w, "<html><head><title>Shop</title></head><body>welcome</body></html>")
	case "/backup.zip":
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("PK\x03\x04 archive"))
	case "/api/v1/users":
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"users":[`+strings.Repeat(`{"id":0,"name":"user"},`, 50)+`{"id":1}]}`)
	case "/old/":
		_, _ = fmt.Fprint(w, "<html><head><title>Index of /old</title></head><body><pre><a href=\"db.sql\">db.sql</a> 2026-01-01 4.2M</pre></body></html>")
	case "/old":
		http.Redirect(w, r, "/old/", http.StatusMovedPermanently)
	case "/admin":
		_, _ = fmt.Fprint(w, "<html><head><title>Admin</title></head><body>secret console</body></html>")
	case "/logout":
		_, _ = fmt.Fprint(w, "<html><head><title>Bye</title></head><body>signed out</body></html>")
	default:
		sum := sha256.Sum256([]byte(fmt.Sprint(i)))
		_, _ = fmt.Fprintf(w, "<html><head><title>Not here</title></head><body>No page at %s (%s, ref %s)</body></html>",
			r.URL.Path, time.Now().Format(time.RFC3339Nano), hex.EncodeToString(sum[:16]))
	}
}

func (s *site) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func inline(list string) *core.ResolvedContent {
	sum := sha256.Sum256([]byte(list))
	return &core.ResolvedContent{Slots: []core.ResolvedSlot{{Slot: Slot,
		Inline: []core.ResolvedList{{Purpose: "web-paths", SHA256: hex.EncodeToString(sum[:]), Data: []byte(list)}}}}}
}

// SECURITY (end to end): the tool, run out of process on a fixture origin
// with the platform's list inline, a GET/HEAD scope with a request cap and a
// denied path:
//   - reports exactly the planted paths of its list (no soft-404 answer, no
//     path outside the list), with the evidence and no body;
//   - sends only GET, nothing under the denied path, nothing that names a
//     state-changing action, at most the cap;
//   - states the candidates the scope filtered as the origin's coverage gap
//     (the destructive ones never reach it: the list composition drops them).
func TestEndToEnd(t *testing.T) {
	s := &site{}
	srv := httptest.NewServer(s)
	defer srv.Close()
	const limit = 60
	ws := &webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: limit, DenyPaths: []string{"/admin"}}
	list := "backup.zip\napi/v1/users\nold/\nmissing\nnothing.php\nadmin\nlogout\nusers/delete\n"
	res, err := NewScanner().ScanTargets(context.Background(), []string{srv.URL}, &core.ScanOptions{
		Capability: "enumerate.web_paths@1", MaxTier: "T1", WebScope: ws, Content: inline(list),
		Params: map[string]json.RawMessage{"lists": json.RawMessage(`["derived"]`), "max_requests_per_origin": json.RawMessage(`300`), "rate": json.RawMessage(`5`)},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var rep ctis.Report
	if err := json.Unmarshal(res.RawOutput, &rep); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range rep.Endpoints {
		got = append(got, e.Path)
		raw, _ := json.Marshal(e)
		if e.Method != "GET" || e.StatusCode == 0 || !strings.Contains(string(raw), `"response":{"hash":"`) {
			t.Errorf("endpoint %s", raw)
		}
		if strings.Contains(string(raw), "archive") || strings.Contains(string(raw), "user") && e.Path != "/api/v1/users" {
			t.Errorf("a body leaked: %s", raw)
		}
	}
	sort.Strings(got)
	if want := []string{"/api/v1/users", "/backup.zip", "/old/"}; !slices.Equal(got, want) {
		t.Fatalf("reported %v, want %v", got, want)
	}
	reqs := s.requests()
	for _, r := range reqs {
		method, p, _ := strings.Cut(r, " ")
		if method != "GET" || strings.HasPrefix(strings.ToLower(p), "/admin") || strings.Contains(p, "logout") || strings.Contains(p, "delete") {
			t.Errorf("the origin saw %q", r)
		}
	}
	if len(reqs) > limit {
		t.Errorf("%d requests, the cap is %d", len(reqs), limit)
	}
	if len(res.CoverageGaps) != 1 || res.CoverageGaps[0].Host != strings.ToLower(srv.URL) ||
		res.CoverageGaps[0].Reason != webdiff.GapScopeFiltered || res.CoverageGaps[0].Detail != "scope_filtered=1" {
		// /admin by the scope; logout and users/delete never reach the tool
		// (the tool host's list composition drops destructive entries).
		t.Errorf("coverage gaps %+v", res.CoverageGaps)
	}
}

// SECURITY: the tool never runs without the bounding scope, end to end.
func TestEndToEndRefusedWithoutScope(t *testing.T) {
	s := &site{}
	srv := httptest.NewServer(s)
	defer srv.Close()
	_, err := NewScanner().ScanTargets(context.Background(), []string{srv.URL}, &core.ScanOptions{
		Capability: "enumerate.web_paths@1", WebScope: &webscope.Scope{Methods: []string{"GET", "POST"}, MaxRequestsPerHost: 50},
		Content: inline("backup.zip\n")})
	if err == nil {
		t.Fatal("ran under a scope that allows POST")
	}
	if n := len(s.requests()); n != 0 {
		t.Fatalf("the origin saw %d requests", n)
	}
}

// An origin whose first answer is an edge challenge is skipped
// (edge_protected): one request, no endpoint, the gap names the edge.
func TestEdgeChallengedOriginSkipped(t *testing.T) {
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `<html><head><title>Just a moment...</title></head><body><script src="/cdn-cgi/challenge-platform/x"></script></body></html>`)
	}))
	defer srv.Close()
	res, err := NewScanner().ScanTargets(context.Background(), []string{srv.URL}, &core.ScanOptions{
		Capability: "enumerate.web_paths@1", WebScope: &webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: 50},
		Content: inline("backup.zip\nadmin-panel\n")})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var rep ctis.Report
	_ = json.Unmarshal(res.RawOutput, &rep)
	mu.Lock()
	defer mu.Unlock()
	if len(rep.Endpoints) != 0 || n != 1 {
		t.Fatalf("%d endpoints after %d requests", len(rep.Endpoints), n)
	}
	if len(res.CoverageGaps) != 1 || res.CoverageGaps[0].Reason != webdiff.GapEdgeProtected || res.CoverageGaps[0].Edge != "challenged" {
		t.Fatalf("coverage gaps %+v", res.CoverageGaps)
	}
}

func TestOriginOf(t *testing.T) {
	for in, want := range map[string]string{"https://App.Example.com:8443/x?y": "https://app.example.com:8443", "http://a.example": "http://a.example"} {
		if got, err := originOf(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"app.example.com", "ftp://a", "https://u:p@a.example", "https://"} {
		if _, err := originOf(in); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
}

func originURL(s string) (*url.URL, error) { return url.Parse(s) }

// An origin on which no request was sent (the list holds only what the scope
// refuses) is reported with the gap no_candidates, so the
// platform gives its dispatch claim back; the origin saw nothing.
func TestNoCandidatesIsReported(t *testing.T) {
	for name, list := range map[string]string{"only denied": "admin\n"} {
		s := &site{}
		srv := httptest.NewServer(s)
		ws := &webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: 60, DenyPaths: []string{"/admin"}}
		res, err := NewScanner().ScanTargets(context.Background(), []string{srv.URL}, &core.ScanOptions{
			Capability: "enumerate.web_paths@1", MaxTier: "T1", WebScope: ws, Content: inline(list),
			Params: map[string]json.RawMessage{"lists": json.RawMessage(`["derived"]`), "max_requests_per_origin": json.RawMessage(`300`), "rate": json.RawMessage(`5`)},
		})
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n := len(s.requests()); n != 0 {
			t.Errorf("%s: the origin saw %d requests", name, n)
		}
		if len(res.CoverageGaps) != 1 || res.CoverageGaps[0].Reason != toolrun.GapNoCandidates {
			t.Errorf("%s: coverage gaps %+v", name, res.CoverageGaps)
		}
	}
}
