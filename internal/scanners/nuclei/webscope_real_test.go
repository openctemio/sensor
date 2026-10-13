//go:build linux

package nuclei

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sensor/internal/toolrun"
)

// EnvRealNuclei names a real nuclei binary for the end-to-end web-scope
// test (skipped without it).
const EnvRealNuclei = "NUCLEI_REAL_BIN"

// webScopeTemplates request an allowed path and a denied one in every form
// a server reads as the denied path, and follow a redirect to it.
var webScopeTemplates = map[string]string{
	"allowed":  `["{{BaseURL}}/public/ok"]`,
	"direct":   `["{{BaseURL}}/admin/secret"]`,
	"upper":    `["{{BaseURL}}/ADMIN/upper"]`,
	"encoded":  `["{{BaseURL}}/%61dmin/encoded"]`,
	"dots":     `["{{BaseURL}}/public/../admin/dots"]`,
	"params":   `["{{BaseURL}}/public/..;/admin/params"]`,
	"redirect": `["{{BaseURL}}/go"]`,
}

func writeWebScopeTemplates(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for id, paths := range webScopeTemplates {
		body := fmt.Sprintf(`id: ws-%s
info:
  name: web scope %s
  author: openctem
  severity: medium
http:
  - method: GET
    path: %s
    redirects: true
    max-redirects: 3
    matchers:
      - type: word
        words: ["reached"]
`, id, id, paths)
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// recordingSite answers "reached <path>" and redirects /go to a denied
// path; it records every raw path it is asked for.
type recordingSite struct {
	mu   sync.Mutex
	hits []string
}

func (s *recordingSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits = append(s.hits, r.URL.EscapedPath())
	s.mu.Unlock()
	if r.URL.Path == "/go" {
		http.Redirect(w, r, "/admin/redirected", http.StatusFound)
		return
	}
	_, _ = fmt.Fprintf(w, "reached %s", r.URL.Path)
}

func (s *recordingSite) served() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

// SECURITY (acceptance): the real nuclei binary, run out of process in a
// sandbox that confines its network to the task's forwarder, with a web
// scope that denies /admin: over HTTP and HTTPS the servers never see a
// path under /admin (direct, upper case, percent-encoded, dot segments,
// path parameters, behind a redirect), and the allowed path is reached and
// reported.
func TestRealNucleiKeepsToWebScope(t *testing.T) {
	bin := os.Getenv(EnvRealNuclei)
	if bin == "" {
		t.Skipf("%s is not set", EnvRealNuclei)
	}
	be, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, ConfineNetwork: true, RequireNetwork: true,
		Limits: executor.Limits{Processes: 1024}})
	if err != nil {
		if os.Getenv("OPENCTEM_TEST_REQUIRE_NETNS") == "1" {
			t.Fatalf("network confinement required by the environment, not available: %v", err)
		}
		t.Skipf("network confinement not available here: %v", err)
	}
	enforced(t, true)
	t.Setenv(toolrun.EnvRuntime, "")
	toolrun.SetHost(&toolhost.Host{RuntimeName: "openctem-sensor", Backend: be})
	t.Cleanup(func() { toolrun.SetHost(&toolhost.Host{RuntimeName: "openctem-sensor"}) })

	plain, secure := &recordingSite{}, &recordingSite{}
	hs := httptest.NewServer(plain)
	defer hs.Close()
	ts := httptest.NewTLSServer(secure)
	defer ts.Close()
	templates := writeWebScopeTemplates(t)

	for _, site := range []struct {
		name   string
		target string
		rec    *recordingSite
	}{
		{"http", strings.Replace(hs.URL, "127.0.0.1", "localhost", 1), plain},
		{"https", strings.Replace(ts.URL, "127.0.0.1", "localhost", 1), secure},
	} {
		t.Run(site.name, func(t *testing.T) {
			s := NewScanner()
			s.Binary = bin
			res, err := s.Scan(context.Background(), site.target, &core.ScanOptions{Capability: "vuln.templates@1",
				WebScope: denyAdmin, CustomTemplateDir: templates})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			served := site.rec.served()
			for _, p := range served {
				if l := strings.ToLower(p); strings.Contains(l, "admin") || strings.Contains(l, "%") {
					t.Errorf("the server saw %q, which the web scope denies", p)
				}
			}
			if !contains(served, "/public/ok") {
				t.Fatalf("the allowed path was not reached; served %v (stderr in result: %.500s)", served, res.Error)
			}
			if !strings.Contains(string(res.RawOutput), "ws-allowed") {
				t.Errorf("the allowed template's finding is missing: %.1000s", res.RawOutput)
			}
			for _, id := range []string{"ws-direct", "ws-upper", "ws-encoded", "ws-dots", "ws-params", "ws-redirect"} {
				if strings.Contains(string(res.RawOutput), id) {
					t.Errorf("%s matched: a denied path answered", id)
				}
			}
			t.Logf("%s: served %v", site.name, served)
		})
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
