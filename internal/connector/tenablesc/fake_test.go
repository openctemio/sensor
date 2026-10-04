package tenablesc

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

const (
	testAccessKey = "0123456789abcdef0123456789abcdef"
	testSecretKey = "fedcba9876543210fedcba9876543210"
	testAPIKey    = "accesskey=" + testAccessKey + "; secretkey=" + testSecretKey + ";"
)

// fakeSC is a Tenable.sc API built from the fixtures in testdata/tenablesc.
type fakeSC struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	version   string
	datasets  map[string][]json.RawMessage // "vulndetails/cumulative", "vulndetails/patched", "sumip/cumulative"
	plugins   map[string]json.RawMessage
	queries   []analysisWire
	requests  []string
	badKeys   int
	intercept func(w http.ResponseWriter, r *http.Request, n int) bool // true: handled
	n         int
}

type analysisWire struct {
	Type       string `json:"type"`
	SourceType string `json:"sourceType"`
	SortField  string `json:"sortField"`
	Query      struct {
		Tool        string   `json:"tool"`
		SourceType  string   `json:"sourceType"`
		StartOffset int      `json:"startOffset"`
		EndOffset   int      `json:"endOffset"`
		Filters     []Filter `json:"filters"`
	} `json:"query"`
}

func newFakeSC(t *testing.T) *fakeSC {
	t.Helper()
	f := &fakeSC{t: t, version: "6.4.0", datasets: map[string][]json.RawMessage{}, plugins: map[string]json.RawMessage{}}
	f.datasets["vulndetails/cumulative"] = loadRows(t, "cumulative.json")
	f.datasets["vulndetails/patched"] = loadRows(t, "mitigated.json")
	f.datasets["sumip/cumulative"] = loadRows(t, "hosts.json")
	b, err := os.ReadFile(filepath.Join("testdata", "tenablesc", "plugins.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &f.plugins); err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func loadRows(t *testing.T, name string) []json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "tenablesc", name))
	if err != nil {
		t.Fatal(err)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func writeEnvelope(w http.ResponseWriter, status int, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "regular", "response": response, "error_code": 0, "error_msg": "",
		"warnings": []any{}, "timestamp": time.Now().Unix(),
	})
}

func writeError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "regular", "response": "", "error_code": code, "error_msg": msg, "warnings": []any{},
	})
}

func (f *fakeSC) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.n++
	n := f.n
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	intercept := f.intercept
	f.mu.Unlock()
	if r.Header.Get("x-apikey") != testAPIKey {
		f.mu.Lock()
		f.badKeys++
		f.mu.Unlock()
		writeError(w, http.StatusUnauthorized, 74, "Invalid API keys")
		return
	}
	if intercept != nil && intercept(w, r, n) {
		return
	}
	switch {
	case r.URL.Path == "/rest/system":
		writeEnvelope(w, 200, map[string]any{"version": f.version, "buildID": "202609010000"})
	case r.URL.Path == "/rest/status":
		writeEnvelope(w, 200, map[string]any{"licenseStatus": "Valid", "licensedIPs": "2048", "activeIPs": "1530"})
	case r.URL.Path == "/rest/analysis" && r.Method == http.MethodPost:
		var q analysisWire
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &q); err != nil {
			writeError(w, 200, 143, "bad query")
			return
		}
		f.mu.Lock()
		f.queries = append(f.queries, q)
		rows := f.datasets[q.Query.Tool+"/"+q.Query.SourceType]
		f.mu.Unlock()
		start, end := q.Query.StartOffset, q.Query.EndOffset
		if start > len(rows) {
			start = len(rows)
		}
		if end > len(rows) {
			end = len(rows)
		}
		page := rows[start:end]
		writeEnvelope(w, 200, map[string]any{
			"totalRecords": jsonString(len(rows)), "returnedRecords": len(page),
			"startOffset": jsonString(start), "endOffset": jsonString(end), "results": page,
		})
	case strings.HasPrefix(r.URL.Path, "/rest/plugin/"):
		id := strings.TrimPrefix(r.URL.Path, "/rest/plugin/")
		f.mu.Lock()
		p, ok := f.plugins[id]
		f.mu.Unlock()
		if !ok {
			writeError(w, 403, 146, "Plugin not found or not visible")
			return
		}
		writeEnvelope(w, 200, p)
	default:
		writeError(w, 404, 1, "no such resource")
	}
}

func jsonString(n int) string { return strconvItoa(n) }

func strconvItoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// caFile writes the fake server's certificate as a CA file.
func (f *fakeSC) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

// instance is a config instance pointing at the fake server.
func (f *fakeSC) instance() *Instance {
	u, _ := url.Parse(f.srv.URL)
	return &Instance{
		Name: "sc-test", URL: u, CAPEM: f.caPEM(),
		AccessKey: Secret{testAccessKey}, SecretKey: Secret{testSecretKey},
		Allow: Allow{
			Operations:   map[string]bool{OperationSync: true},
			Repositories: []int{5, 7},
		},
		Limits: Limits{PageSize: 2, MaxRecords: 1000, MaxResponseBytes: 1 << 20, RequestsPerSecond: 1000},
	}
}

// testClientOptions let the client reach httptest on loopback and skip
// backoff sleeps; production clients cannot do either.
func testClientOptions(sleeps *[]time.Duration) clientOptions {
	return clientOptions{
		blocked: func(ip net.IP) bool { return httpsec.IsIPBlockedWith(ip, true, true) },
		sleep: func(ctx context.Context, d time.Duration) error {
			if sleeps != nil {
				*sleeps = append(*sleeps, d)
			}
			return ctx.Err()
		},
	}
}

func (f *fakeSC) client(t *testing.T, inst *Instance, sleeps *[]time.Duration) *Client {
	t.Helper()
	c, err := newClient(inst, testClientOptions(sleeps))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeSC) setIntercept(fn func(w http.ResponseWriter, r *http.Request, n int) bool) {
	f.mu.Lock()
	f.intercept = fn
	f.mu.Unlock()
}

func (f *fakeSC) recorded() ([]analysisWire, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]analysisWire(nil), f.queries...), append([]string(nil), f.requests...)
}

func (f *fakeSC) badKeyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.badKeys
}
