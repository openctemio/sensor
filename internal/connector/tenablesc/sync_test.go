package tenablesc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var testNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// fakePusher records the reports and the command id each was bound to.
type fakePusher struct {
	mu       sync.Mutex
	reports  []*ctis.Report
	cmdIDs   []string
	fail     error
	rejected bool
}

func (p *fakePusher) PushFindings(ctx context.Context, r *ctis.Report) (*core.PushResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail != nil {
		return nil, p.fail
	}
	p.reports = append(p.reports, r)
	p.cmdIDs = append(p.cmdIDs, core.CommandIDFromContext(ctx))
	if p.rejected {
		return &core.PushResult{Success: false, Message: "nope"}, nil
	}
	return &core.PushResult{Success: true}, nil
}

func (p *fakePusher) findings() []ctis.Finding {
	var out []ctis.Finding
	for _, r := range p.reports {
		out = append(out, r.Findings...)
	}
	return out
}

func testExecutor(f *fakeSC, inst *Instance, p Pusher) *SyncExecutor {
	e := NewSyncExecutor(&Config{Instances: []*Instance{inst}}, p)
	e.now = func() time.Time { return testNow }
	e.newClient = func(in *Instance) (*Client, error) { return newClient(in, testClientOptions(nil)) }
	return e
}

func syncCmd(t *testing.T, payload map[string]any) *core.Command {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: "cmd-1", Type: CommandTypeSync, Payload: b}
}

// platformPayload is exactly what the API sends (RFC-047 §5.1).
func platformPayload(mode string) map[string]any {
	p := map[string]any{
		"scanner": "tenable_sc", "instance": "sc-test", "integration_id": "8c0e5d2a-0000-4000-8000-000000000001",
		"mode": mode, "include": []string{"hosts", "vulns", "mitigated", "plugins"}, "min_severity": 1,
	}
	if mode == ModeIncremental {
		p["window_days"] = 3
	}
	return p
}

func TestSync_EndToEnd(t *testing.T) {
	f := newFakeSC(t)
	p := &fakePusher{}
	e := testExecutor(f, f.instance(), p)
	res, err := e.Execute(context.Background(), syncCmd(t, platformPayload(ModeIncremental)))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.reports) == 0 {
		t.Fatal("nothing pushed")
	}
	for i, r := range p.reports {
		if p.cmdIDs[i] != "cmd-1" {
			t.Fatalf("report %d not bound to the command: %q", i, p.cmdIDs[i])
		}
		if r.Tool == nil || r.Tool.Name != "tenable_sc" {
			t.Fatalf("report %d tool %+v", i, r.Tool)
		}
		if r.Metadata.Branch != nil {
			t.Fatalf("report %d carries a branch: a pull must never look like a full default-branch scan", i)
		}
		if r.Metadata.CoverageType != "incremental" {
			t.Fatalf("report %d coverage %q", i, r.Metadata.CoverageType)
		}
		if err := ctis.CheckFindingAssets(r); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	fs := p.findings()
	if len(fs) != 4 {
		t.Fatalf("%d findings, want 3 open + 1 mitigated", len(fs))
	}
	var mitigated int
	for _, fd := range fs {
		if fd.Properties["tenable_state"] == stateMitigated {
			mitigated++
			if fd.Status != ctis.FindingStatusResolved {
				t.Fatalf("mitigated row status %q", fd.Status)
			}
		}
	}
	if mitigated != 1 {
		t.Fatalf("%d mitigated findings", mitigated)
	}
	md := res.Metadata
	want := map[string]any{"tenable_version": "6.4.0", "licensed_ips": int64(2048), "active_ips": int64(1530),
		"open": 3, "mitigated": 1, "plugins": 3}
	for k, v := range want {
		if md[k] != v {
			t.Fatalf("metadata %s = %v (%T), want %v", k, md[k], md[k], v)
		}
	}
	if md["hosts"].(int) < 3 {
		t.Fatalf("hosts %v", md["hosts"])
	}
	b, _ := json.Marshal(md)
	for _, secret := range []string{testAccessKey, testSecretKey, f.srv.URL, "127.0.0.1"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("metadata leaks %q", secret)
		}
	}

	// The queries: repository and severity filters, the incremental windows.
	qs, _ := f.recorded()
	var sawLastSeen, sawLastMitigated bool
	for _, q := range qs {
		raw, _ := json.Marshal(q.Query.Filters)
		if !strings.Contains(string(raw), `"repository"`) || !strings.Contains(string(raw), `{"id":"5"},{"id":"7"}`) {
			t.Fatalf("query without the repository filter: %s", raw)
		}
		if strings.Contains(string(raw), `"lastSeen","operator":"=","value":"0:3"`) {
			sawLastSeen = true
		}
		if strings.Contains(string(raw), `"lastMitigated","operator":"=","value":"0:3"`) {
			sawLastMitigated = true
		}
	}
	if !sawLastSeen || !sawLastMitigated {
		t.Fatal("incremental windows not applied")
	}
}

func TestSync_FullModeHasNoLastSeenFilter(t *testing.T) {
	f := newFakeSC(t)
	e := testExecutor(f, f.instance(), &fakePusher{})
	if _, err := e.Execute(context.Background(), syncCmd(t, platformPayload(ModeFull))); err != nil {
		t.Fatal(err)
	}
	qs, _ := f.recorded()
	for _, q := range qs {
		raw, _ := json.Marshal(q.Query.Filters)
		if strings.Contains(string(raw), "lastSeen") {
			t.Fatalf("full sync filtered on lastSeen: %s", raw)
		}
		if q.Query.SourceType == "patched" && !strings.Contains(string(raw), `"0:30"`) {
			t.Fatalf("full sync mitigated window: %s", raw)
		}
	}
}

func TestSync_Chunking(t *testing.T) {
	f := newFakeSC(t)
	var rows []json.RawMessage
	for i := 0; i < maxFindingsPerReport+5; i++ {
		rows = append(rows, json.RawMessage(fmt.Sprintf(
			`{"pluginID":"%d","pluginName":"p","severity":{"id":"2"},"ip":"10.1.%d.%d","port":"80","protocol":"TCP","repository":{"id":"5"}}`,
			100000+i, i/250, i%250)))
	}
	f.datasets["vulndetails/cumulative"] = rows
	f.datasets["vulndetails/patched"] = nil
	f.datasets["sumip/cumulative"] = nil
	inst := f.instance()
	inst.Limits.PageSize = 500
	inst.Limits.MaxRecords = 10000
	inst.Limits.MaxResponseBytes = 8 << 20
	p := &fakePusher{}
	payload := platformPayload(ModeIncremental)
	payload["include"] = []string{"vulns"}
	if _, err := testExecutor(f, inst, p).Execute(context.Background(), syncCmd(t, payload)); err != nil {
		t.Fatal(err)
	}
	if len(p.reports) != 2 || len(p.reports[0].Findings) != maxFindingsPerReport || len(p.reports[1].Findings) != 5 {
		t.Fatalf("chunks: %d reports", len(p.reports))
	}
	if p.reports[0].Metadata.ID == p.reports[1].Metadata.ID {
		t.Fatal("chunks share a report id")
	}
}

func TestSync_TooManyRecordsPushesNothingOfThatQuery(t *testing.T) {
	f := newFakeSC(t)
	inst := f.instance()
	inst.Limits.MaxRecords = 2 // cumulative has 3
	p := &fakePusher{}
	_, err := testExecutor(f, inst, p).Execute(context.Background(), syncCmd(t, platformPayload(ModeIncremental)))
	if !errors.Is(err, ErrTooManyRecords) {
		t.Fatalf("want ErrTooManyRecords, got %v", err)
	}
	if len(p.reports) != 0 {
		t.Fatalf("%d reports pushed", len(p.reports))
	}
}

func TestSync_MalformedPageFailsWithoutPushing(t *testing.T) {
	f := newFakeSC(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path != "/rest/analysis" {
			return false
		}
		_, _ = w.Write([]byte(`{"type":"regular","response":{"results":[`))
		return true
	})
	p := &fakePusher{}
	if _, err := testExecutor(f, f.instance(), p).Execute(context.Background(), syncCmd(t, platformPayload(ModeIncremental))); err == nil {
		t.Fatal("malformed page accepted")
	}
	if len(p.reports) != 0 {
		t.Fatal("pushed after a malformed page")
	}
}

func TestSync_PushFailureFailsCommand(t *testing.T) {
	f := newFakeSC(t)
	for _, p := range []*fakePusher{{fail: errors.New("down")}, {rejected: true}} {
		if _, err := testExecutor(f, f.instance(), p).Execute(context.Background(), syncCmd(t, platformPayload(ModeFull))); err == nil {
			t.Fatal("a failed push must fail the command")
		}
	}
}

func TestSync_Admission(t *testing.T) {
	f := newFakeSC(t)
	inst := f.instance()
	mutate := map[string]func(map[string]any){
		"wrong scanner":         func(p map[string]any) { p["scanner"] = "nuclei" },
		"unknown instance":      func(p map[string]any) { p["instance"] = "sc-other" },
		"no window":             func(p map[string]any) { delete(p, "window_days") },
		"window too wide":       func(p map[string]any) { p["window_days"] = 400 },
		"bad mode":              func(p map[string]any) { p["mode"] = "everything" },
		"bad include":           func(p map[string]any) { p["include"] = []string{"credentials"} },
		"severity out of range": func(p map[string]any) { p["min_severity"] = 9 },
		"unknown field":         func(p map[string]any) { p["url"] = "https://evil.example" },
		"repos not allowed":     func(p map[string]any) { p["repositories"] = []int{9, 10} },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			p := platformPayload(ModeIncremental)
			m(p)
			_, err := testExecutor(f, inst, &fakePusher{}).Execute(context.Background(), syncCmd(t, p))
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("want ErrRefused, got %v", err)
			}
		})
	}
	if _, reqs := f.recorded(); len(reqs) != 0 {
		t.Fatalf("a refused job reached Tenable.sc: %v", reqs)
	}

	t.Run("sync not allowed", func(t *testing.T) {
		in := f.instance()
		in.Allow.Operations = map[string]bool{OperationScan: true}
		_, err := testExecutor(f, in, &fakePusher{}).Execute(context.Background(), syncCmd(t, platformPayload(ModeFull)))
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("want ErrRefused, got %v", err)
		}
	})
	t.Run("repositories narrow to the allow-list", func(t *testing.T) {
		p := platformPayload(ModeFull)
		p["repositories"] = []int{7, 9}
		f2 := newFakeSC(t)
		if _, err := testExecutor(f2, f2.instance(), &fakePusher{}).Execute(context.Background(), syncCmd(t, p)); err != nil {
			t.Fatal(err)
		}
		qs, _ := f2.recorded()
		raw, _ := json.Marshal(qs[0].Query.Filters)
		if !strings.Contains(string(raw), `[{"id":"7"}]`) {
			t.Fatalf("repositories not narrowed: %s", raw)
		}
	})
}

// TestMapping_Golden pins the CTIS the fixtures map to (run with -update to
// rewrite after an intended change).
func TestMapping_Golden(t *testing.T) {
	f := newFakeSC(t)
	p := &fakePusher{}
	if _, err := testExecutor(f, f.instance(), p).Execute(context.Background(), syncCmd(t, platformPayload(ModeIncremental))); err != nil {
		t.Fatal(err)
	}
	for _, r := range p.reports {
		r.Metadata.Timestamp = testNow
	}
	got, err := json.MarshalIndent(p.reports, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "tenablesc", "golden_reports.json")
	if *update {
		if err := os.WriteFile(golden, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Fatalf("mapping changed; diff testdata against:\n%s", got)
	}
}

func TestMapping_Fields(t *testing.T) {
	f := newFakeSC(t)
	p := &fakePusher{}
	if _, err := testExecutor(f, f.instance(), p).Execute(context.Background(), syncCmd(t, platformPayload(ModeIncremental))); err != nil {
		t.Fatal(err)
	}
	byPlugin := map[string]ctis.Finding{}
	for _, fd := range p.findings() {
		byPlugin[fd.RuleID] = fd
	}
	log4 := byPlugin["156860"]
	if log4.Severity != ctis.SeverityCritical || log4.Category != "CGI abuses" {
		t.Fatalf("log4shell severity/category: %+v", log4)
	}
	v := log4.Vulnerability
	if v == nil || len(v.CVEIDs) != 3 || v.CVEID != "CVE-2021-44228" || v.CVSSVersion != "3.x" || v.CVSSScore != 10 ||
		v.VPRScore != 10 || !v.ExploitAvailable || v.EPSSScore < 0.97 {
		t.Fatalf("log4shell vulnerability: %+v", v)
	}
	if strings.ContainsRune(log4.Description, 0) || strings.ContainsRune(log4.Description, '‮') {
		t.Fatal("control or bidi characters kept")
	}
	for _, ref := range log4.References {
		if !strings.HasPrefix(ref, "https://") {
			t.Fatalf("non-http reference kept: %q", ref)
		}
	}
	if log4.Properties["tenable_patch_pub_date"] != "2021-12-10T00:00:00Z" || log4.Properties["tenable_acr"] != 9.0 ||
		log4.Properties["tenable_aes"] != 870.0 {
		t.Fatalf("log4shell properties: %v", log4.Properties)
	}
	if _, ok := log4.Properties["tenable_plugin_mod_date"]; !ok {
		t.Fatal("plugin mod date should fall back to the plugin metadata")
	}
	if log4.Network == nil || log4.Network.Port != 8443 || log4.Network.Protocol != "tcp" ||
		log4.Fingerprint != "tenable_sc:5:10.20.0.15:156860:8443/tcp" {
		t.Fatalf("log4shell network/fingerprint: %+v %q", log4.Network, log4.Fingerprint)
	}
	ssl := byPlugin["51192"]
	if ssl.Properties["tenable_accept_risk"] != true || ssl.Category != "General" || ssl.Vulnerability.VPRScore != 0 {
		t.Fatalf("ssl: %+v", ssl)
	}
	trace := byPlugin["10287"]
	if trace.Network != nil {
		t.Fatal("port 0 is host-level: no network location")
	}
	if _, ok := trace.Properties["tenable_acr"]; ok {
		t.Fatal("ACR 42 is out of range and must be dropped")
	}
	if _, ok := trace.Properties["tenable_aes"]; ok {
		t.Fatal("AES -5 is out of range and must be dropped")
	}
	if trace.Remediation != nil {
		t.Fatal("n/a solution kept")
	}
	ms := byPlugin["97833"]
	if ms.Status != ctis.FindingStatusResolved || ms.Properties["tenable_last_mitigated"] == nil || ms.Vulnerability.EPSSScore != 0.943 {
		t.Fatalf("mitigated: %+v", ms)
	}
}
