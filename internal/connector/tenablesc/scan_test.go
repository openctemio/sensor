package tenablesc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// scanSim simulates the scan endpoints of the fake Tenable.sc.
type scanSim struct {
	mu         sync.Mutex
	created    []map[string]any
	states     []map[string]string // returned in order; the last one repeats
	polls      int
	stops      []string
	deletes    []string
	launches   []string
	deleteFail bool
	createFail bool
}

func (s *scanSim) handle(w http.ResponseWriter, r *http.Request, _ int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := r.URL.Path
	switch {
	case p == "/rest/scan" && r.Method == http.MethodPost:
		if s.createFail {
			writeError(w, 403, 143, "You do not have permission to use this policy")
			return true
		}
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		s.created = append(s.created, body)
		writeEnvelope(w, 200, map[string]any{"id": "42", "name": body["name"]})
	case p == "/rest/scan/42/launch" && r.Method == http.MethodPost:
		s.launches = append(s.launches, "42")
		writeEnvelope(w, 200, map[string]any{"scanID": "42", "scanResult": map[string]any{"id": "777", "status": "Queued"}})
	case strings.HasPrefix(p, "/rest/scanResult/") && strings.HasSuffix(p, "/stop"):
		s.stops = append(s.stops, strings.TrimSuffix(strings.TrimPrefix(p, "/rest/scanResult/"), "/stop"))
		writeEnvelope(w, 200, map[string]any{})
	case p == "/rest/scanResult/777" && r.Method == http.MethodGet:
		i := min(s.polls, len(s.states)-1)
		s.polls++
		st := s.states[i]
		writeEnvelope(w, 200, map[string]any{"id": "777", "status": st["status"], "importStatus": st["import"],
			"running": st["status"] == "Running", "totalChecks": "100", "completedChecks": "40"})
	case strings.HasPrefix(p, "/rest/scan/") && r.Method == http.MethodDelete:
		s.deletes = append(s.deletes, strings.TrimPrefix(p, "/rest/scan/"))
		if s.deleteFail {
			writeError(w, 403, 143, "cannot delete")
			return true
		}
		writeEnvelope(w, 200, map[string]any{})
	default:
		return false
	}
	return true
}

func scanInstance(f *fakeSC) *Instance {
	in := f.instance()
	in.Allow.Operations = map[string]bool{OperationSync: true, OperationScan: true}
	in.Allow.ScanPolicies = []int{1000003}
	in.Allow.ScanRepositories = []int{5}
	in.Allow.ScanZones = []int{2}
	in.Allow.MaxTargetsPerScan = 300
	in.Allow.MaxScanSeconds = 3600
	return in
}

type fakePolicy struct{ deny string }

func (p fakePolicy) CheckTarget(_ context.Context, t string) error {
	if p.deny != "" && strings.HasPrefix(t, p.deny) {
		return errors.New("outside targets.allow")
	}
	return nil
}

func newScanFixture(t *testing.T, states ...map[string]string) (*fakeSC, *scanSim, *ScanExecutor, *fakePusher) {
	t.Helper()
	f := newFakeSC(t)
	f.datasets["vulndetails/individual"] = f.datasets["vulndetails/cumulative"]
	f.datasets["sumip/individual"] = f.datasets["sumip/cumulative"]
	sim := &scanSim{states: states}
	f.setIntercept(sim.handle)
	p := &fakePusher{}
	clock := testNow
	e := NewScanExecutor(&Config{Instances: []*Instance{scanInstance(f)}}, p, fakePolicy{deny: "10.99."})
	e.now = func() time.Time { return clock }
	e.newClient = func(in *Instance) (*Client, error) { return newClient(in, testClientOptions(nil)) }
	e.pollInterval = time.Second
	e.sleep = func(ctx context.Context, d time.Duration) error {
		clock = clock.Add(d)
		return ctx.Err()
	}
	return f, sim, e, p
}

func scanPayload() map[string]any {
	return map[string]any{
		"scanner": "tenable_sc", "instance": "sc-test", "integration_id": "8c0e5d2a-0000-4000-8000-000000000001",
		"targets": []string{"10.20.0.0/28", "10.20.0.16", "app01.corp.example"}, "policy_id": 1000003,
		"repository_id": 5, "zone_id": 2, "max_scan_seconds": 1800, "min_severity": 1,
		"run_id": "r-1", "scan_id": "s-1", "pipeline_run_id": "p-1", "step_key": "scan", "step_run_id": "sr-1",
	}
}

func scanCmd(t *testing.T, p map[string]any) *core.Command {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: "cmd-scan-1", Type: CommandTypeScan, Payload: b}
}

var (
	running   = map[string]string{"status": "Running", "import": "No Results"}
	importing = map[string]string{"status": "Completed", "import": "Importing"}
	done      = map[string]string{"status": "Completed", "import": "Finished"}
)

func TestScan_HappyPath(t *testing.T) {
	f, sim, e, p := newScanFixture(t, running, importing, done)
	res, err := e.Execute(context.Background(), scanCmd(t, scanPayload()))
	if err != nil {
		t.Fatal(err)
	}
	if len(sim.created) != 1 {
		t.Fatalf("created %d scans", len(sim.created))
	}
	body := sim.created[0]
	if body["name"] != "openctem-cmd-scan-1" || body["ipList"] != "10.20.0.0/28,10.20.0.16,app01.corp.example" ||
		body["type"] != "policy" || body["timeoutAction"] != "import" {
		t.Fatalf("scan body %v", body)
	}
	for k, want := range map[string]string{"policy": "1000003", "repository": "5", "zone": "2"} {
		if m, _ := body[k].(map[string]any); m["id"] != want {
			t.Fatalf("%s = %v, want id %s", k, body[k], want)
		}
	}
	if body["maxScanTime"] != "1800" {
		t.Fatalf("maxScanTime %v", body["maxScanTime"])
	}
	if len(sim.launches) != 1 || sim.polls != 3 || len(sim.stops) != 0 {
		t.Fatalf("launches %v polls %d stops %v", sim.launches, sim.polls, sim.stops)
	}
	if len(sim.deletes) != 1 || sim.deletes[0] != "42" {
		t.Fatalf("deletes %v: only the definition this command created", sim.deletes)
	}
	qs, _ := f.recorded()
	for _, q := range qs {
		if q.SourceType != "individual" || q.ScanID != "777" || q.View != "all" {
			t.Fatalf("query not scoped to the scan result: %+v", q)
		}
	}
	if len(p.reports) == 0 {
		t.Fatal("nothing pushed")
	}
	sawHostOnly := false
	for i, r := range p.reports {
		if r.Metadata.CoverageType != CoverageFull || r.Metadata.Branch != nil || r.Tool.Name != ToolName {
			t.Fatalf("report %d: %+v", i, r.Metadata)
		}
		if p.cmdIDs[i] != "cmd-scan-1" {
			t.Fatalf("report %d bound to %q", i, p.cmdIDs[i])
		}
		for _, a := range r.Assets {
			if a.Value == "10.20.0.99" {
				sawHostOnly = true
			}
		}
	}
	if !sawHostOnly {
		t.Fatal("a scanned host without findings was not reported as an asset")
	}
	md := res.Metadata
	if md["coverage"] != CoverageFull || md["scan_result_id"] != "777" || md["definition_deleted"] != true ||
		md["scan_status"] != "Completed" || md["import_status"] != "Finished" || md["targets"] != 3 {
		t.Fatalf("metadata %v", md)
	}
	if md["addresses"] != int64(18) {
		t.Fatalf("addresses %v, want 16+1+1", md["addresses"])
	}
	raw, _ := json.Marshal(md)
	for _, leak := range []string{testAccessKey, testSecretKey, f.srv.URL, "127.0.0.1"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("metadata leaks %q", leak)
		}
	}
}

func TestScan_ZoneOmittedWhenZero(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, done)
	p := scanPayload()
	delete(p, "zone_id")
	delete(p, "max_scan_seconds")
	if _, err := e.Execute(context.Background(), scanCmd(t, p)); err != nil {
		t.Fatal(err)
	}
	if _, ok := sim.created[0]["zone"]; ok {
		t.Fatal("zone sent although the job names none")
	}
	if sim.created[0]["maxScanTime"] != "3600" {
		t.Fatalf("max scan time %v, want the config maximum", sim.created[0]["maxScanTime"])
	}
}

func TestScan_PartialOutcomes(t *testing.T) {
	for name, st := range map[string]map[string]string{
		"error":      {"status": "Error", "import": "Finished"},
		"partial":    {"status": "Partial", "import": "Finished"},
		"no results": {"status": "Completed", "import": "No Results"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, e, p := newScanFixture(t, st)
			res, err := e.Execute(context.Background(), scanCmd(t, scanPayload()))
			if err != nil {
				t.Fatal(err)
			}
			if res.Metadata["coverage"] != CoveragePartial {
				t.Fatalf("coverage %v", res.Metadata["coverage"])
			}
			for _, r := range p.reports {
				if r.Metadata.CoverageType != CoveragePartial {
					t.Fatalf("report coverage %q", r.Metadata.CoverageType)
				}
			}
		})
	}
	t.Run("import error pushes nothing", func(t *testing.T) {
		_, _, e, p := newScanFixture(t, map[string]string{"status": "Completed", "import": "Error"})
		res, err := e.Execute(context.Background(), scanCmd(t, scanPayload()))
		if err != nil || res.Metadata["coverage"] != CoveragePartial || len(p.reports) != 0 {
			t.Fatalf("err %v md %v reports %d", err, res.Metadata, len(p.reports))
		}
	})
}

func TestScan_TimeoutStopsAndIsPartial(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, running)
	p := scanPayload()
	p["max_scan_seconds"] = 600
	res, err := e.Execute(context.Background(), scanCmd(t, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(sim.stops) != 1 || sim.stops[0] != "777" {
		t.Fatalf("stops %v", sim.stops)
	}
	if res.Metadata["coverage"] != CoveragePartial || res.Metadata["timed_out"] != true || len(sim.deletes) != 1 {
		t.Fatalf("metadata %v deletes %v", res.Metadata, sim.deletes)
	}
}

func TestScan_CancelStops(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, running)
	ctx, cancel := context.WithCancel(context.Background())
	e.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	_, err := e.Execute(ctx, scanCmd(t, scanPayload()))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if len(sim.stops) != 1 || len(sim.deletes) != 1 {
		t.Fatalf("a cancelled scan must be stopped and its definition deleted: stops %v deletes %v", sim.stops, sim.deletes)
	}
}

func TestScan_DeleteFailureIsAWarning(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, done)
	sim.deleteFail = true
	res, err := e.Execute(context.Background(), scanCmd(t, scanPayload()))
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata["definition_deleted"] != false || res.Metadata["warnings"] == nil {
		t.Fatalf("metadata %v", res.Metadata)
	}
}

func TestScan_CreateFailureFails(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, done)
	sim.createFail = true
	if _, err := e.Execute(context.Background(), scanCmd(t, scanPayload())); err == nil {
		t.Fatal("a refused create must fail the command")
	}
	if len(sim.launches) != 0 || len(sim.deletes) != 0 {
		t.Fatal("nothing to launch or delete after a failed create")
	}
}

func TestScan_Admission(t *testing.T) {
	mutate := map[string]func(map[string]any){
		"wrong scanner":          func(p map[string]any) { p["scanner"] = "nessus" },
		"unknown instance":       func(p map[string]any) { p["instance"] = "other" },
		"policy not allowed":     func(p map[string]any) { p["policy_id"] = 1000009 },
		"repository not allowed": func(p map[string]any) { p["repository_id"] = 7 },
		"zone not allowed":       func(p map[string]any) { p["zone_id"] = 3 },
		"no targets":             func(p map[string]any) { p["targets"] = []string{} },
		"unknown field":          func(p map[string]any) { p["ipList"] = "0.0.0.0/0" },
		"url target":             func(p map[string]any) { p["targets"] = []string{"https://app.corp"} },
		"port target":            func(p map[string]any) { p["targets"] = []string{"10.20.0.5:22"} },
		"list in one target":     func(p map[string]any) { p["targets"] = []string{"10.20.0.5,10.20.0.6"} },
		"newline":                func(p map[string]any) { p["targets"] = []string{"10.20.0.5\n10.0.0.0/8"} },
		"too wide v4":            func(p map[string]any) { p["targets"] = []string{"10.0.0.0/8"} },
		"too wide v6":            func(p map[string]any) { p["targets"] = []string{"2001:db8::/64"} },
		"loopback":               func(p map[string]any) { p["targets"] = []string{"127.0.0.1"} },
		"metadata":               func(p map[string]any) { p["targets"] = []string{"169.254.169.254"} },
		"metadata v6":            func(p map[string]any) { p["targets"] = []string{"fd00:ec2::254"} },
		"range over metadata":    func(p map[string]any) { p["targets"] = []string{"169.254.0.0/16"} },
		"localhost name":         func(p map[string]any) { p["targets"] = []string{"localhost"} },
		"metadata name":          func(p map[string]any) { p["targets"] = []string{"metadata.google.internal"} },
		"multicast":              func(p map[string]any) { p["targets"] = []string{"224.0.0.1"} },
		"local policy":           func(p map[string]any) { p["targets"] = []string{"10.99.0.1"} },
		"too many addresses":     func(p map[string]any) { p["targets"] = []string{"10.20.0.0/23"} },
		"severity":               func(p map[string]any) { p["min_severity"] = 7 },
		"negative max":           func(p map[string]any) { p["max_scan_seconds"] = -1 },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			f, sim, e, _ := newScanFixture(t, done)
			p := scanPayload()
			m(p)
			_, err := e.Execute(context.Background(), scanCmd(t, p))
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("want ErrRefused, got %v", err)
			}
			if _, reqs := f.recorded(); len(reqs) != 0 || len(sim.created) != 0 {
				t.Fatalf("a refused job reached Tenable.sc: %v", reqs)
			}
		})
	}
	t.Run("scan not allowed", func(t *testing.T) {
		f, _, e, _ := newScanFixture(t, done)
		e.Config.Instances[0].Allow.Operations = map[string]bool{OperationSync: true}
		if _, err := e.Execute(context.Background(), scanCmd(t, scanPayload())); !errors.Is(err, ErrRefused) {
			t.Fatalf("got %v", err)
		}
		if _, reqs := f.recorded(); len(reqs) != 0 {
			t.Fatal("reached Tenable.sc")
		}
	})
	t.Run("max seconds clamp to the owner's", func(t *testing.T) {
		_, sim, e, _ := newScanFixture(t, done)
		p := scanPayload()
		p["max_scan_seconds"] = 999999
		if _, err := e.Execute(context.Background(), scanCmd(t, p)); err != nil {
			t.Fatal(err)
		}
		if sim.created[0]["maxScanTime"] != "3600" {
			t.Fatalf("maxScanTime %v", sim.created[0]["maxScanTime"])
		}
	})
}

func TestCheckScanTarget(t *testing.T) {
	ok := map[string]int64{"10.0.0.1": 1, "10.0.0.0/30": 4, "10.0.0.7/24": 256, "2001:db8::1": 1,
		"2001:db8::/124": 16, "App01.Corp.Example.": 1, "::ffff:10.0.0.5": 1}
	for in, n := range ok {
		if _, got, err := checkScanTarget(in); err != nil || got != n {
			t.Errorf("%q: %d %v, want %d", in, got, err, n)
		}
	}
	if t2, _, _ := checkScanTarget("10.0.0.7/24"); t2 != "10.0.0.0/24" {
		t.Errorf("not masked: %s", t2)
	}
	for _, bad := range []string{"", "0.0.0.0", "::", "fe80::1%eth0", "a b", "-bad.example", "x..y", strings.Repeat("a", 64) + ".example"} {
		if _, _, err := checkScanTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSync_CatalogFilteredToAllowLists(t *testing.T) {
	f := newFakeSC(t)
	in := scanInstance(f)
	res, err := testExecutor(f, in, &fakePusher{}).Execute(context.Background(), syncCmd(t, platformPayload(ModeFull)))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res.Metadata["catalog"])
	got := string(raw)
	for _, want := range []string{`"repositories":[{"id":5,"name":"Datacenter"},{"id":7,"name":"Branch IPv6"}]`,
		`"scan_repositories":[{"id":5,"name":"Datacenter"}]`, `"policies":[{"id":1000003,"name":"Basic Network Scan"}]`,
		`"scan_zones":[{"id":2,"name":"DC scanners"}]`} {
		if !strings.Contains(got, want) {
			t.Fatalf("catalog %s lacks %s", got, want)
		}
	}
	for _, leak := range []string{"Secret lab", "Full audit", "Other"} {
		if strings.Contains(got, leak) {
			t.Fatalf("catalog shows %q outside the allow-list: %s", leak, got)
		}
	}

	// Sync-only instance: no scan objects; a catalog failure is a warning.
	f2 := newFakeSC(t)
	f2.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path == "/rest/repository" {
			writeError(w, 403, 1, "no")
			return true
		}
		return false
	})
	res, err = testExecutor(f2, f2.instance(), &fakePusher{}).Execute(context.Background(), syncCmd(t, platformPayload(ModeFull)))
	if err != nil {
		t.Fatalf("a catalog failure failed the sync: %v", err)
	}
	if res.Metadata["catalog_warnings"] == nil {
		t.Fatal("no catalog warning")
	}
	if c, _ := res.Metadata["catalog"].(map[string]any); c["policies"] != nil {
		t.Fatal("policies listed for a sync-only instance")
	}
}

func TestConfig_AllowsScans(t *testing.T) {
	f := newFakeSC(t)
	if (&Config{Instances: []*Instance{f.instance()}}).AllowsScans() {
		t.Fatal("sync-only config allows scans")
	}
	if !(&Config{Instances: []*Instance{scanInstance(f)}}).AllowsScans() {
		t.Fatal("scan config does not allow scans")
	}
	var nilCfg *Config
	if nilCfg.AllowsScans() {
		t.Fatal("nil config")
	}
}
