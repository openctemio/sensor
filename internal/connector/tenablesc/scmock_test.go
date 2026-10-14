package tenablesc

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/openctemio/sensor/internal/connector/tenablesc/scmock"
)

// The connector against the documented-shape mock (scmock): one batch end to
// end, the licence refusing a second one, and a restart that follows the
// scan it already launched.

func newMockEstate(t *testing.T, licensed int) (*scmock.Server, *ScanExecutor, *fakePusher) {
	t.Helper()
	vuln := func(id string, sev int) scmock.Vuln {
		return scmock.Vuln{PluginID: id, Name: "Plugin " + id, Severity: sev, Port: 443, Protocol: "TCP", CVE: "CVE-2024-0001", CVSSV3: 7.5}
	}
	mock := scmock.New(scmock.Options{
		AccessKey: testAccessKey, SecretKey: testSecretKey, LicensedIPs: licensed,
		Repositories: []scmock.Named{{ID: 5, Name: "openctem-rotation"}, {ID: 7, Name: "Other team"}},
		Policies:     []scmock.Named{{ID: 1000003, Name: "Basic network scan"}},
		Zones:        []scmock.Named{{ID: 2, Name: "DC"}},
		Hosts: []scmock.Host{
			{IP: "10.30.0.1", DNSName: "db01.corp.example", Alive: true, Vulns: []scmock.Vuln{vuln("150000", 3)}},
			{IP: "10.30.0.2", Alive: true, Vulns: []scmock.Vuln{vuln("150001", 2)}},
			{IP: "10.30.0.3", Alive: true}, // live, only the scan-information plugin: does not count
			{IP: "10.30.0.4", Alive: false},
			{IP: "10.30.1.1", Alive: true, Vulns: []scmock.Vuln{vuln("150002", 4)}},
			{IP: "10.30.1.2", Alive: true, Vulns: []scmock.Vuln{vuln("150003", 1)}},
		},
	})
	srv := httptest.NewTLSServer(mock.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	inst := &Instance{
		Name: "sc-test", URL: u, CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}),
		AccessKey: Secret{testAccessKey}, SecretKey: Secret{testSecretKey},
		Allow: Allow{
			Operations: map[string]bool{OperationSync: true, OperationScan: true}, Repositories: []int{5},
			ScanPolicies: []int{1000003}, ScanRepositories: []int{5}, ScanZones: []int{2},
			MaxTargetsPerScan: 256, MaxScanSeconds: 3600,
		},
		Limits: Limits{PageSize: 50, MaxRecords: 1000, MaxResponseBytes: 1 << 20, RequestsPerSecond: 1000},
	}
	p := &fakePusher{}
	clock := testNow
	e := NewScanExecutor(&Config{Instances: []*Instance{inst}}, p, nil)
	e.now = func() time.Time { return clock }
	e.newClient = func(in *Instance) (*Client, error) { return newClient(in, testClientOptions(nil)) }
	e.pollInterval = time.Second
	e.sleep = func(ctx context.Context, d time.Duration) error { clock = clock.Add(d); return ctx.Err() }
	return mock, e, p
}

func mockPayload(id string, targets ...string) map[string]any {
	return map[string]any{
		"scanner": "tenable_sc", "instance": "sc-test", "targets": targets, "policy_id": 1000003,
		"repository_id": 5, "zone_id": 2, "max_scan_seconds": 1800, "min_severity": 1,
		"run_id": "r-" + id, "step_key": "scan",
	}
}

func TestMock_OneBatchEndToEnd(t *testing.T) {
	mock, e, p := newMockEstate(t, 3)
	cmd := scanCmd(t, mockPayload("1", "10.30.0.0/30", "db01.corp.example", "10.30.0.4"))
	res, err := e.Execute(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	got := outcomeStates(res)
	if got["10.30.0.0/30"] != "done:" || got["db01.corp.example"] != "done:" || got["10.30.0.4"] != "failed:unreachable" {
		t.Fatalf("outcomes %v", got)
	}
	if res.Metadata["coverage"] != CoverageFull || res.Metadata["total_ips"] != int64(4) || res.Metadata["definition_deleted"] != true {
		t.Fatalf("metadata %v", res.Metadata)
	}
	findings, assets := 0, map[string]bool{}
	for _, r := range p.reports {
		findings += len(r.Findings)
		for _, a := range r.Assets {
			assets[a.Value] = true
		}
	}
	// 10.30.0.1 (high) and 10.30.0.2 (medium); 10.30.0.3 has only info.
	if findings != 2 || !assets["db01.corp.example"] || !assets["10.30.0.3"] {
		t.Fatalf("findings %d assets %v", findings, assets)
	}
	// Two hosts with real findings count; the info-only host does not.
	if n := mock.ActiveIPs(); n != 2 {
		t.Fatalf("active IPs %d, want 2", n)
	}
}

func TestMock_LicenceBlocksTheNextBatch(t *testing.T) {
	_, e, p := newMockEstate(t, 3)
	if _, err := e.Execute(context.Background(), scanCmd(t, mockPayload("1", "10.30.0.0/30"))); err != nil {
		t.Fatal(err)
	}
	pushed := len(p.reports)
	cmd := scanCmd(t, mockPayload("2", "10.30.1.0/30"))
	cmd.ID = "cmd-scan-2"
	_, err := e.Execute(context.Background(), cmd)
	if !errors.Is(err, ErrImportRefused) {
		t.Fatalf("err %v, want the licence refusal", err)
	}
	if len(p.reports) != pushed {
		t.Fatal("a blocked batch pushed reports")
	}
}

func TestMock_RestartFollowsTheLaunchedScan(t *testing.T) {
	_, e, _ := newMockEstate(t, 10)
	// The sensor created and launched the scan, then restarted.
	c, err := newClient(e.Config.Instances[0], testClientOptions(nil))
	if err != nil {
		t.Fatal(err)
	}
	def, err := c.CreateScan(context.Background(), ScanSpec{Name: "openctem-cmd-scan-1", PolicyID: 1000003, RepositoryID: 5, Targets: []string{"10.30.0.1"}, MaxScanTime: 600})
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.LaunchScan(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Execute(context.Background(), scanCmd(t, mockPayload("1", "10.30.0.1")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata["resumed"] != true || res.Metadata["scan_result_id"] != first || res.Metadata["definition_deleted"] != true {
		t.Fatalf("metadata %v: want the first scan result %s followed and its definition deleted", res.Metadata, first)
	}
	left, err := c.FindScans(context.Background(), "openctem-cmd-scan-1")
	if err != nil || len(left) != 0 {
		t.Fatalf("definitions left %v err %v", left, err)
	}
}
