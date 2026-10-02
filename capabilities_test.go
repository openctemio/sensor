package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
)

func fakeProbe(name string, installed bool, version string, err error, caps ...string) toolProbe {
	return toolProbe{name: name, caps: caps, check: func(context.Context) (bool, string, error) {
		return installed, version, err
	}}
}

func TestCapabilityReporter_Report(t *testing.T) {
	r := &capabilityReporter{
		probes: []toolProbe{
			fakeProbe("semgrep", true, "1.90.0", nil, "sast"),
			fakeProbe("nuclei", true, "v3.3.0", nil, "dast"),
			fakeProbe("trivy", false, "", nil, "sca"),
			fakeProbe("betterleaks", true, "1.0", errors.New("broken"), "secrets"), // installed but failing
		},
		validate: true, maxJobs: 3, ttl: time.Minute, now: time.Now,
	}
	got := r.CapabilityReport(context.Background())
	wantTools := []core.ToolInfo{
		{Name: "semgrep", Version: "1.90.0", Installed: true},
		{Name: "nuclei", Version: "v3.3.0", Installed: true},
		{Name: "trivy", Installed: false},
		{Name: "betterleaks", Installed: false},
	}
	if !reflect.DeepEqual(got.Tools, wantTools) {
		t.Errorf("tools = %+v", got.Tools)
	}
	if want := []string{"semgrep", "sast", "nuclei", "dast", "validate:nuclei", "validate"}; !reflect.DeepEqual(got.Capabilities, want) {
		t.Errorf("capabilities = %v, want %v", got.Capabilities, want)
	}
	if got.MaxConcurrentJobs != 3 {
		t.Errorf("max jobs = %d", got.MaxConcurrentJobs)
	}
}

// Without command polling the daemon serves no validation; with nothing
// installed it reports an empty inventory, not "nothing reported".
func TestCapabilityReporter_NoCommandsNoTools(t *testing.T) {
	r := &capabilityReporter{probes: []toolProbe{fakeProbe("nuclei", false, "", nil, "dast")},
		maxJobs: 5, ttl: time.Minute, now: time.Now}
	got := r.CapabilityReport(context.Background())
	if got.Capabilities == nil || len(got.Capabilities) != 0 {
		t.Errorf("capabilities = %#v, want []", got.Capabilities)
	}
	empty := (&capabilityReporter{maxJobs: 5, ttl: time.Minute, now: time.Now}).CapabilityReport(context.Background())
	if empty.Tools == nil || len(empty.Tools) != 0 {
		t.Errorf("tools = %#v, want [] (reported: nothing installed)", empty.Tools)
	}
}

// Tools are probed at most once per TTL: probing runs each tool's version
// check, too slow for every heartbeat.
func TestCapabilityReporter_CachesProbes(t *testing.T) {
	calls := 0
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	r := &capabilityReporter{
		probes: []toolProbe{{name: "nuclei", check: func(context.Context) (bool, string, error) {
			calls++
			return calls > 1, "v3", nil // installed from the second probe on
		}}},
		ttl: 10 * time.Minute, now: func() time.Time { return now },
	}
	ctx := context.Background()
	r.CapabilityReport(ctx)
	r.CapabilityReport(ctx)
	if calls != 1 {
		t.Fatalf("probed %d times within the TTL", calls)
	}
	now = now.Add(11 * time.Minute)
	if got := r.CapabilityReport(ctx); calls != 2 || !got.Tools[0].Installed {
		t.Fatalf("not re-probed after the TTL: calls=%d tools=%+v", calls, got.Tools)
	}
}

func TestNewCapabilityReporter_FromConfig(t *testing.T) {
	cfg := &Config{}
	cfg.Sensor.EnableCommands = true
	cfg.Scanners = []ScannerConfig{
		{Name: "semgrep", Enabled: true},
		{Name: "trivy-fs", Enabled: true},
		{Name: "trivy-image", Enabled: true}, // same tool: one entry, both capabilities
		{Name: "nuclei", Enabled: false},     // disabled: not reported
		{Name: "no-such-scanner", Enabled: true},
		{Name: "gitleaks", Enabled: true}, // retired name: runs betterleaks
	}
	cfg.Sensor.MaxJobs = 4
	r := newCapabilityReporter(cfg, nil)
	var names []string
	var trivyCaps []string
	for _, p := range r.probes {
		names = append(names, p.name)
		if p.name == "trivy" {
			trivyCaps = p.caps
		}
	}
	if want := []string{"semgrep", "trivy", "betterleaks"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("probes = %v, want %v", names, want)
	}
	if want := []string{"sca", "container"}; !reflect.DeepEqual(trivyCaps, want) {
		t.Fatalf("trivy capabilities = %v, want %v", trivyCaps, want)
	}
	if !r.validate || r.maxJobs != 4 {
		t.Fatalf("validate=%v maxJobs=%d", r.validate, r.maxJobs)
	}
}

// End to end through the SDK: the daemon's heartbeat carries the report.
func TestCapabilityReporter_HeartbeatCarriesReport(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
	t.Cleanup(func() { _ = c.Close() })
	s := core.NewBaseSensor(&core.BaseSensorConfig{Name: "caps"}, c)
	s.SetCapabilityReporter(&capabilityReporter{
		probes:   []toolProbe{fakeProbe("nuclei", true, "v3.3.0", nil, "dast")},
		validate: true, maxJobs: 2, ttl: time.Minute, now: time.Now,
	})
	if _, err := s.FirstHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	beats := f.Heartbeats()
	if len(beats) == 0 {
		t.Fatal("no heartbeat")
	}
	var hb struct {
		Tools             []core.ToolInfo `json:"tools"`
		Capabilities      []string        `json:"capabilities"`
		MaxConcurrentJobs int             `json:"max_concurrent_jobs"`
		OS, Arch          string
	}
	if err := json.Unmarshal(beats[len(beats)-1], &hb); err != nil {
		t.Fatal(err)
	}
	if len(hb.Tools) != 1 || hb.Tools[0].Name != "nuclei" || !hb.Tools[0].Installed || hb.MaxConcurrentJobs != 2 ||
		!reflect.DeepEqual(hb.Capabilities, []string{"nuclei", "dast", "validate:nuclei", "validate"}) || hb.OS == "" {
		t.Fatalf("heartbeat = %+v", hb)
	}
}

// Scanner content is added to the cached inventory on every heartbeat.
func TestCapabilityReporter_DecoratesEveryHeartbeat(t *testing.T) {
	n := 0
	r := &capabilityReporter{
		probes: []toolProbe{fakeProbe("trivy", true, "0.68.2", nil, "sca")},
		decorate: func(rep core.CapabilityReport) core.CapabilityReport {
			n++
			return rep
		},
		ttl: time.Hour, now: time.Now,
	}
	r.CapabilityReport(context.Background())
	r.CapabilityReport(context.Background())
	if n != 2 {
		t.Fatalf("decorated %d times, want 2", n)
	}
}
