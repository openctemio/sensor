package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
)

// registryWith returns a tool registry holding the given fake tools.
func registryWith(t *testing.T, specs ...core.ToolSpec) *core.ToolRegistry {
	t.Helper()
	reg := core.NewToolRegistry()
	for _, s := range specs {
		if err := reg.Register(s); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func fakeTool(name string, installed bool, version string, err error, caps ...string) core.ToolSpec {
	return core.ToolSpec{Name: name, Capabilities: caps, Probe: func(context.Context) (bool, string, error) {
		return installed, version, err
	}}
}

func TestCapabilityReporter_Report(t *testing.T) {
	reg := registryWith(t,
		fakeTool("semgrep", true, "1.90.0", nil, "sast"),
		fakeTool("nuclei", true, "v3.3.0", nil, "dast", "validate:nuclei"),
		fakeTool("trivy", false, "", nil, "sca"),
		fakeTool("betterleaks", true, "1.0", errors.New("broken"), "secrets"), // installed but failing
	)
	reg.AddCapabilities("validate")
	reg.SetMaxConcurrentJobs(3)
	got := (&capabilityReporter{tools: reg}).CapabilityReport(context.Background())
	wantTools := []core.ToolInfo{
		{Name: "semgrep", Kind: core.ToolKindScanner, Version: "1.90.0", Installed: true},
		{Name: "nuclei", Kind: core.ToolKindScanner, Version: "v3.3.0", Installed: true},
		{Name: "trivy", Kind: core.ToolKindScanner, Installed: false},
		{Name: "betterleaks", Kind: core.ToolKindScanner, Installed: false},
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
// installed, or no scanner at all, it reports an empty inventory, not
// "nothing reported".
func TestCapabilityReporter_NoCommandsNoTools(t *testing.T) {
	got := (&capabilityReporter{tools: registryWith(t, fakeTool("nuclei", false, "", nil, "dast"))}).CapabilityReport(context.Background())
	if got.Capabilities == nil || len(got.Capabilities) != 0 {
		t.Errorf("capabilities = %#v, want []", got.Capabilities)
	}
	empty := (&capabilityReporter{tools: core.NewToolRegistry()}).CapabilityReport(context.Background())
	if empty.Tools == nil || len(empty.Tools) != 0 || empty.Capabilities == nil {
		t.Errorf("report = %#v, want [] (reported: nothing installed)", empty)
	}
}

// Tools are probed at most once per TTL: probing runs each tool's version
// check, too slow for every heartbeat.
func TestCapabilityReporter_CachesProbes(t *testing.T) {
	calls := 0
	cfg := &Config{}
	reg := core.NewToolRegistry()
	r := newCapabilityReporter(cfg, reg, nil)
	if err := reg.Register(core.ToolSpec{Name: "nuclei", Probe: func(context.Context) (bool, string, error) {
		calls++
		return true, "v3", nil
	}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r.CapabilityReport(ctx)
	r.CapabilityReport(ctx)
	if calls != 1 {
		t.Fatalf("probed %d times within the TTL (%s)", calls, inventoryTTL)
	}
	reg.Refresh()
	if r.CapabilityReport(ctx); calls != 2 {
		t.Fatalf("not re-probed after a refresh: calls=%d", calls)
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
	reg := core.NewToolRegistry()
	newCapabilityReporter(cfg, reg, nil)
	if want := []string{"semgrep", "trivy", "betterleaks"}; !reflect.DeepEqual(reg.Names(), want) {
		t.Fatalf("registered = %v, want %v", reg.Names(), want)
	}
}

// installedScanner is a scanner that is always installed.
type installedScanner struct {
	name string
	caps []string
}

func (s installedScanner) Name() string           { return s.name }
func (s installedScanner) Version() string        { return "" }
func (s installedScanner) Capabilities() []string { return s.caps }
func (s installedScanner) Scan(context.Context, string, *core.ScanOptions) (*core.ScanResult, error) {
	return &core.ScanResult{}, nil
}
func (s installedScanner) IsInstalled(context.Context) (bool, string, error) { return true, "1.0", nil }

// The trivy modes merge into one tool serving both capabilities, a daemon
// that runs commands serves validation (through nuclei, and in general), and
// the operator's cap is reported.
func TestRegisterTools_Capabilities(t *testing.T) {
	factory := func(sc ScannerConfig, _ bool) (core.Scanner, error) {
		switch sc.Name {
		case "trivy-fs", "trivy-image":
			return installedScanner{name: "trivy", caps: []string{"vulnerability", "sca"}}, nil
		case "nuclei":
			return installedScanner{name: "nuclei", caps: []string{"dast", "vulnerability_scanning"}}, nil
		}
		return nil, errors.New("unknown")
	}
	cfg := &Config{}
	cfg.Sensor.EnableCommands = true
	cfg.Sensor.MaxJobs = 4
	cfg.Scanners = []ScannerConfig{{Name: "trivy-fs", Enabled: true}, {Name: "trivy-image", Enabled: true}, {Name: "nuclei", Enabled: true}, {Name: "bogus", Enabled: true}}
	reg := core.NewToolRegistry()
	registerTools(cfg, reg, factory)
	rep := reg.CapabilityReport(context.Background())
	if want := []string{"trivy", "sca", "container", "nuclei", "dast", "validate:nuclei", "validate"}; !reflect.DeepEqual(rep.Capabilities, want) {
		t.Fatalf("capabilities = %v, want %v", rep.Capabilities, want)
	}
	if rep.MaxConcurrentJobs != 4 || len(rep.Tools) != 2 {
		t.Fatalf("report = %+v", rep)
	}

	// Without command polling: no validation.
	cfg.Sensor.EnableCommands = false
	reg = core.NewToolRegistry()
	registerTools(cfg, reg, factory)
	rep = reg.CapabilityReport(context.Background())
	if slices.Contains(rep.Capabilities, "validate") || slices.Contains(rep.Capabilities, "validate:nuclei") {
		t.Fatalf("capabilities = %v", rep.Capabilities)
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
	reg := registryWith(t, fakeTool("nuclei", true, "v3.3.0", nil, "dast", "validate:nuclei"))
	reg.AddCapabilities("validate")
	reg.SetMaxConcurrentJobs(2)
	s.SetCapabilityReporter(&capabilityReporter{tools: reg})
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
		tools: registryWith(t, fakeTool("trivy", true, "0.68.2", nil, "sca")),
		decorate: func(rep core.CapabilityReport) core.CapabilityReport {
			n++
			return rep
		},
	}
	r.CapabilityReport(context.Background())
	r.CapabilityReport(context.Background())
	if n != 2 {
		t.Fatalf("decorated %d times, want 2", n)
	}
}
