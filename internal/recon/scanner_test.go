package recon

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

type fakeRecon struct {
	name    string
	typ     core.ReconType
	results map[string]*core.ReconResult
	err     error
	seen    []string
}

func (f *fakeRecon) Name() string         { return f.name }
func (f *fakeRecon) Version() string      { return "1.0.0" }
func (f *fakeRecon) Type() core.ReconType { return f.typ }
func (f *fakeRecon) IsInstalled(context.Context) (bool, string, error) {
	return true, "1.0.0", nil
}
func (f *fakeRecon) Scan(_ context.Context, target string, _ *core.ReconOptions) (*core.ReconResult, error) {
	f.seen = append(f.seen, target)
	if f.err != nil {
		return nil, f.err
	}
	if r, ok := f.results[target]; ok {
		return r, nil
	}
	return &core.ReconResult{ScannerName: f.name, ReconType: f.typ, Target: target}, nil
}

func parse(t *testing.T, raw []byte) *ctis.Report {
	t.Helper()
	p := &core.JSONParser{}
	if !p.CanParse(raw) {
		t.Fatalf("the generic CTIS parser does not accept the output: %s", raw)
	}
	r, err := p.Parse(context.Background(), raw, &core.ParseOptions{ToolName: "subfinder"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScanTargets_SubdomainsBecomeAssets(t *testing.T) {
	f := &fakeRecon{name: "subfinder", typ: core.ReconTypeSubdomain, results: map[string]*core.ReconResult{
		"example.com": {Subdomains: []core.Subdomain{{Host: "api.example.com", Domain: "example.com", Source: "crtsh"}}},
		"example.org": {Subdomains: []core.Subdomain{{Host: "www.example.org", Domain: "example.org"}}},
	}}
	s := NewScanner(f)
	res, err := s.ScanTargets(context.Background(), []string{"example.com", "example.org"}, &core.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.seen, []string{"example.com", "example.org"}) {
		t.Fatalf("targets run: %v", f.seen)
	}
	r := parse(t, res.RawOutput)
	got := map[string]ctis.AssetType{}
	for _, a := range r.Assets {
		got[a.Value] = a.Type
	}
	if got["api.example.com"] != ctis.AssetTypeSubdomain || got["www.example.org"] != ctis.AssetTypeSubdomain {
		t.Fatalf("assets = %v", got)
	}
	if r.Tool == nil || r.Tool.Name != "subfinder" {
		t.Fatalf("tool = %+v", r.Tool)
	}
}

func TestScanTargets_OpenPortsBecomeServices(t *testing.T) {
	f := &fakeRecon{name: "naabu", typ: core.ReconTypePort, results: map[string]*core.ReconResult{
		"192.0.2.10": {OpenPorts: []core.OpenPort{{Host: "192.0.2.10", IP: "192.0.2.10", Port: 443, Protocol: "tcp"}}},
	}}
	res, err := NewScanner(f).Scan(context.Background(), "192.0.2.10", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := parse(t, res.RawOutput); len(r.Assets) == 0 {
		t.Fatalf("no assets from an open port: %s", res.RawOutput)
	}
}

// A tool run that fails must fail the job: reporting 0 assets would make a
// broken tool look like an empty attack surface.
func TestScanTargets_ToolErrorFailsTheJob(t *testing.T) {
	f := &fakeRecon{name: "dnsx", typ: core.ReconTypeDNS, results: map[string]*core.ReconResult{
		"example.com": {Error: "exit status 1: missing wordlist"},
	}}
	if _, err := NewScanner(f).Scan(context.Background(), "example.com", nil); !errors.Is(err, ErrToolFailed) {
		t.Fatalf("err = %v, want ErrToolFailed", err)
	}
	// "flag provided but not defined" exits 2 with no Error set.
	f = &fakeRecon{name: "dnsx", typ: core.ReconTypeDNS, results: map[string]*core.ReconResult{
		"example.com": {ExitCode: 2},
	}}
	if _, err := NewScanner(f).Scan(context.Background(), "example.com", nil); !errors.Is(err, ErrToolFailed) {
		t.Fatalf("exit 2: err = %v, want ErrToolFailed", err)
	}
	f = &fakeRecon{name: "dnsx", typ: core.ReconTypeDNS, err: errors.New("boom")}
	if _, err := NewScanner(f).Scan(context.Background(), "example.com", nil); !errors.Is(err, ErrToolFailed) {
		t.Fatalf("err = %v, want ErrToolFailed", err)
	}
}

// One target that fails (a host that does not resolve) does not discard the
// other targets' results; it is listed in the report.
func TestScanTargets_PartialFailureKeepsResults(t *testing.T) {
	f := &fakeRecon{name: "naabu", typ: core.ReconTypePort, results: map[string]*core.ReconResult{
		"192.0.2.10":       {OpenPorts: []core.OpenPort{{Host: "192.0.2.10", IP: "192.0.2.10", Port: 443, Protocol: "tcp"}}},
		"gone.example.com": {ExitCode: 1},
	}}
	res, err := NewScanner(f).ScanTargets(context.Background(), []string{"gone.example.com", "192.0.2.10"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := parse(t, res.RawOutput)
	if len(r.Assets) == 0 {
		t.Fatal("results of the working target were dropped")
	}
	failed, ok := r.Properties["failed_targets"].([]any)
	if !ok || len(failed) != 1 {
		t.Fatalf("failed_targets = %#v", r.Properties["failed_targets"])
	}

	f.results["192.0.2.10"] = &core.ReconResult{ExitCode: 2}
	if _, err := NewScanner(f).ScanTargets(context.Background(), []string{"gone.example.com", "192.0.2.10"}, nil); !errors.Is(err, ErrToolFailed) {
		t.Fatalf("every target failed: err = %v, want ErrToolFailed", err)
	}
}

// The capabilities are the platform tool catalog's names for each tool, so
// a job that requires them is offered to the sensor.
func TestCapabilities_MatchThePlatformCatalog(t *testing.T) {
	want := map[string][]string{
		"subfinder": {"recon", "subdomain"},
		"dnsx":      {"recon", "dns"},
		"naabu":     {"recon", "portscan"},
		"httpx":     {"recon", "http", "tech_detect"},
		"katana":    {"recon", "crawler", "url_discovery"},
	}
	for _, name := range Tools {
		s, err := New(name)
		if err != nil {
			t.Fatal(err)
		}
		if s.Name() != name {
			t.Errorf("New(%q).Name() = %q", name, s.Name())
		}
		if !slices.Equal(s.Capabilities(), want[name]) {
			t.Errorf("%s capabilities = %v, want %v", name, s.Capabilities(), want[name])
		}
		if !IsTool(name) {
			t.Errorf("IsTool(%q) = false", name)
		}
	}
	if _, err := New("amass"); err == nil {
		t.Error("New(amass) did not fail")
	}
	if IsTool("nuclei") {
		t.Error("IsTool(nuclei) = true")
	}
}

// optsRecon records the options each run got.
type optsRecon struct {
	fakeRecon
	opts []core.ReconOptions
}

func (f *optsRecon) Scan(ctx context.Context, target string, o *core.ReconOptions) (*core.ReconResult, error) {
	f.opts = append(f.opts, *o)
	return f.fakeRecon.Scan(ctx, target, o)
}

// Research/22c B5: dnsx, naabu and subfinder resolve through the sensor's
// resolvers (SENSOR_DNS_RESOLVERS, else /etc/resolv.conf), never their
// built-in public lists; httpx and katana are left alone (they use the
// system resolver already). An invalid operator list fails the job.
func TestScanTargets_ToolsUseTheSensorResolvers(t *testing.T) {
	old := sensorResolvers
	t.Cleanup(func() { sensorResolvers = old })
	sensorResolvers = func(func(string) (string, bool)) ([]string, error) { return []string{"10.53.0.1"}, nil }

	for _, tool := range []string{"dnsx", "naabu", "subfinder", "httpx", "katana"} {
		f := &optsRecon{fakeRecon: fakeRecon{name: tool, typ: core.ReconTypeDNS}}
		if _, err := NewScanner(f).ScanTargets(t.Context(), []string{"a.example.com", "b.example.com"}, nil); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		for _, o := range f.opts {
			want := slices.Contains(resolvingTools, tool)
			if got := slices.Equal(o.Resolvers, []string{"10.53.0.1"}); got != want {
				t.Errorf("%s: resolvers %q (want sensor resolvers: %v)", tool, o.Resolvers, want)
			}
		}
	}

	// Resolvers set on the scanner are kept.
	f := &optsRecon{fakeRecon: fakeRecon{name: "dnsx", typ: core.ReconTypeDNS}}
	s := NewScanner(f)
	s.Options.Resolvers = []string{"192.0.2.53"}
	if _, err := s.ScanTargets(t.Context(), []string{"a.example.com"}, nil); err != nil || !slices.Equal(f.opts[0].Resolvers, []string{"192.0.2.53"}) {
		t.Errorf("scanner resolvers replaced: %q %v", f.opts[0].Resolvers, err)
	}

	sensorResolvers = func(func(string) (string, bool)) ([]string, error) {
		return nil, errors.New("SENSOR_DNS_RESOLVERS: bad")
	}
	f = &optsRecon{fakeRecon: fakeRecon{name: "naabu", typ: core.ReconTypePort}}
	if _, err := NewScanner(f).ScanTargets(t.Context(), []string{"a.example.com"}, nil); err == nil || len(f.opts) != 0 {
		t.Errorf("invalid resolver list: err %v, runs %d (want a failure before any run)", err, len(f.opts))
	}
}
