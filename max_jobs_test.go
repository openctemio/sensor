package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/resource"
)

func TestResolveMaxJobs(t *testing.T) {
	cases := []struct {
		name    string
		flagSet bool
		flagVal int
		env     string
		cfg     int
		want    int
		wantErr bool
	}{
		{name: "default: no cap", want: 0},
		{name: "config", cfg: 8, want: 8},
		{name: "env over config", env: "3", cfg: 8, want: 3},
		{name: "flag over env", flagSet: true, flagVal: 12, env: "3", cfg: 8, want: 12},
		{name: "flag default value not set: env wins", flagVal: 5, env: "2", want: 2},
		{name: "env not a number", env: "lots", wantErr: true},
		{name: "env zero", env: "0", wantErr: true},
		{name: "flag above limit", flagSet: true, flagVal: 101, wantErr: true},
		{name: "config negative", cfg: -1, wantErr: true},
		{name: "upper bound", env: "100", want: 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveMaxJobs(c.flagSet, c.flagVal, c.env, c.cfg)
			if (err != nil) != c.wantErr || got != c.want {
				t.Fatalf("resolveMaxJobs = %d, %v; want %d (error %v)", got, err, c.want, c.wantErr)
			}
		})
	}
}

func TestCanonicalToolName(t *testing.T) {
	for in, want := range map[string]string{"trivy-fs": "trivy", "Semgrep": "semgrep", "betterleaks": "betterleaks", " nuclei ": "nuclei"} {
		if got := canonicalToolName(in); got != want {
			t.Errorf("canonicalToolName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveStateDir(t *testing.T) {
	t.Setenv(envStateDir, "")
	if got := resolveStateDir(outboxPlan{Config: client.OutboxConfig{Dir: "/var/lib/openctem/outbox"}}); got != "/var/lib/openctem" {
		t.Fatalf("from outbox: %q", got)
	}
	t.Setenv(envStateDir, "/data/state")
	if got := resolveStateDir(outboxPlan{}); got != "/data/state" {
		t.Fatalf("from env: %q", got)
	}
}

// On this machine: the daemon's resource manager probes real resources,
// gives at least one slot, never more than the cap, and persists the cost
// history in the state dir.
func TestNewResourceManager_RealHost(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{Scanners: []ScannerConfig{{Name: "trivy-fs", Enabled: true}, {Name: "nuclei", Enabled: true}}}
	cfg.Sensor.MaxJobs = 3
	m := newResourceManager(cfg, dir, nil)
	if m.MaxSlots() != 3 {
		t.Fatalf("cap %d", m.MaxSlots())
	}
	if s := m.Slots(0); s < 1 || s > 3 {
		t.Fatalf("slots %d", s)
	}
	res, capacity := m.Snapshot(0)
	if res.CPUCores <= 0 || capacity.PerTool["trivy"].MemBytes == 0 || capacity.PerTool["nuclei"].MemBytes == 0 {
		t.Fatalf("snapshot %+v %+v", res, capacity)
	}
	m.Observe(resource.JobSample{Tool: "trivy", Targets: 1, Wall: time.Second})
	if _, err := os.Stat(filepath.Join(dir, "tool-costs.json")); err != nil {
		t.Fatal(err)
	}
}

func TestResolveDrainGrace(t *testing.T) {
	cases := map[string]struct {
		want    time.Duration
		wantErr bool
	}{
		"":      {want: 30 * time.Second},
		"45s":   {want: 45 * time.Second},
		" 2m ":  {want: 2 * time.Minute},
		"500ms": {wantErr: true},
		"2h":    {wantErr: true},
		"lots":  {wantErr: true},
		"-5s":   {wantErr: true},
	}
	for in, c := range cases {
		got, err := resolveDrainGrace(in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("resolveDrainGrace(%q) = %v, %v; want %v (error %v)", in, got, err, c.want, c.wantErr)
		}
	}
}
