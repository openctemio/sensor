package content

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/scanners/semgrep"
	"github.com/openctemio/sensor/internal/scanners/trivy"
)

type innerExec struct{ called []string }

func (i *innerExec) Execute(_ context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	i.called = append(i.called, cmd.Type)
	return &core.CommandExecutionResult{}, nil
}

func TestRefreshContentCommand(t *testing.T) {
	ok := newFake()
	bad := newFake()
	bad.name, bad.tool = core.ContentSemgrepRules, "semgrep"
	bad.resolveErr = errors.New("registry down")
	m := newTestManager(t, ok, bad)
	inner := &innerExec{}
	e := &CommandExecutor{Inner: inner, Manager: m}

	// Other commands pass through.
	if _, err := e.Execute(context.Background(), &core.Command{Type: "scan"}); err != nil || len(inner.called) != 1 {
		t.Fatalf("delegation: %v %v", inner.called, err)
	}

	payload := `{"force":true,"policy":{"refresh_interval_hours":8,"content":{"nuclei-templates":{"max_age_hours":72}}}}`
	res, err := e.Execute(context.Background(), &core.Command{Type: core.CommandTypeRefreshContent, Payload: json.RawMessage(payload)})
	if err != nil {
		t.Fatalf("partial failure failed the command: %v", err)
	}
	md := res.Metadata
	if got := md["refreshed"].([]string); len(got) != 1 || got[0] != core.ContentNucleiTemplates {
		t.Fatalf("refreshed %v", got)
	}
	if got := md["failed"].(map[string]string); !strings.Contains(got[core.ContentSemgrepRules], "registry down") {
		t.Fatalf("failed %v", got)
	}
	content := md["content"].([]core.ContentInfo)
	if len(content) != 2 || content[0].Version != "v1" {
		t.Fatalf("content %+v", content)
	}
	raw, _ := json.Marshal(md)
	if !strings.Contains(string(raw), `"content":[{"name":"nuclei-templates","version":"v1"`) {
		t.Fatalf("metadata JSON %s", raw)
	}
	if m.Policy().RefreshIntervalHours != 8 {
		t.Fatal("policy not applied")
	}

	// Everything requested failed: the command fails (with the metadata).
	res, err = e.Execute(context.Background(), &core.Command{Type: core.CommandTypeRefreshContent,
		Payload: json.RawMessage(`{"content":["semgrep-rules"]}`)})
	if err == nil || res == nil {
		t.Fatalf("all-failed refresh: %v", err)
	}

	// A malformed payload fails.
	if _, err := e.Execute(context.Background(), &core.Command{Type: core.CommandTypeRefreshContent,
		Payload: json.RawMessage(`{"content":["../x"]}`)}); !errors.Is(err, core.ErrInvalidRefreshContent) {
		t.Fatalf("bad payload: %v", err)
	}

	// Content management off.
	if _, err := (&CommandExecutor{}).Execute(context.Background(), &core.Command{Type: core.CommandTypeRefreshContent}); err == nil {
		t.Fatal("refresh without a manager succeeded")
	}
}

// recordingBinary records its arguments, one run per line, and prints out.
func recordingBinary(t *testing.T, name, out string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, name)
	log = filepath.Join(dir, "args")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\nprintf '%s' '" + out + "'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	return bin, log
}

func installFake(t *testing.T, name, tool, version string) *Manager {
	t.Helper()
	src := newFake()
	src.name, src.tool, src.version = name, tool, version
	m := newTestManager(t, src)
	if res := m.Refresh(context.Background(), nil, false); res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	return m
}

func TestWrappedTrivyUsesManagedDB(t *testing.T) {
	m := installFake(t, core.ContentTrivyDB, "trivy", "2026-10-02T01:05:41Z")
	bin, log := recordingBinary(t, "trivy", `{"Results":[]}`)
	base := trivy.NewScanner()
	base.Binary = bin
	scanner := m.WrapScanner(base)
	if scanner.Name() != "trivy" {
		t.Fatal("name changed")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := scanner.Scan(context.Background(), t.TempDir(), &core.ScanOptions{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	args, _ := os.ReadFile(log)
	h := m.Acquire(core.ContentTrivyDB)
	defer h.Release()
	for _, line := range strings.Split(strings.TrimSpace(string(args)), "\n") {
		if !strings.Contains(line, "--skip-db-update") || !strings.Contains(line, "--cache-dir "+h.Dir) {
			t.Fatalf("scan not on the managed DB: %s", line)
		}
	}
	if base.CacheDir != "" || base.SkipDBUpdate {
		t.Fatal("shared scanner modified")
	}
	if used := m.LastUsed("trivy"); len(used) != 1 || used[0].Version != "2026-10-02T01:05:41Z" {
		t.Fatalf("used %+v", used)
	}
}

func TestWrappedNucleiAndSemgrep(t *testing.T) {
	m := installFake(t, core.ContentNucleiTemplates, "nuclei", "v10.4.9")
	bin, log := recordingBinary(t, "nuclei", "")
	base := nuclei.NewScanner()
	base.Binary = bin
	w := m.WrapScanner(base)
	if _, err := w.Scan(context.Background(), "https://example.com", &core.ScanOptions{}); err != nil {
		t.Fatal(err)
	}
	multi, ok := w.(core.MultiTargetScanner)
	if !ok {
		t.Fatal("wrapped nuclei lost multi-target scans")
	}
	if _, err := multi.ScanTargets(context.Background(), []string{"https://a.example", "https://b.example"}, &core.ScanOptions{}); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(log)
	for _, line := range strings.Split(strings.TrimSpace(string(args)), "\n") {
		for _, want := range []string{"-disable-update-check", "-disable-unsigned-templates", "-t "} {
			if !strings.Contains(line, want) {
				t.Fatalf("nuclei run without %s: %s", want, line)
			}
		}
	}
	if base.TemplateDir != "" {
		t.Fatal("shared scanner modified")
	}

	// semgrep without managed rules runs unchanged (--config auto).
	ms := newTestManager(t, &SemgrepRules{Fetcher: &Fetcher{}})
	sbase := semgrep.NewScanner()
	if ws := ms.WrapScanner(sbase); ws.Name() != "semgrep" {
		t.Fatal("semgrep wrapper")
	}
	// Unknown scanners are returned as they are.
	var nilM *Manager
	if nilM.WrapScanner(base) != core.Scanner(base) {
		t.Fatal("nil manager wrapped")
	}
}

func TestDecorateAndReporter(t *testing.T) {
	m := installFake(t, core.ContentNucleiTemplates, "nuclei", "v10.4.9")
	r := &Reporter{Manager: m, Tools: []string{"nuclei", "betterleaks"}, Probe: func(_ context.Context, tool string) (string, bool) {
		return "1.0", tool == "nuclei"
	}}
	rep := r.CapabilityReport(context.Background())
	if len(rep.Tools) != 2 || rep.Capabilities != nil || rep.MaxConcurrentJobs != 0 {
		t.Fatalf("report %+v", rep)
	}
	if c := rep.Tools[0].Content; len(c) != 1 || c[0].Version != "v10.4.9" || !c[0].Managed {
		t.Fatalf("nuclei content %+v", rep.Tools[0])
	}
	if rep.Tools[1].Content != nil || rep.Tools[1].Installed {
		t.Fatalf("betterleaks %+v", rep.Tools[1])
	}
	// The heartbeat member as sent.
	st := &core.SensorStatus{}
	rep.Apply(st)
	raw, _ := json.Marshal(st.Tools)
	if !strings.Contains(string(raw), `"content":[{"name":"nuclei-templates","version":"v10.4.9"`) {
		t.Fatalf("heartbeat tools %s", raw)
	}

	// Decorate leaves a report without tools alone, and maps trivy-fs to trivy.
	if got := m.Decorate(core.CapabilityReport{}); got.Tools != nil {
		t.Fatal("decorated a report without tools")
	}
	if ToolOf("trivy-fs") != "trivy" || ToolOf("Nuclei") != "nuclei" {
		t.Fatal("ToolOf")
	}
}

type capturePusher struct {
	core.Pusher
	reports []*ctis.Report
}

func (c *capturePusher) PushFindings(_ context.Context, r *ctis.Report) (*core.PushResult, error) {
	c.reports = append(c.reports, r)
	return &core.PushResult{}, nil
}

func TestPusherStampsContent(t *testing.T) {
	m := installFake(t, core.ContentNucleiTemplates, "nuclei", "v10.4.9")
	inner := &capturePusher{}
	p := &Pusher{Pusher: inner, Manager: m}

	// No scan yet: nothing to stamp.
	r0 := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"}}
	_, _ = p.PushFindings(context.Background(), r0)
	if r0.Tool.Properties != nil {
		t.Fatal("stamped without a scan")
	}

	h := m.acquire("nuclei", core.ContentNucleiTemplates)
	h.Release()
	r := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei", Version: "3.4.1"}}
	_, _ = p.PushFindings(context.Background(), r)
	raw, _ := json.Marshal(r.Tool)
	if !strings.Contains(string(raw), `"properties":{"content":[{"name":"nuclei-templates","version":"v10.4.9"`) || !strings.Contains(string(raw), `"version":"3.4.1"`) {
		t.Fatalf("tool %s", raw)
	}
	// Other tools are not stamped.
	other := &ctis.Report{Tool: &ctis.Tool{Name: "betterleaks"}}
	_, _ = p.PushFindings(context.Background(), other)
	if other.Tool.Properties != nil {
		t.Fatal("betterleaks stamped")
	}
}

func TestSettingsFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	s, err := SettingsFromEnv(env(map[string]string{}))
	if err != nil || !s.Enabled || s.Interval != DefaultInterval || s.Keep != 1 || s.NucleiArchiveURL != DefaultNucleiArchiveURL ||
		s.NucleiChecksumsURL != DefaultNucleiChecksumsURL || s.NucleiLatestURL != DefaultNucleiLatestURL || s.Root == "" {
		t.Fatalf("defaults %+v %v", s, err)
	}
	s, err = SettingsFromEnv(env(map[string]string{
		EnvContent: "off", EnvInterval: "12h", EnvKeep: "0",
		EnvTrivyRepos: "harbor.internal/aquasec/trivy-db:2", EnvNucleiURL: "https://mirror.internal/nt-{version}.tar.gz",
		EnvSemgrepRulesets: "p/default, p/secrets",
	}))
	if err != nil || s.Enabled || s.Interval != 12*time.Hour || s.Keep != 0 || len(s.TrivyRepositories) != 1 ||
		s.NucleiLatestURL != "" || s.NucleiChecksumsURL != "" || len(s.SemgrepRulesets) != 2 {
		t.Fatalf("custom %+v %v", s, err)
	}
	for k, v := range map[string]string{
		EnvContent: "maybe", EnvInterval: "1m", EnvKeep: "x", EnvTrivyRepos: "not a ref", EnvNucleiSHA256: "abc", EnvNucleiMin: "0",
	} {
		if _, err := SettingsFromEnv(env(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	if m, err := NewFromSettings(Settings{Enabled: false}, Tools{Trivy: true}, false); m != nil || err != nil {
		t.Fatal("disabled settings built a manager")
	}
	m, err := NewFromSettings(Settings{Enabled: true, Root: t.TempDir(), Interval: time.Hour}, Tools{Trivy: true, Nuclei: true, Semgrep: true}, false)
	if err != nil || len(m.Names()) != 3 {
		t.Fatalf("%v %v", m, err)
	}
}
