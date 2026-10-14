package executor

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/core"
)

// Scan targets come from asset data, i.e. from ingest, so they are
// attacker-influenceable. The sensor checks them in the SDK executor with its
// own policy (ScanTargetPolicy): one target at a time, so a refused target is
// left out and the scan runs on the rest.
//
// These tests run the SDK executor with the policy main builds, so a change
// to either side that weakens the answer fails here.

// recordingScanner is a list-capable scanner that records the targets it ran
// on. A refused target reaching it IS the vulnerability.
type recordingScanner struct {
	name string
	mu   sync.Mutex
	ran  []string
}

func (s *recordingScanner) Name() string           { return s.name }
func (s *recordingScanner) Version() string        { return "1" }
func (s *recordingScanner) Capabilities() []string { return nil }
func (s *recordingScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "1", nil
}
func (s *recordingScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}
func (s *recordingScanner) ScanTargets(_ context.Context, targets []string, _ *core.ScanOptions) (*core.ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ran = append([]string(nil), targets...)
	return &core.ScanResult{ScannerName: s.name}, nil
}
func (s *recordingScanner) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ran
}
func (s *recordingScanner) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ran = nil
}

func scanCmd(t *testing.T, payload map[string]any) *core.Command {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return &core.Command{ID: "c1", Type: "scan", Payload: b}
}

// guardedExecutor is the SDK executor with the sensor's policy and one
// network scanner.
func guardedExecutor(scanner string) (*core.DefaultCommandExecutor, *recordingScanner) {
	sc := &recordingScanner{name: scanner}
	e := core.NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(ScanTargetPolicy(nil))
	return e, sc
}

// The hard-blocked tier. No configuration opens these.
func TestScanGuard_BlocksHardBlockedTargets(t *testing.T) {
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/", "169.254.169.254", "169.254.169.254:80",
		"http://127.0.0.1:8080", "127.0.0.1:80", "[::1]:443", "localhost", "localhost:8080",
		"100.64.0.1", "metadata.google.internal",
	} {
		t.Run(target, func(t *testing.T) {
			e, sc := guardedExecutor("nuclei")
			_, err := e.Execute(context.Background(), scanCmd(t, map[string]any{"scanner": "nuclei", "target": target}))
			if err == nil {
				t.Fatal("no error returned; the job would be reported as a success")
			}
			if sc.got() != nil {
				t.Fatalf("SECURITY: the scanner ran on %v", sc.got())
			}
		})
	}
}

// The guard must not break ordinary scanning. IP literals, so the test does
// not depend on DNS. host:port is what a port scan hands the HTTP probe (the
// 2026-10-14 live failure: "DNS lookup failed for scanner target
// \"104.17.85.188:80\"").
func TestScanGuard_AllowsOrdinaryTargets(t *testing.T) {
	for _, target := range []string{
		"93.184.216.34", "https://93.184.216.34/app", "104.17.85.188:80", "[2606:4700::6811:55bc]:443",
	} {
		t.Run(target, func(t *testing.T) {
			e, sc := guardedExecutor("httpx")
			if _, err := e.Execute(context.Background(), scanCmd(t, map[string]any{"scanner": "httpx", "target": target})); err != nil {
				t.Fatalf("ordinary scan refused: %v", err)
			}
			if !slices.Equal(sc.got(), []string{target}) {
				t.Fatalf("scanner ran on %v", sc.got())
			}
		})
	}
}

// One refused target fails only that target: the good ones run, each
// refused one is listed with its reason and the guard rule and settled
// skipped/refused (so the platform does not hand it out again).
func TestScanGuard_RefusesPerTarget(t *testing.T) {
	good := []string{"104.17.85.188:80", "8.8.8.8:443"}
	bad := []string{"127.0.0.1:80", "nothing.invalid:443", "169.254.169.254", "http://169.254.169.254/latest/"}
	e, sc := guardedExecutor("httpx")
	res, err := e.Execute(context.Background(), scanCmd(t, map[string]any{"scanner": "httpx", "targets": append(slices.Clone(good), bad...)}))
	if err != nil {
		t.Fatalf("one refused target failed the whole task: %v", err)
	}
	if !slices.Equal(sc.got(), good) {
		t.Fatalf("scanner ran on %v; want only %v", sc.got(), good)
	}
	listed, _ := res.Metadata[core.MetaRefusedTargets].([]core.RefusedTarget)
	if len(listed) != len(bad) || res.Metadata[core.MetaPartial] != true {
		t.Fatalf("refused targets in the result: %+v", res.Metadata)
	}
	for i, r := range listed {
		if r.Target != bad[i] || r.Rule != core.RefusedTargetRuleGuard || r.Reason == "" {
			t.Errorf("refused[%d] = %+v", i, r)
		}
	}
	if listed[1].Reason != core.RefusedTargetUnresolvable {
		t.Errorf("a name that does not resolve: reason %q, want %q", listed[1].Reason, core.RefusedTargetUnresolvable)
	}
	states := map[string]outcome.Target{}
	for _, o := range res.TargetOutcomes {
		states[o.Target] = o
	}
	for _, b := range bad {
		if o := states[b]; o.State != outcome.Skipped || o.Class != outcome.Refused {
			t.Errorf("%s: outcome %+v, want skipped/refused", b, o)
		}
	}
	for _, g := range good {
		if o := states[g]; o.State != outcome.Done {
			t.Errorf("%s: outcome %+v, want done", g, o)
		}
	}
}

// Only when every target is refused does the task fail, naming each one and
// why. A name that does not resolve is refused (fail closed): it cannot be
// proven safe, and it could resolve to a blocked address at scan time.
func TestScanGuard_AllRefusedFails(t *testing.T) {
	bad := []string{"127.0.0.1:80", "nothing.invalid", "intranet", "169.254.169.254"}
	e, sc := guardedExecutor("nuclei")
	_, err := e.Execute(context.Background(), scanCmd(t, map[string]any{"scanner": "nuclei", "targets": bad}))
	if err == nil {
		t.Fatal("a task whose every target is refused succeeded")
	}
	for _, want := range []string{"4 of 4 targets refused", "nothing.invalid", "cannot resolve"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure %q does not say %q", err, want)
		}
	}
	if sc.got() != nil {
		t.Fatalf("SECURITY: the scanner ran on %v", sc.got())
	}
}

// A payload the executor cannot parse is never run.
func TestScanGuard_RefusesUnparseablePayload(t *testing.T) {
	e, sc := guardedExecutor("nuclei")
	_, err := e.Execute(context.Background(), &core.Command{Type: "scan", Payload: json.RawMessage(`{"target": `)})
	if err == nil || sc.got() != nil {
		t.Fatalf("an unparseable scan payload: err %v, ran %v", err, sc.got())
	}
}

// The validating executor no longer touches scans: it hands them on as sent
// (the SDK executor behind it checks each target).
func TestValidatingExecutor_PassesScansThrough(t *testing.T) {
	inner := &passExecutor{}
	v := NewValidatingCommandExecutor(inner, false)
	cmd := scanCmd(t, map[string]any{"scanner": "httpx", "targets": []string{"104.17.85.188:80", "127.0.0.1"}})
	if _, err := v.Execute(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if inner.cmd != cmd {
		t.Fatal("the scan did not reach the executor as sent")
	}
}

type passExecutor struct{ cmd *core.Command }

func (p *passExecutor) Execute(_ context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	if cmd == nil {
		return nil, errors.New("nil command")
	}
	p.cmd = cmd
	return &core.CommandExecutionResult{}, nil
}
