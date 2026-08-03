package executor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// In the default build a scan is executed by core.NewDefaultCommandExecutor
// from sdk-go, which calls scanner.Scan(ctx, payload.Target, opts) with no
// validation — the pinned v0.5.2 has no httpsec package at all. The agent's own
// guarded path (vulnscan.go → validateScanTarget) sits behind executor.Router,
// whose only construction site is platform.go under //go:build platform.
//
// So the shipping agent has had no SSRF guard on scan targets, while the much
// narrower validate path has had one since it landed. Scan targets come from
// assets.name, i.e. from ingest.
//
// These tests pin the guard at the boundary the agent controls, so a future
// sdk-go bump — or downgrade — cannot silently change the answer.

// recordingExecutor stands in for the SDK executor and records whether the
// command reached it. Reaching it IS the vulnerability.
type recordingExecutor struct{ reached bool }

func (r *recordingExecutor) Execute(_ context.Context, _ *core.Command) (*core.CommandExecutionResult, error) {
	r.reached = true
	return &core.CommandExecutionResult{}, nil
}

func scanCmd(t *testing.T, payload map[string]any) *core.Command {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return &core.Command{Type: "scan", Payload: b}
}

// The hard-blocked tier. No configuration opens these, so if any reaches the
// scanner the guard is not doing its job.
func TestScanGuard_BlocksHardBlockedTargets(t *testing.T) {
	cases := map[string]map[string]any{
		"AWS/GCP metadata":     {"target": "http://169.254.169.254/latest/meta-data/"},
		"metadata bare host":   {"target": "169.254.169.254"},
		"loopback":             {"target": "http://127.0.0.1:8080"},
		"loopback by name":     {"target": "localhost"},
		"in the targets array": {"targets": []string{"example.test", "169.254.169.254"}},
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			inner := &recordingExecutor{}
			e := NewValidatingCommandExecutor(inner, false)

			_, err := e.Execute(context.Background(), scanCmd(t, payload))

			if inner.reached {
				t.Fatal("the scan command reached the SDK executor — sdk-go v0.5.2 " +
					"passes payload.Target straight to scanner.Scan with no validation")
			}
			if err == nil {
				t.Fatal("no error returned; the job would be reported as a success")
			}
			if !strings.Contains(err.Error(), "refused") {
				t.Errorf("refused, but not for the expected reason: %v", err)
			}
		})
	}
}

// The guard must not break ordinary scanning. A guard that refuses real targets
// would be reverted within a day, which is worse than not having one.
func TestScanGuard_AllowsOrdinaryTargets(t *testing.T) {
	// IP literals, so the test does not depend on DNS. The guard resolves
	// hostnames, and a test that needs the network is a test that fails in CI
	// for reasons that have nothing to do with the guard.
	cases := map[string]map[string]any{
		"public IP":       {"target": "93.184.216.34"},
		"public https":    {"target": "https://93.184.216.34/app"},
		"targets array":   {"targets": []string{"93.184.216.34", "8.8.8.8"}},
		"no target field": {"scanner": "gitleaks"},
		"empty payload":   {},
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			inner := &recordingExecutor{}
			e := NewValidatingCommandExecutor(inner, false)

			if _, err := e.Execute(context.Background(), scanCmd(t, payload)); err != nil {
				t.Fatalf("ordinary scan refused: %v", err)
			}
			if !inner.reached {
				t.Fatal("the scan never reached the executor — the guard is too broad")
			}
		})
	}
}

// A payload this guard cannot parse must not be forwarded unread. The whole
// reason the guard exists is that what reaches the scanner is influenced by
// ingested data.
func TestScanGuard_RefusesUnparseablePayload(t *testing.T) {
	inner := &recordingExecutor{}
	e := NewValidatingCommandExecutor(inner, false)

	_, err := e.Execute(context.Background(), &core.Command{
		Type:    "scan",
		Payload: json.RawMessage(`{"target": `),
	})

	if inner.reached {
		t.Fatal("an unparseable scan payload was forwarded to the scanner")
	}
	if err == nil {
		t.Fatal("no error on an unparseable payload")
	}
}

// Non-scan commands must be untouched by this path.
func TestScanGuard_DelegatesOtherCommandTypes(t *testing.T) {
	inner := &recordingExecutor{}
	e := NewValidatingCommandExecutor(inner, false)

	cmd := &core.Command{Type: "collect", Payload: json.RawMessage(`{"target":"169.254.169.254"}`)}
	if _, err := e.Execute(context.Background(), cmd); err != nil {
		t.Fatalf("collect command errored: %v", err)
	}
	if !inner.reached {
		t.Fatal("a non-scan command was intercepted by the scan guard")
	}
}

// The guard refuses a hostname it cannot resolve. That is pre-existing
// behaviour of validateScannerTarget — the platform build has always worked
// this way — but extending the guard to the default build extends this
// consequence with it, so it is pinned here deliberately rather than discovered
// by an operator whose internal-only DNS name stops scanning.
//
// If this turns out to be too strict in practice, the fix is a decision about
// the guard, not about this executor.
func TestScanGuard_RefusesUnresolvableHost(t *testing.T) {
	inner := &recordingExecutor{}
	e := NewValidatingCommandExecutor(inner, false)

	// .test is reserved and never resolves.
	_, err := e.Execute(context.Background(), scanCmd(t, map[string]any{"target": "nothing.test"}))

	if err == nil {
		t.Fatal("an unresolvable host was allowed through")
	}
	if !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Errorf("refused for an unexpected reason: %v", err)
	}
	if inner.reached {
		t.Fatal("the command still reached the executor")
	}
}
