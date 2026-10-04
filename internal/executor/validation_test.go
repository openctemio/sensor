package executor

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

func TestProbeReachability_OpenPortDetected(t *testing.T) {
	// A listener we control → reachable → detected. probeReachability skips the
	// SSRF guard (loopback is hard-blocked in RunSafeCheck), so it is the right
	// seam to exercise the reachability decision.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	outcome, _, ev := probeReachability(context.Background(), []string{ln.Addr().String()}, 2*time.Second, nil, nil)
	if outcome != "detected" {
		t.Fatalf("outcome = %q, want detected", outcome)
	}
	if ev["reachable"] != true {
		t.Errorf("evidence.reachable = %v, want true", ev["reachable"])
	}
}

func TestProbeReachability_ClosedPortNotDetected(t *testing.T) {
	// Bind then immediately close to get a port that is (almost certainly) closed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	outcome, _, _ := probeReachability(context.Background(), []string{addr}, 2*time.Second, nil, nil)
	// A closed port yields connection refused → not_detected. Some kernels may
	// briefly hold the port; accept inconclusive but never detected.
	if outcome == "detected" {
		t.Fatalf("outcome = detected for a closed port, want not_detected/inconclusive")
	}
}

func TestResolveDialTargets(t *testing.T) {
	cases := map[string][]string{
		"example.com":             {"example.com:443", "example.com:80"},
		"example.com:8443":        {"example.com:8443"},
		"https://example.com/x":   {"example.com:443"},
		"http://example.com:8080": {"example.com:8080"},
	}
	for in, want := range cases {
		got, err := resolveDialTargets(in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("%q: got %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q: got %v, want %v", in, got, want)
				break
			}
		}
	}
}

func TestRunSafeCheck_SSRFBlockedTargetRefused(t *testing.T) {
	// IMDS is hard-blocked regardless of the private-target opt-in.
	old := allowPrivateTargets
	allowPrivateTargets = true
	defer func() { allowPrivateTargets = old }()

	outcome, _, ev := RunSafeCheck(context.Background(), "http://169.254.169.254/latest/meta-data", 2*time.Second)
	if outcome != "error" {
		t.Fatalf("outcome = %q, want error (SSRF-blocked)", outcome)
	}
	if _, ok := ev["refused_reason"]; !ok {
		t.Errorf("expected refused_reason in evidence, got %v", ev)
	}
}

func TestRunSafeCheck_EmptyAddress(t *testing.T) {
	outcome, _, _ := RunSafeCheck(context.Background(), "  ", time.Second)
	if outcome != "error" {
		t.Fatalf("outcome = %q, want error for empty address", outcome)
	}
}

// stubExecutor records whether the inner executor was called (delegation path).
type stubExecutor struct{ called bool }

func (s *stubExecutor) Execute(_ context.Context, _ *core.Command) (*core.CommandExecutionResult, error) {
	s.called = true
	return &core.CommandExecutionResult{}, nil
}

// RFC-011.2 Phase 2b: a nuclei re-verify with no detection signature must not
// run nuclei — it stays inconclusive (the api maps that to no state change, so
// it can never cause a false downgrade).
func TestRunNucleiValidate_NoSignature(t *testing.T) {
	outcome, _, _ := RunNucleiValidate(context.Background(), "cmd-1", "https://example.com", "", "", 5*time.Second, false)
	if outcome != "inconclusive" {
		t.Fatalf("outcome = %q, want inconclusive when no signature", outcome)
	}
}

// The nuclei re-verify reuses the safe-check SSRF guard: a hard-blocked target
// is refused before nuclei is ever invoked.
func TestRunNucleiValidate_SSRFBlockedTargetRefused(t *testing.T) {
	old := allowPrivateTargets
	allowPrivateTargets = true // IMDS is hard-blocked regardless of the opt-in
	defer func() { allowPrivateTargets = old }()

	outcome, _, ev := RunNucleiValidate(context.Background(), "cmd-2",
		"http://169.254.169.254/latest/meta-data", "apache-struts-rce", "", 2*time.Second, false)
	if outcome != "error" {
		t.Fatalf("outcome = %q, want error (SSRF-blocked)", outcome)
	}
	if _, ok := ev["refused_reason"]; !ok {
		t.Errorf("expected refused_reason in evidence, got %v", ev)
	}
}

// The wrapper routes a validate command with ExecutorKind=nuclei to the nuclei
// path (proven here via the SSRF guard resolving the verdict without a live
// nuclei binary), never to safe-check reachability.
func TestValidatingCommandExecutor_RoutesNucleiKind(t *testing.T) {
	old := allowPrivateTargets
	allowPrivateTargets = true
	defer func() { allowPrivateTargets = old }()

	inner := &stubExecutor{}
	e := NewValidatingCommandExecutor(inner, false)

	p := validateJobPayload{FindingID: "f-1", ExecutorKind: "nuclei", Technique: "T1190", TemplateID: "apache-struts-rce"}
	p.Target.Address = "169.254.169.254" // hard-blocked → guard resolves immediately
	payload, _ := json.Marshal(p)

	res, err := e.Execute(context.Background(), &core.Command{ID: "cmd-3", Type: "validate", Payload: payload})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if inner.called {
		t.Error("validate command should NOT be delegated to the inner executor")
	}
	out, _ := res.Metadata["outcome"].(string)
	if out != "error" {
		t.Errorf("metadata.outcome = %q, want error (nuclei path refused the blocked target)", out)
	}
	// The evidence must be the nuclei path's (carries the signature), not safe-check's.
	ev, _ := res.Metadata["evidence"].(map[string]any)
	if ev == nil || ev["signature"] != "apache-struts-rce" {
		t.Errorf("expected nuclei evidence with signature, got %v", res.Metadata["evidence"])
	}
}

func TestValidatingCommandExecutor_DelegatesNonValidate(t *testing.T) {
	inner := &stubExecutor{}
	e := NewValidatingCommandExecutor(inner, false)
	_, err := e.Execute(context.Background(), &core.Command{Type: "scan"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !inner.called {
		t.Error("non-validate command was not delegated to the inner executor")
	}
}

func TestValidatingCommandExecutor_HandlesValidate(t *testing.T) {
	inner := &stubExecutor{}
	e := NewValidatingCommandExecutor(inner, false)

	// Use a hard-blocked bare IP so the guard resolves the verdict immediately
	// (no DNS / network in unit tests) — the point here is the wrapper wiring,
	// not the probe itself (covered by TestProbeReachability_*).
	p := validateJobPayload{FindingID: "f-1", ExecutorKind: "safe-check", Technique: "T1046"}
	p.Target.Address = "169.254.169.254"
	payload, _ := json.Marshal(p)

	res, err := e.Execute(context.Background(), &core.Command{Type: "validate", Payload: payload})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if inner.called {
		t.Error("validate command should NOT be delegated to the inner executor")
	}
	// The wrapper must produce a verdict in metadata (the server hook reads it).
	if out, ok := res.Metadata["outcome"].(string); !ok || out == "" {
		t.Errorf("metadata.outcome = %v, want a non-empty verdict", res.Metadata["outcome"])
	}
}

// A nuclei re-verification names the template release it ran on (version
// and archive digest), so the platform can tell a retest on another
// template set from one on the set the finding was recorded with.
func TestNucleiValidateEvidenceNamesTemplateRelease(t *testing.T) {
	set := nucleiTemplateSet{dir: t.TempDir(), content: core.ContentInfo{
		Name: core.ContentNucleiTemplates, Version: "v10.4.9",
		Digest: "sha256:d7cd989935f9a84943cba8a193f567db37626dbf4e526ff57ba5b1f24badd5d6",
	}}
	// No signature: the run stops before nuclei, the evidence still names the set.
	outcome, _, ev := runNucleiValidate(context.Background(), "cmd-1", "https://h.example.test", "", "", set, time.Second, 0, false)
	if outcome != "inconclusive" || ev["templates_version"] != "v10.4.9" || ev["templates_digest"] != set.content.Digest {
		t.Fatalf("outcome %s evidence %v", outcome, ev)
	}
	// nuclei's own directory: no release to name.
	_, _, ev = runNucleiValidate(context.Background(), "cmd-2", "https://h.example.test", "", "", nucleiTemplateSet{}, time.Second, 0, false)
	if _, ok := ev["templates_version"]; ok {
		t.Fatalf("evidence %v", ev)
	}
}
