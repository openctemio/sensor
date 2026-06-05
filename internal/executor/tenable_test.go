package executor

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/platform"
)

func TestTenableExecutor_Meta(t *testing.T) {
	e := NewTenableExecutor(&TenableConfig{Enabled: true, BaseURL: "https://n", AccessKey: "a", SecretKey: "b"}, nil)
	if e.Name() != "tenable" {
		t.Fatalf("name: %q", e.Name())
	}
	if len(e.Capabilities()) != 1 || e.Capabilities()[0] != "infra" {
		t.Fatalf("capabilities: %v", e.Capabilities())
	}
	if !e.IsEnabled() {
		t.Fatal("should be enabled")
	}
	if len(e.InstalledTools()) != 1 {
		t.Fatalf("installed tools: %v", e.InstalledTools())
	}
}

func TestTenableExecutor_FailsWhenUnconfigured(t *testing.T) {
	// No base URL / keys → fail-result (not a hard error), so the platform sees
	// a failed job rather than a panic.
	e := NewTenableExecutor(&TenableConfig{Enabled: true}, nil)
	res, err := e.Execute(context.Background(), &platform.JobInfo{ID: "j1", Payload: map[string]any{"targets": []any{"10.0.0.1"}}})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if res.Status != "failed" {
		t.Fatalf("expected failed status, got %q", res.Status)
	}
}

func TestTenableExecutor_RejectsSC(t *testing.T) {
	e := NewTenableExecutor(&TenableConfig{Enabled: true, Engine: "tenable_sc", BaseURL: "https://n", AccessKey: "a", SecretKey: "b"}, nil)
	res, _ := e.Execute(context.Background(), &platform.JobInfo{ID: "j", Payload: map[string]any{"targets": []any{"10.0.0.1"}}})
	if res.Status != "failed" {
		t.Fatal("tenable.sc should fail (not yet supported)")
	}
}

func TestTenableExecutor_NoTargets(t *testing.T) {
	e := NewTenableExecutor(&TenableConfig{Enabled: true, BaseURL: "https://n", AccessKey: "a", SecretKey: "b"}, nil)
	res, _ := e.Execute(context.Background(), &platform.JobInfo{ID: "j", Payload: map[string]any{}})
	if res.Status != "failed" {
		t.Fatal("missing targets should fail")
	}
}

func TestParseTenablePayload(t *testing.T) {
	p := parseTenablePayload(&platform.JobInfo{Payload: map[string]any{
		"targets":       []any{"10.0.0.1", "10.0.0.0/24"},
		"session_id":    "sess-1",
		"template_uuid": "tmpl",
	}})
	if len(p.Targets) != 2 || p.SessionID != "sess-1" || p.TemplateUUID != "tmpl" {
		t.Fatalf("payload parse wrong: %+v", p)
	}
}

func TestRouter_RoutesTenable(t *testing.T) {
	r := NewRouter(&RouterConfig{}, nil)
	r.RegisterTenable(NewTenableExecutor(&TenableConfig{Enabled: true, BaseURL: "https://n", AccessKey: "a", SecretKey: "b"}, nil))
	for _, jt := range []string{"tenable", "infra"} {
		exec, err := r.Route(&platform.JobInfo{Type: jt})
		if err != nil || exec == nil || exec.Name() != "tenable" {
			t.Fatalf("route %q: exec=%v err=%v", jt, exec, err)
		}
	}
}
