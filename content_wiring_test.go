package main

import (
	"reflect"
	"testing"

	"github.com/openctemio/sensor/internal/content"
)

func TestContentTools(t *testing.T) {
	names, used := contentTools([]ScannerConfig{
		{Name: "trivy-fs", Enabled: true}, {Name: "trivy-config", Enabled: true},
		{Name: "gitleaks", Enabled: true}, {Name: "nuclei", Enabled: false}, {Name: "semgrep", Enabled: true},
	})
	if want := []string{"trivy", "betterleaks", "semgrep"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("names %v, want %v", names, want)
	}
	if used != (content.Tools{Trivy: true, Semgrep: true}) {
		t.Fatalf("used %+v", used)
	}
}

func TestNewContentManagerOffAndReadOnly(t *testing.T) {
	t.Setenv(content.EnvContent, "off")
	if m, err := newContentManager([]ScannerConfig{{Name: "trivy", Enabled: true}}, false, false); m != nil || err != nil {
		t.Fatalf("SENSOR_CONTENT=off built a manager: %v %v", m, err)
	}
	t.Setenv(content.EnvContent, "")
	t.Setenv(content.EnvDir, t.TempDir()+"/absent")
	// A one-shot run does not create the content directory.
	if m, err := newContentManager([]ScannerConfig{{Name: "trivy", Enabled: true}}, false, true); m != nil || err != nil {
		t.Fatalf("read-only manager without a content dir: %v %v", m, err)
	}
	t.Setenv(content.EnvInterval, "nonsense")
	if _, err := newContentManager(nil, false, false); err == nil {
		t.Fatal("invalid setting accepted")
	}
}
