package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// An older config or CI template that still says "gitleaks" runs betterleaks.
func TestGetScannerRunsBetterleaksForRetiredName(t *testing.T) {
	for _, name := range []string{"betterleaks", "gitleaks"} {
		s, err := getScanner(ScannerConfig{Name: name, Enabled: true}, false)
		if err != nil {
			t.Fatalf("getScanner(%q): %v", name, err)
		}
		if s.Name() != core.ScannerBetterleaks {
			t.Errorf("getScanner(%q).Name() = %q, want %q", name, s.Name(), core.ScannerBetterleaks)
		}
	}
}
