package codeql

import (
	"context"
	"testing"

	"github.com/openctemio/sensor/internal/scanners/internal/reporttest"
)

// A read-only target must scan: neither the CodeQL database nor the SARIF
// report goes into the scanned tree, and both are removed afterwards.
func TestScanReadOnlyTargetKeepsDatabaseAndReportOutOfTree(t *testing.T) {
	target := reporttest.ReadOnlyTarget(t)
	bin, log := reporttest.FakeTool(t, `{"version":"2.1.0","runs":[]}`)
	s := NewSecurityScanner(LanguageGo)
	s.Binary = bin
	if _, err := s.Scan(context.Background(), target, nil); err != nil {
		t.Fatalf("scan of a read-only target failed: %v", err)
	}
	reporttest.AssertOutsideAndRemoved(t, log, target)
}
