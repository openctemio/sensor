package semgrep

import (
	"context"
	"testing"

	"github.com/openctemio/sensor/internal/scanners/internal/reporttest"
)

// A read-only target (a :ro volume) must scan: the report goes to a private
// temporary directory, never into the scanned tree, and is removed afterwards.
func TestScanReadOnlyTargetKeepsReportOutOfTree(t *testing.T) {
	target := reporttest.ReadOnlyTarget(t)
	bin, log := reporttest.FakeTool(t, `{"results":[],"errors":[]}`)
	s := NewScanner()
	s.Binary = bin
	res, err := s.Scan(context.Background(), target, nil)
	if err != nil {
		t.Fatalf("scan of a read-only target failed: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	reporttest.AssertOutsideAndRemoved(t, log, target)
}
