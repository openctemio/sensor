package nuclei

import (
	"testing"
	"time"
)

// The run's own process bound is the manifest's, never shorter: the job's
// budget, not a constant, decides how long a list run may take.
func TestDefaultTimeoutIsTheManifestBound(t *testing.T) {
	if got := time.Duration(ToolManifest.Resources.Timeout); got != DefaultTimeout {
		t.Fatalf("manifest timeout %s, DefaultTimeout %s", got, DefaultTimeout)
	}
	if NewScanner().Timeout != DefaultTimeout {
		t.Fatal("a new scanner does not take the manifest bound")
	}
}
