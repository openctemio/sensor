package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// No strong isolation backend ships yet: every candidate the sensor offers
// must be of class strong when listed, and today there are none, so the
// capability cannot be advertised.
func TestNoStrongIsolationBackendShipsYet(t *testing.T) {
	for _, c := range strongIsolationBackends() {
		if c.Class != executor.ClassStrong {
			t.Fatalf("candidate %s has class %q: only strong backends belong in this list", c.Name, c.Class)
		}
	}
	if n := len(strongIsolationBackends()); n != 0 {
		t.Fatalf("%d strong backends listed; update the docs and the helm/ansible install notes with the one you add", n)
	}
}
