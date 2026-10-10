package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sensor/internal/toolrun"
)

type statusBackend struct {
	executor.Backend
	st executor.Status
}

func (b statusBackend) Status() executor.Status { return b.st }

// SECURITY: scope.limits@1 is advertised only when the sandbox confines
// the tools' network and tools run out of process.
func TestScopeLimitsEnforced(t *testing.T) {
	prev := executor.Current()
	t.Cleanup(func() { executor.SetCurrent(prev) })
	executor.SetCurrent(statusBackend{st: executor.Status{NetworkEnforced: true}})
	if !scopeLimitsEnforced() {
		t.Fatal("confined sandbox: not advertised")
	}
	t.Setenv(toolrun.EnvRuntime, "in-process")
	if scopeLimitsEnforced() {
		t.Fatal("in-process tools: advertised")
	}
	t.Setenv(toolrun.EnvRuntime, "")
	executor.SetCurrent(statusBackend{st: executor.Status{}})
	if scopeLimitsEnforced() {
		t.Fatal("unconfined sandbox: advertised")
	}
}
