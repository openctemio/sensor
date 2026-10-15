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

// SECURITY: net.confined@1 is advertised only when the sandbox confines
// the tools' network and tools run out of process.
func TestNetConfined(t *testing.T) {
	prev := executor.Current()
	t.Cleanup(func() { executor.SetCurrent(prev) })
	executor.SetCurrent(statusBackend{st: executor.Status{NetworkEnforced: true}})
	if !netConfined() {
		t.Fatal("confined sandbox: not advertised")
	}
	t.Setenv(toolrun.EnvRuntime, "in-process")
	if netConfined() {
		t.Fatal("in-process tools: advertised")
	}
	t.Setenv(toolrun.EnvRuntime, "")
	executor.SetCurrent(statusBackend{st: executor.Status{NetworkEnforced: false, NetworkMissing: "operation not permitted"}})
	if netConfined() {
		t.Fatal("unconfined sandbox: advertised")
	}
	if executor.CapabilityNetConfined != "net.confined@1" {
		t.Fatalf("capability name %q: the platform matches net.confined@1", executor.CapabilityNetConfined)
	}
}

// SECURITY: http.identity@1 is advertised only when tools run out of
// process, through the tool host that applies the job's identification;
// in-process tools never claim it.
func TestHTTPIdentityApplied(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	if !httpIdentityApplied() {
		t.Fatal("tools through the tool host: not advertised")
	}
	t.Setenv(toolrun.EnvRuntime, "in-process")
	if httpIdentityApplied() {
		t.Fatal("in-process tools: advertised")
	}
}
