package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sensor/internal/lookup"
	"github.com/openctemio/sensor/internal/scanners/betterleaks"
	"github.com/openctemio/sensor/internal/scanners/codeql"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/scanners/opengrep"
	"github.com/openctemio/sensor/internal/scanners/semgrep"
	"github.com/openctemio/sensor/internal/scanners/trivy"
	"github.com/openctemio/sensor/internal/toolrun"
)

type acceptsPools bool

func (a acceptsPools) AcceptsEgressPools() bool { return bool(a) }

// SECURITY: egress.upstream@1 is advertised only when tool tasks run
// confined to their forwarder and the owner accepts platform pools.
func TestEgressUpstreamCapability(t *testing.T) {
	prev := executor.Current()
	t.Cleanup(func() { executor.SetCurrent(prev) })
	executor.SetCurrent(statusBackend{st: executor.Status{NetworkEnforced: true}})
	if !egressUpstream(acceptsPools(true)) {
		t.Fatal("confined, pools accepted: not advertised")
	}
	if egressUpstream(acceptsPools(false)) {
		t.Fatal("direct-only (or shared): advertised")
	}
	t.Setenv(toolrun.EnvRuntime, "in-process")
	if egressUpstream(acceptsPools(true)) {
		t.Fatal("in-process tools: advertised")
	}
	t.Setenv(toolrun.EnvRuntime, "")
	executor.SetCurrent(statusBackend{st: executor.Status{}})
	if egressUpstream(acceptsPools(true)) {
		t.Fatal("unconfined sandbox: advertised")
	}
	if core.CapabilityEgressUpstream != "egress.upstream@1" {
		t.Fatalf("capability name %q", core.CapabilityEgressUpstream)
	}
}

// Every built-in scanner says whether a job's proxy pool can carry its
// connections: out of process yes, in process no.
func TestBuiltinScannersRouteEgressOnlyOutOfProcess(t *testing.T) {
	scanners := map[string]core.EgressScanner{
		"nuclei": nuclei.NewScanner(), "trivy": trivy.NewScanner(), "semgrep": semgrep.NewScanner(),
		"opengrep": opengrep.NewScanner(), "codeql": codeql.NewScanner(), "betterleaks": &betterleaksAdapter{BetterleaksScanner: betterleaks.NewScanner()},
	}
	for name, s := range scanners {
		if !s.RoutesEgress() {
			t.Errorf("%s out of process: does not route egress", name)
		}
	}
	t.Setenv(toolrun.EnvRuntime, "in-process")
	for name, s := range scanners {
		if s.RoutesEgress() {
			t.Errorf("%s in process: routes egress", name)
		}
	}
	var _ core.EgressScanner = (*lookup.Scanner)(nil)
}
