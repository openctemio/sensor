package main

// What this sensor reports it can do (api RFC-029 §4.3.1): on every
// heartbeat the daemon tells the platform which of its scanners are really
// installed (with their version and content), the capabilities it serves
// and how many jobs it runs at once. The platform dispatches by this report;
// its administrator can only narrow it. The inventory is the SDK's tool
// registry (BaseSensor.Tools): the daemon registers its scanners there, and
// the SDK probes and reports them.

import (
	"context"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// inventoryTTL is how long a tool probe result is reused. Probing runs each
// tool's version check, which is too slow for every heartbeat; a tool
// installed while the daemon runs shows up within this time.
const inventoryTTL = 10 * time.Minute

// registerConfiguredTools registers cfg's enabled scanners in reg (probed
// with their IsInstalled), the capabilities the daemon serves whatever its
// tools and its concurrency cap. Scanners that cannot be created (unknown
// names) are not registered: they cannot run here and the platform would
// drop unknown names anyway.
func registerConfiguredTools(cfg *Config, reg *core.ToolRegistry) {
	registerTools(cfg, reg, getScanner)
}

// registerTools is registerConfiguredTools with the scanner factory given.
func registerTools(cfg *Config, reg *core.ToolRegistry, newScanner func(ScannerConfig, bool) (core.Scanner, error)) {
	// The validating executor wraps every command executor, so a daemon
	// that runs commands always serves validation.
	validate := cfg.Sensor.EnableCommands
	reg.SetProbeTTL(inventoryTTL)
	reg.SetProbeTimeout(toolProbeTimeout)
	for _, sc := range cfg.Scanners {
		if !sc.Enabled {
			continue
		}
		scanner, err := newScanner(sc, false)
		if err != nil || scanner == nil {
			continue
		}
		var extra []string
		if core.CanonicalScannerName(sc.Name) == "trivy-image" {
			// A trivy image scan is a container scan whatever its
			// scanner list says.
			extra = append(extra, "container")
		}
		if validate && scanner.Name() == "nuclei" {
			extra = append(extra, "validate:nuclei")
		}
		// Another mode of the same tool (trivy-fs and trivy-image) merges
		// into one entry.
		_ = reg.RegisterScanner(scanner, extra...)
	}
	if validate {
		reg.AddCapabilities("validate")
	}
	// The operator's cap (sensor.max_jobs, -max-concurrent,
	// SENSOR_MAX_JOBS); 0 reports none, and the poller's slot maximum is
	// reported instead (BaseSensor.SetLoadReporter).
	reg.SetMaxConcurrentJobs(cfg.Sensor.MaxJobs)
}

// capabilityReporter is the heartbeat's report: the tool registry's, with
// each tool's scanner content, and an empty inventory reported as "no tool"
// (a daemon reports what it has, even nothing).
type capabilityReporter struct {
	tools *core.ToolRegistry
	// decorate adds each tool's scanner content (content.Manager.Decorate);
	// nil leaves the report as it is.
	decorate func(core.CapabilityReport) core.CapabilityReport
}

var _ core.CapabilityReporter = (*capabilityReporter)(nil)

// newCapabilityReporter registers cfg's scanners in reg (a new registry
// when nil; pass the sensor's, BaseSensor.Tools) and reports it.
func newCapabilityReporter(cfg *Config, reg *core.ToolRegistry, decorate func(core.CapabilityReport) core.CapabilityReport) *capabilityReporter {
	if reg == nil {
		reg = core.NewToolRegistry()
	}
	registerConfiguredTools(cfg, reg)
	return &capabilityReporter{tools: reg, decorate: decorate}
}

// CapabilityReport implements core.CapabilityReporter.
func (r *capabilityReporter) CapabilityReport(ctx context.Context) core.CapabilityReport {
	rep := r.tools.CapabilityReport(ctx)
	if rep.Tools == nil {
		rep.Tools = []core.ToolInfo{}
	}
	if rep.Capabilities == nil {
		rep.Capabilities = []string{}
	}
	if r.decorate != nil {
		// Content changes between probes (refreshes), so it is added on
		// every heartbeat.
		return r.decorate(rep)
	}
	return rep
}
