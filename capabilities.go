package main

// What this sensor reports it can do (api RFC-029 §4.3.1): on every
// heartbeat the daemon tells the platform which of its configured scanners
// are really installed (with their version), the capabilities it serves and
// how many jobs it runs at once. The platform dispatches by this report; its
// administrator can only narrow it.

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// toolProbe is one configured scanner the inventory checks.
type toolProbe struct {
	// name is the scanner's catalog name (core.Scanner.Name: "trivy" for
	// every trivy mode).
	name string
	// check is the scanner's own IsInstalled.
	check func(ctx context.Context) (bool, string, error)
	// caps are the capability-registry names the scanner serves when it is
	// installed, besides its own name (the platform dispatches a scan with
	// the tool's name as the required capability).
	caps []string
}

// registryCapability maps a scanner's own capability words to the
// platform's capability registry; words the registry does not know are not
// reported (the platform would drop them).
var registryCapability = map[string]string{
	"sast":             "sast",
	"sca":              "sca",
	"dast":             "dast",
	"iac":              "iac",
	"container":        "container",
	"secret_detection": "secrets",
	"secrets":          "secrets",
}

// scannerCapabilities returns the registry capabilities of a configured
// scanner. A trivy image scan is a container scan whatever its scanner
// list says.
func scannerCapabilities(configured string, scanner core.Scanner) []string {
	var out []string
	add := func(c string) {
		if c != "" && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	for _, c := range scanner.Capabilities() {
		add(registryCapability[c])
	}
	if configured == "trivy-image" {
		add("container")
	}
	return out
}

// inventoryTTL is how long a tool probe result is reused. Probing runs each
// tool's version check, which is too slow for every heartbeat; a tool
// installed while the daemon runs shows up within this time.
const inventoryTTL = 10 * time.Minute

// capabilityReporter builds the heartbeat's capability report from the
// configured scanners, probing them at most once per ttl.
type capabilityReporter struct {
	probes []toolProbe
	// validate is true when the daemon runs commands: it always serves
	// validation (the validating executor wraps every command executor).
	validate bool
	// maxJobs is the operator's cap (sensor.max_jobs, -max-concurrent,
	// SENSOR_MAX_JOBS); 0 reports none, and the poller's slot maximum is
	// reported instead (BaseSensor.SetLoadReporter).
	maxJobs int
	// decorate adds each tool's scanner content (content.Manager.Decorate);
	// nil leaves the report as it is.
	decorate func(core.CapabilityReport) core.CapabilityReport
	ttl      time.Duration
	now      func() time.Time

	mu     sync.Mutex
	at     time.Time
	report core.CapabilityReport
}

var _ core.CapabilityReporter = (*capabilityReporter)(nil)

// newCapabilityReporter reports the enabled scanners of cfg. Scanners that
// cannot be created (unknown names) are not reported: they cannot run here
// and the platform would drop unknown names anyway.
func newCapabilityReporter(cfg *Config, decorate func(core.CapabilityReport) core.CapabilityReport) *capabilityReporter {
	r := &capabilityReporter{
		validate: cfg.Sensor.EnableCommands,
		maxJobs:  cfg.Sensor.MaxJobs,
		decorate: decorate,
		ttl:      inventoryTTL,
		now:      time.Now,
	}
	idx := map[string]int{}
	for _, sc := range cfg.Scanners {
		if !sc.Enabled {
			continue
		}
		scanner, err := getScanner(sc, false)
		if err != nil || scanner == nil {
			continue
		}
		caps := scannerCapabilities(core.CanonicalScannerName(sc.Name), scanner)
		if i, ok := idx[scanner.Name()]; ok {
			// Another mode of the same tool (trivy-fs and trivy-image).
			for _, c := range caps {
				if !slices.Contains(r.probes[i].caps, c) {
					r.probes[i].caps = append(r.probes[i].caps, c)
				}
			}
			continue
		}
		idx[scanner.Name()] = len(r.probes)
		r.probes = append(r.probes, toolProbe{name: scanner.Name(), check: scanner.IsInstalled, caps: caps})
	}
	return r
}

// CapabilityReport implements core.CapabilityReporter.
func (r *capabilityReporter) CapabilityReport(ctx context.Context) core.CapabilityReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.at.IsZero() || r.now().Sub(r.at) >= r.ttl {
		r.report = r.build(ctx)
		r.at = r.now()
	}
	if r.decorate != nil {
		// Content changes between probes (refreshes), so it is added on
		// every heartbeat.
		return r.decorate(r.report)
	}
	return r.report
}

func (r *capabilityReporter) build(ctx context.Context) core.CapabilityReport {
	out := core.CapabilityReport{
		Tools:             make([]core.ToolInfo, 0, len(r.probes)),
		Capabilities:      []string{},
		MaxConcurrentJobs: r.maxJobs,
	}
	addCap := func(c string) {
		if !slices.Contains(out.Capabilities, c) {
			out.Capabilities = append(out.Capabilities, c)
		}
	}
	for _, p := range r.probes {
		pctx, cancel := context.WithTimeout(ctx, toolProbeTimeout)
		installed, version, err := p.check(pctx)
		cancel()
		installed = installed && err == nil
		if !installed {
			version = ""
		}
		out.Tools = append(out.Tools, core.ToolInfo{Name: p.name, Version: version, Installed: installed})
		if !installed {
			continue
		}
		addCap(p.name)
		for _, c := range p.caps {
			addCap(c)
		}
		if r.validate && p.name == "nuclei" {
			addCap("validate:nuclei")
		}
	}
	if r.validate {
		addCap("validate")
	}
	return out
}

