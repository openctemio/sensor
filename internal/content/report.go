package content

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ToolOf maps a scanner name to the tool whose content it uses ("trivy-fs"
// and the other trivy modes use trivy's).
func ToolOf(scanner string) string {
	s := strings.ToLower(strings.TrimSpace(scanner))
	switch {
	case s == "trivy" || strings.HasPrefix(s, "trivy-"):
		return "trivy"
	case s == "nuclei":
		return "nuclei"
	case s == "semgrep":
		return "semgrep"
	default:
		return s
	}
}

// Decorate attaches the content of each reported tool to a capability
// report. A reporter that builds the tool inventory itself wraps its report
// with it.
func (m *Manager) Decorate(r core.CapabilityReport) core.CapabilityReport {
	if m == nil || r.Tools == nil {
		return r
	}
	tools := make([]core.ToolInfo, len(r.Tools))
	for i, t := range r.Tools {
		if c := m.Report(ToolOf(t.Name)); len(c) > 0 {
			t.Content = c
		}
		tools[i] = t
	}
	r.Tools = tools
	return r
}

// ProbeFunc reports a tool's installed version.
type ProbeFunc func(ctx context.Context, tool string) (version string, installed bool)

// Reporter reports the configured tools, their versions and their content
// on every heartbeat. Tool probes are cached.
type Reporter struct {
	Manager *Manager
	// Tools are the canonical tool names configured on the sensor.
	Tools []string
	Probe ProbeFunc
	// TTL is how long a probe is reused (default 10 minutes).
	TTL time.Duration

	mu     sync.Mutex
	probed time.Time
	cache  map[string]core.ToolInfo
}

// CapabilityReport implements core.CapabilityReporter. Capabilities and
// concurrency are not reported here.
func (r *Reporter) CapabilityReport(ctx context.Context) core.CapabilityReport {
	r.mu.Lock()
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if r.cache == nil || time.Since(r.probed) > ttl {
		r.cache = map[string]core.ToolInfo{}
		for _, t := range r.Tools {
			info := core.ToolInfo{Name: t}
			if r.Probe != nil {
				info.Version, info.Installed = r.Probe(ctx, t)
			}
			r.cache[t] = info
		}
		r.probed = time.Now()
	}
	tools := make([]core.ToolInfo, 0, len(r.Tools))
	for _, t := range r.Tools {
		tools = append(tools, r.cache[t])
	}
	r.mu.Unlock()
	return r.Manager.Decorate(core.CapabilityReport{Tools: tools})
}

// Pusher stamps the content a scan used onto its results
// (tool.properties.content) and delegates to the inner pusher.
//
// The content is the version the tool's most recent scan started with. Two
// scans of one tool that overlap a content swap can be stamped with the
// newer one; scans themselves always run on one consistent version.
type Pusher struct {
	core.Pusher
	Manager *Manager
}

// PushFindings implements core.Pusher.
func (p *Pusher) PushFindings(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	p.Stamp(report)
	return p.Pusher.PushFindings(ctx, report)
}

// PushAssets implements core.Pusher.
func (p *Pusher) PushAssets(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	p.Stamp(report)
	return p.Pusher.PushAssets(ctx, report)
}

// Stamp writes the content the report's tool last scanned with into
// report.Tool.Properties["content"] (ctis tool properties are free-form).
func (p *Pusher) Stamp(report *ctis.Report) {
	if p == nil || p.Manager == nil || report == nil || report.Tool == nil {
		return
	}
	used := p.Manager.LastUsed(ToolOf(report.Tool.Name))
	if len(used) == 0 {
		return
	}
	if report.Tool.Properties == nil {
		report.Tool.Properties = ctis.Properties{}
	}
	report.Tool.Properties["content"] = used
}
