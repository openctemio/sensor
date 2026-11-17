package toolrun

import (
	"errors"
	"fmt"
	"maps"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Traffic says what a tool sends to the hosts its task's targets name, and
// so how it is paced. Every tool the sensor compiles in is listed in
// toolTraffic: a tool that is not is refused when it starts, and a test
// fails (TestEveryToolHasATrafficKind).
type Traffic int

const (
	// NoTargetTraffic: the tool sends nothing to the hosts of its targets.
	// It reads local files (a code scan), asks the sensor's resolvers (DNS)
	// or asks third parties about the target (passive sources, registries,
	// advisory and rule feeds). A tool of this kind whose manifest says
	// network egress-proxy still needs the budget: its scope is every
	// public host, its targets included, and the tool host holds every host
	// it reaches to it (requireBudget).
	NoTargetTraffic Traffic = iota + 1
	// TargetRequests: the tool sends requests to its targets (HTTP, or a
	// connection with a protocol exchange). It runs under the scan's
	// per-host budget: Run refuses to start it without one
	// (toolhost.RunOptions.HostBudget).
	TargetRequests
	// TargetPackets: the tool probes ports. It is paced in packets per
	// second by the level of the scan's budget (adapt.Pacing.ProbePPS), not
	// held to the budget's requests per second: a port probe is not a
	// request, and a port scan at 20 probes a second per host would not
	// finish. It is started with the budget and
	// toolhost.RunOptions.PortProbes: Run refuses it without either.
	TargetPackets
)

// toolTraffic lists every compiled-in tool by its manifest name.
var toolTraffic = map[string]Traffic{
	// Requests to the targets: under the per-host budget.
	"nuclei":          TargetRequests,
	"nuclei-validate": TargetRequests, // re-verification and retests send the finding's template to the target
	"httpx":           TargetRequests,
	"katana":          TargetRequests,
	"webguess":        TargetRequests,
	"webshot":         TargetRequests, // a browser loads the page
	"svcdetect":       TargetRequests, // connects to each service and exchanges a banner or a probe

	// Port probes: packets per second of the budget's level.
	"naabu": TargetPackets,

	// Nothing to the targets' hosts.
	"dnsx":        NoTargetTraffic, // DNS queries to the sensor's resolvers
	"dnsx-enum":   NoTargetTraffic, // DNS queries to the sensor's resolvers
	"subfinder":   NoTargetTraffic, // passive sources (third parties)
	"rdap":        NoTargetTraffic, // the registries' RDAP services
	"asn":         NoTargetTraffic, // a routing dataset and the registries' RDAP services
	"trivy":       NoTargetTraffic, // reads a local checkout or image; fetches its advisory database
	"semgrep":     NoTargetTraffic, // reads a local checkout; fetches rules
	"codeql":      NoTargetTraffic, // reads a local checkout; fetches query packs
	"opengrep":    NoTargetTraffic, // reads a local checkout, no network
	"betterleaks": NoTargetTraffic, // reads a local checkout, no network
}

// TrafficOf is what the tool named name sends to its targets (false: the
// tool is not listed).
func TrafficOf(name string) (Traffic, bool) {
	t, ok := toolTraffic[name]
	return t, ok
}

// SetTraffic lists a tool under kind, for a test that runs a variant of a
// tool under another name.
func SetTraffic(name string, kind Traffic) { toolTraffic[name] = kind }

// TrafficKinds is a copy of the table: every listed tool and what it sends
// to its targets.
func TrafficKinds() map[string]Traffic { return maps.Clone(toolTraffic) }

// ErrNoHostBudget is the error of a tool that sends requests to its
// targets and was started without a per-host budget.
var ErrNoHostBudget = errors.New("the tool sends requests to its targets and was started without a per-host budget")

// requireBudget refuses to start a tool whose traffic kind needs a budget
// the caller did not give, a tool whose manifest says it may reach any
// public host (network egress-proxy, its targets included) without one,
// and a tool that connects to its targets and is not listed: no tool
// reaches a target unpaced because its adapter forgot the budget.
func requireBudget(m tool.Manifest, o toolhost.RunOptions) error {
	noBudget := o.HostBudget == nil || !o.HostBudget.Valid()
	if m.Permissions.Network == tool.NetEgressProxy && noBudget {
		return fmt.Errorf("%s: %w", m.Name, ErrNoHostBudget)
	}
	kind, ok := TrafficOf(m.Name)
	if !ok {
		if m.Permissions.Network != tool.NetTargets {
			return nil
		}
		return fmt.Errorf("%s: the tool connects to its targets and has no traffic kind (internal/toolrun/traffic.go)", m.Name)
	}
	if (kind == TargetRequests || kind == TargetPackets) && noBudget {
		return fmt.Errorf("%s: %w", m.Name, ErrNoHostBudget)
	}
	if o.PortProbes != (kind == TargetPackets) {
		// Only a port scan is paced in packets per second: no other tool
		// may leave the budget's requests per second, and a port scan
		// must say what it is.
		return fmt.Errorf("%s: the tool's traffic kind and its port-probe pacing do not agree (internal/toolrun/traffic.go)", m.Name)
	}
	return nil
}

// BudgetFor is the budget handed to the tool host for one run: the scan's
// budget (Budget) as the task's own copy, with every value the scan asked
// for above it recorded (clamps: PacedLimits.Fit, the nuclei adapter), so
// the run's target_rate.budget.clamped and its log state what was asked
// and what applied.
func BudgetFor(b adapt.HostBudget, clamps []adapt.BudgetClamp) *adapt.HostBudget {
	out := b
	out.Clamped = append([]adapt.BudgetClamp(nil), b.Clamped...)
	for _, c := range clamps {
		out.Clamp(c.Key, c.Asked, c.To)
	}
	return &out
}

// CapRate lowers a tool's own rate setting to limit, the most the scan's
// host budget allows that tool (rate 0: the tool's default, def). A rate a
// person set above it is returned as a clamp, with what was asked and what
// applies; a default that was lowered is not one.
func CapRate(key string, rate, def, limit int) (int, []adapt.BudgetClamp) {
	effective := rate
	if effective <= 0 {
		effective = def
	}
	if effective <= limit {
		return rate, nil
	}
	if rate <= 0 {
		return limit, nil
	}
	return limit, []adapt.BudgetClamp{{Key: key, Asked: rate, To: limit, By: adapt.LimitHostBudget}}
}
