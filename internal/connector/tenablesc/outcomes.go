package tenablesc

import (
	"net/netip"
	"strings"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// Per-target outcomes of a connector_scan (ctis outcome): which of the
// command's targets the Tenable.sc scan assessed, which did not reply, and
// which it never finished. The platform settles the targets from them (the
// coverage ledger keeps "assessed, nothing found" apart from "not scanned"),
// and normalizes them against the command's own targets, so nothing here can
// add a target.

// maxAssessedHosts bounds the hosts one scan pull remembers for outcomes.
const maxAssessedHosts = 1 << 20

// unreachableDetail is the reach detail of a target the scan did not hear.
const unreachableDetail = "no reply to the Tenable.sc scan"

// assessedHosts are the hosts a scan result lists (any severity, so a live
// host with only the scan-information plugin counts). nil records nothing.
type assessedHosts struct {
	ips   map[netip.Addr]struct{}
	names map[string]struct{}
}

func newAssessedHosts() *assessedHosts {
	return &assessedHosts{ips: map[netip.Addr]struct{}{}, names: map[string]struct{}{}}
}

// add records one host row's address and DNS name (either may be empty or
// malformed; such values are ignored).
func (a *assessedHosts) add(ip, dnsName string) {
	if a == nil || len(a.ips)+len(a.names) >= maxAssessedHosts {
		return
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
		a.ips[addr.Unmap()] = struct{}{}
	}
	if n := normalizeHostName(dnsName); n != "" {
		a.names[n] = struct{}{}
	}
}

// covers reports whether the scan assessed target (a normalized job
// target): an address it listed, a range holding one, or a host name it
// listed.
func (a *assessedHosts) covers(target string) bool {
	if a == nil {
		return false
	}
	if pfx, err := netip.ParsePrefix(target); err == nil {
		for ip := range a.ips {
			if pfx.Contains(ip) {
				return true
			}
		}
		return false
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		_, ok := a.ips[addr.Unmap()]
		return ok
	}
	_, ok := a.names[normalizeHostName(target)]
	return ok
}

func normalizeHostName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || len(s) > maxHostnameLen || !scanHostnameRE.MatchString(s) {
		return ""
	}
	return s
}

// outcomeCounts are the counts reported in the command metadata.
type outcomeCounts struct {
	assessed, unreachable, unfinished int
}

// targetOutcomes names each job target's outcome by its payload spelling:
// assessed → done (reached); not listed by a scan that completed and was
// imported → failed unreachable (a dead host, never "nothing found");
// otherwise unfinished. Reach observations go to rec (nil: none).
func targetOutcomes(job *scanJob, hosts *assessedHosts, complete bool, rec *reach.Recorder) ([]outcome.Target, outcomeCounts) {
	out := make([]outcome.Target, 0, len(job.targets))
	var n outcomeCounts
	for _, t := range job.targets {
		raw := job.payloadTarget(t)
		switch {
		case hosts.covers(t):
			out = append(out, outcome.Target{Target: raw, State: outcome.Done})
			n.assessed++
			if rec != nil {
				rec.Record(reach.Observation{Target: raw, Class: reach.Reached})
			}
		case complete:
			out = append(out, outcome.Target{Target: raw, State: outcome.Failed, Class: outcome.Unreachable})
			n.unreachable++
			if rec != nil {
				rec.Record(reach.Observation{Target: raw, Class: reach.Timeout, Detail: unreachableDetail})
			}
		default:
			out = append(out, outcome.Target{Target: raw, State: outcome.Unfinished})
			n.unfinished++
		}
	}
	return out, n
}
