// Package reachobs carries what the sensor's tools saw while trying to
// reach a job's targets (an answer, a closed port, no route, a timeout, a
// name that does not resolve) to the job's reach recorder (sdk-go
// pkg/reach), so the command result says which targets were not reached
// instead of reading them as "nothing found". Design: api RFC-089,
// docs/rfcs/RFC-089-reachability-aware-routing.md in openctemio/openctem.
//
// A tool that runs in this process records into the job's recorder (Record).
// A tool that runs in the tool child (another process, no recorder) attaches
// its observations to its report (Attach); the sensor takes them off the
// report (Take) and records them. Either way Record keeps only outcomes
// toward the job's own targets: a tool's output never names a target, or an
// address outside an address target, into the result.
package reachobs

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// Property is the report property a tool child's observations travel in.
// The sensor removes it before the report goes anywhere.
const Property = "reach_observations"

const (
	// maxAttachBytes bounds the observations a report carries: the tool
	// runtime refuses report info over 64 KiB, which would drop the
	// report's other properties with it.
	maxAttachBytes = 16 << 10
	// maxTake bounds the observations read back from a report.
	maxTake = 1024
	// maxDetail bounds an observation's detail.
	maxDetail = 64
)

// Obs is one outcome toward a job target.
type Obs struct {
	// Target is the job target as the tool was given it.
	Target string `json:"t"`
	// Addr is the address the tool reached or tried ("" unknown).
	Addr string `json:"a,omitempty"`
	// Port is the port (0 unknown).
	Port int `json:"p,omitempty"`
	// Class is the outcome (reach.Class).
	Class reach.Class `json:"c"`
	// Detail is a short reason for a target not reached.
	Detail string `json:"d,omitempty"`
}

// toolText maps messages the tools print that the SDK's table does not
// name (lower case).
var toolText = []struct {
	class   reach.Class
	needles []string
}{
	// httpx and nuclei (fastdialer): a name with no address.
	{reach.DNSFailure, []string{"no address found for host", "could not resolve host"}},
	// naabu: a name target that does not resolve.
	{reach.DNSFailure, []string{"no valid ipv4 or ipv6 targets"}},
}

// Classify maps a tool's failure text toward a target to its class
// (reach.Unknown when it names none).
func Classify(msg string) reach.Class {
	lower := strings.ToLower(msg)
	for _, tc := range toolText {
		for _, n := range tc.needles {
			if strings.Contains(lower, n) {
				return tc.class
			}
		}
	}
	return reach.ClassifyText(msg)
}

// Detail is a short reason from a tool's failure text: its last
// colon-separated part ("dial tcp 10.0.0.5:443: connect: no route to
// host" is "no route to host"), so addresses, URLs and anything else the
// message carried are left out.
func Detail(msg string) string {
	if i := strings.LastIndexByte(msg, ':'); i >= 0 {
		msg = msg[i+1:]
	}
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(msg))
	if len(msg) > maxDetail {
		cut := maxDetail
		for cut > 0 && msg[cut]&0xC0 == 0x80 {
			cut--
		}
		msg = msg[:cut]
	}
	return msg
}

// Failure is the observation of a run that failed on target with msg (ok
// false when the message names no reach outcome).
func Failure(target, msg string) (Obs, bool) {
	c := Classify(msg)
	if !c.Valid() {
		return Obs{}, false
	}
	return Obs{Target: target, Class: c, Detail: Detail(msg)}, true
}

// Attach puts obs on r for the sensor to take back (Take), unreached
// outcomes first and within a size bound: what does not fit is left out.
func Attach(r *ctis.Report, obs []Obs) {
	if r == nil || len(obs) == 0 {
		return
	}
	sorted := dedupe(obs)
	out := make([]Obs, 0, len(sorted))
	size := 2
	for _, o := range sorted {
		b, err := json.Marshal(o)
		if err != nil {
			continue
		}
		if size+len(b)+1 > maxAttachBytes {
			break
		}
		size += len(b) + 1
		out = append(out, o)
	}
	if len(out) == 0 {
		return
	}
	if r.Properties == nil {
		r.Properties = ctis.Properties{}
	}
	r.Properties[Property] = out
}

// dedupe keeps the best outcome per (target, address, port class), the
// unreached ones first: one host's many open ports are one observation.
func dedupe(obs []Obs) []Obs {
	type key struct{ target, addr, portClass string }
	best := map[key]Obs{}
	var order []key
	for _, o := range obs {
		if !o.Class.Valid() {
			continue
		}
		k := key{o.Target, o.Addr, reach.PortClass(o.Port)}
		prev, ok := best[k]
		if !ok {
			order = append(order, k)
		}
		if !ok || better(o.Class, prev.Class) {
			best[k] = o
		}
	}
	out := make([]Obs, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Class.Unreached() && !out[j].Class.Unreached()
	})
	return out
}

// better reports whether a is a better outcome than b (reach's order:
// a target that answered once was reached).
func better(a, b reach.Class) bool {
	return classRank(a) > classRank(b)
}

func classRank(c reach.Class) int {
	for i, k := range reach.Classes {
		if c == k {
			return len(reach.Classes) - i
		}
	}
	return 0
}

// Take removes the observations from r and returns them (at most maxTake).
// A property that does not decode is dropped all the same.
func Take(r *ctis.Report) []Obs {
	if r == nil || r.Properties == nil {
		return nil
	}
	v, ok := r.Properties[Property]
	if !ok {
		return nil
	}
	delete(r.Properties, Property)
	if len(r.Properties) == 0 {
		r.Properties = nil
	}
	if obs, ok := v.([]Obs); ok {
		return obs[:min(len(obs), maxTake)]
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var obs []Obs
	if err := json.Unmarshal(b, &obs); err != nil {
		return nil
	}
	return obs[:min(len(obs), maxTake)]
}

// Record records obs into the job's recorder (ctx's; none: nothing) and
// returns how many it kept. Only outcomes toward one of targets count,
// recorded under that target; an address is kept only inside an address or
// range target, or, for a name target, when it is a routable unicast
// address.
func Record(ctx context.Context, targets []string, obs []Obs) int {
	rec := reach.FromContext(ctx)
	if rec == nil || len(obs) == 0 || len(targets) == 0 {
		return 0
	}
	index := make(map[string]string, len(targets))
	for _, t := range targets {
		if k := hostKey(t); k != "" {
			if _, dup := index[k]; !dup {
				index[k] = t
			}
		}
	}
	kept := 0
	for _, o := range obs {
		if !o.Class.Valid() {
			continue
		}
		target, ok := matchTarget(targets, index, o.Target)
		if !ok {
			continue
		}
		port := o.Port
		if port < 0 || port > 65535 {
			port = 0
		}
		rec.Record(reach.Observation{
			Target: target,
			Addr:   admittedAddr(target, o.Addr),
			Port:   port,
			Class:  o.Class,
			Detail: Detail(o.Detail),
		})
		kept++
	}
	return kept
}

// matchTarget returns the job target obs names: the same string, or the
// same host.
func matchTarget(targets []string, index map[string]string, name string) (string, bool) {
	for _, t := range targets {
		if t == name {
			return t, true
		}
	}
	t, ok := index[hostKey(name)]
	return t, ok && t != ""
}

// admittedAddr is a, when it may be reported for target (invalid
// otherwise): inside an address or range target, or a routable unicast
// address for a name.
func admittedAddr(target, a string) netip.Addr {
	addr, err := netip.ParseAddr(strings.Trim(a, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	addr = addr.Unmap()
	if addr.Zone() != "" {
		return netip.Addr{}
	}
	if p, err := netip.ParsePrefix(target); err == nil {
		if p.Masked().Contains(addr) {
			return addr
		}
		return netip.Addr{}
	}
	h := hostKey(target)
	if ta, err := netip.ParseAddr(h); err == nil {
		if ta.Unmap() == addr {
			return addr
		}
		return netip.Addr{}
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() {
		return netip.Addr{}
	}
	return addr
}

// hostKey is the host of a target (a name, an address, host:port or a
// URL), lower case without a trailing dot or brackets; a range is itself.
func hostKey(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if p, err := netip.ParsePrefix(t); err == nil {
		return p.Masked().String()
	}
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Host != "" {
			t = u.Hostname()
		}
	} else if a, err := netip.ParseAddrPort(t); err == nil {
		t = a.Addr().String()
	} else if i := strings.LastIndexByte(t, ':'); i > 0 && strings.Count(t, ":") == 1 {
		t = t[:i]
	}
	t = strings.TrimSuffix(strings.ToLower(strings.Trim(t, "[]")), ".")
	if a, err := netip.ParseAddr(t); err == nil {
		return a.Unmap().String()
	}
	return t
}
