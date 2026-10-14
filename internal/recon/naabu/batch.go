package naabu

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// ScanBatch scans every target in one naabu run (-l): naabu's workers,
// rate and per-probe timeout apply across the whole list, and an
// unresolvable or silent host costs only its own probes. Each open port is
// attributed to the input target it belongs to: the target naming its host,
// the target that is its address, or the range target that contains it. A
// record that belongs to no target is dropped (naabu scans only what it is
// given; anything else is not reported). A target with no open port has no
// entry: naabu prints nothing for it.
func (s *Scanner) ScanBatch(ctx context.Context, targets []string, opts *core.ReconOptions) (map[string]*core.ReconResult, error) {
	start := time.Now()
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	f, err := os.CreateTemp("", "naabu-targets-*.txt") // created 0600
	if err != nil {
		return nil, fmt.Errorf("create target list: %w", err)
	}
	list := f.Name()
	defer os.Remove(list) //nolint:errcheck // best-effort cleanup
	if _, err := f.WriteString(strings.Join(targets, "\n") + "\n"); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write target list: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("write target list: %w", err)
	}
	o := core.ReconOptions{}
	if opts != nil {
		o = *opts
	}
	o.InputFile = list
	args := s.buildArgs("", &o)

	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}
	// No process timeout of its own unless the operator set one: the job's
	// context bounds the run.
	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		Timeout: s.Timeout,
		Verbose: s.Verbose,
	})
	if err != nil {
		return nil, err
	}
	ports, err := s.parseOutput(execResult.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse naabu output: %w", err)
	}
	finished := time.Now()
	out := map[string]*core.ReconResult{}
	attr := newAttributor(targets)
	for _, p := range ports {
		t, ok := attr.target(p)
		if !ok {
			continue
		}
		r := out[t]
		if r == nil {
			r = &core.ReconResult{
				ScannerName:    s.Name(),
				ScannerVersion: s.version,
				ReconType:      s.Type(),
				Target:         t,
				StartedAt:      start.Unix(),
				FinishedAt:     finished.Unix(),
				DurationMs:     finished.Sub(start).Milliseconds(),
				ExitCode:       execResult.ExitCode,
			}
			out[t] = r
		}
		r.OpenPorts = append(r.OpenPorts, p)
	}
	if len(ports) == 0 && execResult.ExitCode != 0 {
		return out, fmt.Errorf("naabu exited %d: %s", execResult.ExitCode, lastLine(execResult.Stderr))
	}
	return out, nil
}

// attributor maps an open port back to the input target it came from.
type attributor struct {
	names    map[string]string // lower-case host name or canonical address -> target
	prefixes []prefixTarget
}

type prefixTarget struct {
	prefix netip.Prefix
	target string
}

func newAttributor(targets []string) *attributor {
	a := &attributor{names: map[string]string{}}
	for _, t := range targets {
		v := strings.TrimSpace(t)
		if p, err := netip.ParsePrefix(v); err == nil {
			a.prefixes = append(a.prefixes, prefixTarget{prefix: p.Masked(), target: t})
			continue
		}
		key := hostKey(v)
		if _, dup := a.names[key]; !dup {
			a.names[key] = t
		}
	}
	return a
}

func (a *attributor) target(p core.OpenPort) (string, bool) {
	if t, ok := a.names[hostKey(p.Host)]; ok {
		return t, true
	}
	ipText := p.IP
	if ipText == "" {
		ipText = p.Host
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	if t, ok := a.names[ip.String()]; ok {
		return t, true
	}
	for _, pt := range a.prefixes {
		if pt.prefix.Contains(ip) {
			return pt.target, true
		}
	}
	return "", false
}

// hostKey is a host's comparison key: a canonical address, or the
// lower-case name without a trailing dot.
func hostKey(h string) string {
	h = strings.TrimSpace(h)
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.Unmap().String()
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func lastLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
