package dnsx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/resolv"
)

// System-resolver fallback.
//
// dnsx resolves only through its built-in public resolvers (or the -r list),
// so a name that only the sensor's network knows (an internal zone, a Docker
// or Kubernetes service name) never resolved, while httpx, naabu (-sr) and
// nuclei reached the same host. dnsx has no flag to fall back to the host's
// resolver, so the scanner does it: the hosts the first run did not resolve
// are queried once more through the nameservers in /etc/resolv.conf. Names
// the public resolvers answer keep their public answer.
//
// The daemon now runs dnsx through the sensor's resolvers in the first place
// (recon.Scanner, internal/recon/internal/resolv), so the fallback applies
// only when the first run used another list.

// resolvConfPath is the resolver configuration the fallback reads.
var resolvConfPath = "/etc/resolv.conf"

// maxFallbackInputBytes bounds how much of an input list file is read to
// find the unresolved hosts. A larger list skips the fallback.
const maxFallbackInputBytes = 16 << 20

// inputHosts returns the hosts a run was asked to resolve, normalized, in
// order and deduplicated: the input list file when there is one, else the
// comma-separated target. ok is false when they cannot be known (the file is
// unreadable or too large).
func inputHosts(target string, opts *core.ReconOptions) (hosts []string, ok bool) {
	var raw []string
	if opts != nil && opts.InputFile != "" {
		f, err := os.Open(opts.InputFile)
		if err != nil {
			return nil, false
		}
		defer func() { _ = f.Close() }()
		data, err := io.ReadAll(io.LimitReader(f, maxFallbackInputBytes+1))
		if err != nil || len(data) > maxFallbackInputBytes {
			return nil, false
		}
		raw = strings.Split(string(data), "\n")
	} else {
		raw = strings.Split(target, ",")
	}
	seen := map[string]bool{}
	for _, h := range raw {
		h = normalizeHost(h)
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts, true
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// answeredHosts returns the hosts dnsx printed a JSON answer for.
func answeredHosts(stdout []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		var line struct {
			Host string `json:"host"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil && line.Host != "" {
			out[normalizeHost(line.Host)] = true
		}
	}
	return out
}

// unresolvedHosts returns the input hosts the first run did not answer.
func unresolvedHosts(inputs []string, stdout []byte) []string {
	answered := answeredHosts(stdout)
	var out []string
	for _, h := range inputs {
		if !answered[h] {
			out = append(out, h)
		}
	}
	return out
}

// extraArgsSetResolvers reports whether the extra arguments pick the
// resolvers themselves; the fallback then stays out of the way.
func extraArgsSetResolvers(opts *core.ReconOptions) bool {
	if opts == nil {
		return false
	}
	for _, a := range opts.ExtraArgs {
		name := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
		switch name {
		case "r", "resolver", "rL":
			return true
		}
	}
	return false
}

// fallbackPlan returns the scanner and options of the system-resolver run
// for the hosts the first run left unresolved, or ok=false when there is
// nothing to do. The caller removes cleanup's file.
func (s *Scanner) fallbackPlan(target string, opts *core.ReconOptions, stdout []byte) (fb *Scanner, fbOpts *core.ReconOptions, cleanup func(), ok bool) {
	if extraArgsSetResolvers(opts) {
		return nil, nil, nil, false
	}
	sys := resolv.System(resolvConfPath)
	if len(sys) == 0 || slices.Equal(sys, s.resolvers(opts)) {
		return nil, nil, nil, false
	}
	inputs, known := inputHosts(target, opts)
	if !known {
		return nil, nil, nil, false
	}
	missing := unresolvedHosts(inputs, stdout)
	if len(missing) == 0 {
		return nil, nil, nil, false
	}
	file, err := writeTempFile(missing)
	if err != nil {
		return nil, nil, nil, false
	}

	cp := *s
	cp.Resolvers = sys
	cp.OutputFile = "" // the first run owns the output file
	o := core.ReconOptions{}
	if opts != nil {
		o = *opts
	}
	o.Resolvers = nil
	o.InputFile = file
	return &cp, &o, func() { removeTempFile(file) }, true
}

// resolvers is the -r list of a run.
func (s *Scanner) resolvers(opts *core.ReconOptions) []string {
	if opts != nil && len(opts.Resolvers) > 0 {
		return opts.Resolvers
	}
	return s.Resolvers
}
