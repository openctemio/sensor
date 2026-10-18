package nuclei

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"

	"github.com/openctemio/sensor/internal/egressenv"
)

// Limits of the custom-template run (organization content the sensor did
// not author; api research/185 §4.6).

// customCPUPerWallSecond is how many CPU seconds the custom-template run may
// use per second of its timeout: a run that keeps more than two cores busy
// for its whole time is a template looping, not scanning.
const customCPUPerWallSecond = 2

// maxResolvedTargets bounds the names resolved to decide on -lna.
const maxResolvedTargets = 256

// resolveTimeout bounds that resolution.
const resolveTimeout = 3 * time.Second

// lookupHost resolves a target name (a variable so tests can replace it).
var lookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) { //nolint:gochecknoglobals // test seam
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// cgnat is the shared address space (RFC 6598), local to a provider's
// network.
var cgnat = netip.MustParsePrefix("100.64.0.0/10") //nolint:gochecknoglobals // static

// customLimits are the custom-template run's resource limits: a CPU-time
// cap derived from its timeout, on top of the sandbox's defaults.
func (s *Scanner) customLimits() executor.Limits {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	secs := timeout.Seconds() * customCPUPerWallSecond
	if secs > math.MaxInt32 {
		secs = math.MaxInt32
	}
	l := executor.DefaultLimits()
	l.CPUSeconds = uint64(math.Ceil(secs))
	return l
}

// customLocalNetworkArgs is -lna (no connections to loopback, private or
// link-local addresses) for the custom-template run of a task that is not
// confined to its egress forwarder, so a custom template cannot reach the
// sensor host's own services, the cloud metadata endpoint or neighbours
// through a hard-coded address. A confined task needs none: its forwarder
// already refuses everything outside the job's targets. When a target is
// itself on a local network (an internal scan), -lna would block the scan,
// so it is left off and the run is logged as such.
func (s *Scanner) customLocalNetworkArgs(ctx context.Context, target, listFile string) []string {
	if s.webScoped || egressenv.Confined() {
		return nil
	}
	hosts := targetHosts(target, listFile, s.TargetFile)
	if host, local := anyLocal(ctx, hosts); local {
		fmt.Fprintf(os.Stderr, "[nuclei] custom templates run without local-network restriction: target %q is on a local network; turn on network confinement to restrict them\n", host)
		return nil
	}
	return []string{"-lna"}
}

// targetHosts lists the host of each target of the run.
func targetHosts(target, listFile, targetFile string) []string {
	var raw []string
	switch {
	case target != "":
		raw = []string{target}
	case listFile != "" || targetFile != "":
		f := listFile
		if f == "" {
			f = targetFile
		}
		fh, err := os.Open(f) //nolint:gosec // the run's own target list
		if err != nil {
			return nil
		}
		defer func() { _ = fh.Close() }()
		sc := bufio.NewScanner(fh)
		for sc.Scan() && len(raw) < MaxListTargets {
			if l := strings.TrimSpace(sc.Text()); l != "" {
				raw = append(raw, l)
			}
		}
	}
	hosts := make([]string, 0, len(raw))
	for _, t := range raw {
		if h := hostOf(t); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// hostOf is the host of a URL, host:port, host or address target.
func hostOf(t string) string {
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	if p, err := netip.ParsePrefix(t); err == nil {
		return p.Addr().String()
	}
	return strings.Trim(t, "[]")
}

// anyLocal reports the first host that is, or resolves to, a local
// address. A name that does not resolve counts as not local (nuclei could
// not reach it either).
func anyLocal(ctx context.Context, hosts []string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	resolved := 0
	for _, h := range hosts {
		if strings.EqualFold(h, "localhost") {
			return h, true
		}
		if a, err := netip.ParseAddr(h); err == nil {
			if isLocal(a) {
				return h, true
			}
			continue
		}
		if resolved >= maxResolvedTargets || ctx.Err() != nil {
			continue
		}
		resolved++
		addrs, err := lookupHost(ctx, h)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if isLocal(a) {
				return h, true
			}
		}
	}
	return "", false
}

func isLocal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || cgnat.Contains(a)
}
