package svcdetect

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/contract/politeness"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// maxWorkers bounds the services probed at once (the per-host limit and
// the rate apply on top).
const maxWorkers = 32

// dial is how the tool connects (tests replace it to watch every dial).
var dial dialFunc = tool.Dial

// parseTarget reads a service target: "host:port/transport" with an
// explicit transport and port, never a URL or a range.
func parseTarget(t tool.Target) (*target, string, error) {
	tr := t.Transport()
	if tr == "" || strings.Contains(t.Value, "://") {
		return nil, "", errors.New("not a service (host:port/transport)")
	}
	host, port := t.Host(), t.Port()
	if host == "" || port <= 0 || port > 65535 {
		return nil, "", errors.New("not a service (host:port/transport)")
	}
	value, err := ctis.CanonicalService(host, port, tr)
	if err != nil {
		return nil, "", errors.New("not a service (host:port/transport)")
	}
	out := &target{t: t, host: host, port: uint16(port), value: value} //nolint:gosec // checked 1-65535 above
	if ip, err := netip.ParseAddr(host); err == nil {
		out.ip = ip.Unmap().WithZone("")
		out.host = out.ip.String()
	} else {
		out.host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	out.addr = net.JoinHostPort(out.host, fmt.Sprint(port))
	return out, tr, nil
}

// run is the tool's Run in the child.
func run(ctx tool.Context, task tool.Task, _ json.RawMessage) error {
	cfg, err := readConfig(task)
	if err != nil {
		return err
	}
	budget := BudgetFast
	if cfg.thorough {
		budget = BudgetThorough
	}
	d := &detector{
		dial:     dial,
		probes:   append(ownProbes(task.Identity, Manifest.Version), nervaProbes...),
		timeout:  time.Duration(cfg.timeoutMs) * time.Millisecond,
		thorough: cfg.thorough,
		budget:   budget,
	}
	sortProbes(d.probes)

	var queue []*target
	for _, t := range task.Targets {
		st, tr, err := parseTarget(t)
		switch {
		case err != nil:
			ctx.TargetSkipped(t, err.Error())
		case tr == "sctp":
			ctx.TargetSkipped(t, "sctp services are never probed")
		case tr == "udp" && !cfg.udp:
			ctx.TargetSkipped(t, "udp is opt-in (transports) and not requested")
		case tr == "udp":
			ctx.TargetSkipped(t, "udp is not probed by this version: the task's forwarder has no UDP route")
		case !cfg.ports.has(int(st.port)):
			ctx.TargetSkipped(t, "port not in the scan's ports")
		default:
			queue = append(queue, st)
		}
	}
	queue = interleaveByHost(queue)

	var (
		mu                             sync.Mutex
		identified, unknown, unreached int
		outputErr                      error
	)
	limiter := rate.NewLimiter(rate.Limit(cfg.rate), 1)
	hostSem := map[string]chan struct{}{}
	for _, t := range queue {
		k := politeness.HostOf(t.value)
		if hostSem[k] == nil {
			hostSem[k] = make(chan struct{}, HostConcurrency)
		}
	}
	jobs := make(chan *target)
	var wg sync.WaitGroup
	for range min(maxWorkers, max(1, len(queue))) {
		wg.Go(func() {
			for t := range jobs {
				sem := hostSem[politeness.HostOf(t.value)]
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					continue
				}
				r, err := d.detect(ctx, t)
				<-sem
				mu.Lock()
				switch {
				case ctx.Err() != nil:
				case err != nil:
					unreached++
					if errors.Is(err, tool.ErrEgressRefused) {
						ctx.TargetSkipped(t.t, "the task's forwarder refused the destination")
					} else {
						ctx.TargetError(t.t, tool.Unreachable(errors.New("the service did not accept a connection")))
					}
				case r == nil:
					unknown++
					ctx.TargetDone(t.t)
				default:
					identified++
					if err := ctx.Emit().Asset(asset(t, r)); err != nil {
						if errors.Is(err, tool.ErrOutputLimit) && outputErr == nil {
							outputErr = err
						} else {
							ctx.Log().Warn("svcdetect: a record was refused", "error", err.Error())
						}
					}
					ctx.TargetDone(t.t)
				}
				mu.Unlock()
			}
		})
	}
	for i, t := range queue {
		if outputErr != nil || limiter.Wait(ctx) != nil {
			break
		}
		ctx.Progress(i, len(queue), "")
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	ctx.Log().Info("svcdetect: done", "services", len(queue), "identified", identified, "unknown", unknown, "unreachable", unreached)
	if outputErr != nil {
		return outputErr
	}
	return ctx.Err()
}

// sortProbes orders probes by priority (stable).
func sortProbes(ps []*probe) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && ps[j].priority < ps[j-1].priority; j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
}

// interleaveByHost orders the services round-robin over their hosts, so a
// host with many open ports does not hold every worker.
func interleaveByHost(ts []*target) []*target {
	var hosts []string
	by := map[string][]*target{}
	for _, t := range ts {
		k := politeness.HostOf(t.value)
		if by[k] == nil {
			hosts = append(hosts, k)
		}
		by[k] = append(by[k], t)
	}
	out := make([]*target, 0, len(ts))
	for len(out) < len(ts) {
		for _, h := range hosts {
			if q := by[h]; len(q) > 0 {
				out = append(out, q[0])
				by[h] = q[1:]
			}
		}
	}
	return out
}

// asset is the CTIS service asset of an identified service: the same value
// as the input port.
func asset(t *target, r *result) ctis.Asset {
	svc := &ctis.ServiceTechnical{
		Port:               int(t.port),
		Transport:          ctis.TransportTCP,
		AppProtocol:        cleanText(r.protocol, maxKey),
		State:              ctis.PortOpen,
		Product:            cleanText(r.product, maxProduct),
		Version:            cleanText(r.version, maxVersion),
		CPE:                r.cpe,
		Banner:             cleanText(r.banner, MaxBanner),
		IsTLS:              r.tls,
		HasAnonymousAccess: r.anonymous,
	}
	if len(r.details) > 0 {
		svc.Details = map[string]string{}
		for _, raw := range slices.Sorted(maps.Keys(r.details)) {
			k := cleanKey(raw)
			if k == "" {
				continue
			}
			if len(svc.Details) == MaxDetails {
				break
			}
			svc.Details[k] = cleanText(r.details[raw], MaxDetailValue)
		}
	}
	return ctis.Asset{Type: ctis.AssetTypeService, Value: t.value, Technical: &ctis.AssetTechnical{Service: svc}}
}
