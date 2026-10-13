package naabu

import (
	"net/netip"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sensor/internal/reachobs"
)

// ReachObservations reads what naabu saw toward target: each open port was
// reached. naabu prints nothing for a closed, filtered or unroutable port,
// so a host with no open port is not recorded either way ("no open ports"
// is not "reached"); a run that failed on the target is classified by its
// error (recon.Scanner).
func (s *Scanner) ReachObservations(target string, res *core.ReconResult) []reachobs.Obs {
	if res == nil {
		return nil
	}
	out := make([]reachobs.Obs, 0, len(res.OpenPorts))
	for _, p := range res.OpenPorts {
		addr := p.IP
		if addr == "" {
			if _, err := netip.ParseAddr(p.Host); err == nil {
				addr = p.Host
			}
		}
		out = append(out, reachobs.Obs{Target: target, Addr: addr, Port: p.Port, Class: reach.Reached})
	}
	return out
}
