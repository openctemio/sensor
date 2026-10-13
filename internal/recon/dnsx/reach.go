package dnsx

import (
	"slices"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sensor/internal/reachobs"
)

// ReachObservations reads which of target's names did not resolve in this
// sensor's DNS view: a name dnsx printed no answer for, when the run asked
// for address records (a run that asked only for, say, TXT records says
// nothing about a name without them). A name that resolved says nothing
// about a path to it and is not recorded.
func (s *Scanner) ReachObservations(target string, res *core.ReconResult) []reachobs.Obs {
	if res == nil || res.ExitCode != 0 || res.Error != "" || !s.asksAddresses() {
		return nil
	}
	inputs, known := inputHosts(target, nil)
	if !known || len(inputs) == 0 {
		return nil
	}
	answered := answeredHosts(res.RawOutput)
	var out []reachobs.Obs
	for _, h := range inputs {
		if !answered[h] {
			out = append(out, reachobs.Obs{Target: h, Class: reach.DNSFailure, Detail: "no answer"})
		}
	}
	return out
}

// asksAddresses reports whether a run queries A or AAAA records (dnsx's
// default, and -recon).
func (s *Scanner) asksAddresses() bool {
	if s.QueryAll || len(s.RecordTypes) == 0 {
		return true
	}
	return slices.ContainsFunc(s.RecordTypes, func(rt string) bool {
		rt = strings.ToUpper(strings.TrimSpace(rt))
		return rt == "A" || rt == "AAAA"
	})
}
