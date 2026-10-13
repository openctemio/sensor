package httpx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sensor/internal/reachobs"
)

// ReachObservations reads what httpx saw toward target from its output: a
// URL that answered was reached (any HTTP response); one that did not
// (-probe's "failed" lines) is classified by httpx's reason (no route,
// timeout, connection refused, no address for the name). A reason that
// names no network outcome is left out.
func (s *Scanner) ReachObservations(target string, res *core.ReconResult) []reachobs.Obs {
	if res == nil || len(res.RawOutput) == 0 {
		return nil
	}
	var out []reachobs.Obs
	sc := bufio.NewScanner(bytes.NewReader(res.RawOutput))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var o HTTPXOutput
		if err := json.Unmarshal(line, &o); err != nil {
			continue
		}
		obs := reachobs.Obs{Target: target, Addr: o.HostIP, Port: urlPort(o)}
		if obs.Addr == "" && len(o.A) > 0 {
			obs.Addr = o.A[0]
		}
		if o.Failed {
			c := reachobs.Classify(o.Error)
			if !c.Valid() {
				continue
			}
			obs.Class, obs.Detail = c, reachobs.Detail(o.Error)
		} else {
			obs.Class = reach.Reached
		}
		out = append(out, obs)
	}
	return out
}

// urlPort is the port httpx reported, or the one its URL names (the
// scheme's default without one); 0 when unknown.
func urlPort(o HTTPXOutput) int {
	if p, err := strconv.Atoi(o.Port); err == nil && p > 0 && p < 65536 {
		return p
	}
	u, err := url.Parse(o.URL)
	if err != nil {
		return 0
	}
	if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 && p < 65536 {
		return p
	}
	switch u.Scheme {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}
