package nuclei

// Rate toward targets (RFC-074 in openctemio/openctem api/docs/rfcs,
// RFC-074-adaptive-sensor-control.md).
//
// nuclei does its own networking, so the adaptive per-host rate reaches it
// in two ways, the simplest that hold up:
//
//   - Its flags carry the ceiling: -rate-limit is the effective limit (the
//     scan's rate_limit, already lowered by scan windows, program rules and
//     the local policy, capped at SENSOR_NUCLEI_MAX_RATE_LIMIT), and that
//     same value is the task's RunOptions.TargetRate. In a confined run
//     every connection goes through the task forwarder, whose per-host
//     controller (sdk-go adapt.HostRate) paces each host below that ceiling
//     as it answers, so nuclei is never restarted to change its rate (a
//     restart would reload the templates and lose nuclei's per-host error
//     counts).
//   - -max-host-error is the bounds table's per-host error budget
//     (adapt.TargetRate.ToolHostErrors): nuclei's own host breaker. A host
//     nuclei skips for it ("Skipped <host> from target list as found
//     unresponsive ...") is a coverage gap of the run (breaker_open), read
//     from nuclei's log, so the run completes partial instead of reporting
//     "no findings" for that host. A silent run (-silent) does not log it;
//     the forwarder's own gaps still apply.

import (
	"regexp"
	"strings"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// unresponsiveLine matches nuclei's log line for a host its host breaker
// skipped.
var unresponsiveLine = regexp.MustCompile(`Skipped (\S{1,256}) from target list as found unresponsive( permanently)?`)

// maxGapHostLen bounds a host name read from nuclei's log.
const maxGapHostLen = 256

// coverageGaps returns the hosts nuclei skipped as unresponsive (once each,
// at most adapt.TargetRate.MaxGaps) and how many there were.
func coverageGaps(stderr string) ([]adapt.Gap, int) {
	if !strings.Contains(stderr, "unresponsive") {
		return nil, 0
	}
	seen := map[string]bool{}
	var gaps []adapt.Gap
	for _, m := range unresponsiveLine.FindAllStringSubmatch(stderr, -1) {
		host := m[1]
		if len(host) > maxGapHostLen || seen[host] {
			continue
		}
		seen[host] = true
		if len(gaps) < adapt.TargetRate.MaxGaps {
			detail := "nuclei skipped the host after its error budget"
			if m[2] != "" {
				detail = "nuclei skipped the host after a permanent error"
			}
			gaps = append(gaps, adapt.Gap{Host: host, Reason: adapt.GapBreakerOpen, Detail: detail})
		}
	}
	return gaps, len(seen)
}
