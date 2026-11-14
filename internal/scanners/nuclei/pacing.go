package nuclei

// The pacing level mapped to nuclei's flags (toolrun.Pacing; research 518,
// decision D1). nuclei's -rate-limit is global to the process and nuclei has
// no per-host rate, so a host's share is set through the job's host count:
//
//   - -rate-limit: the level's per-host rate times the hosts worked at once
//     (adapt.Pacing.JobRate: 20/s for one host, at most 160/s for 8 or more);
//   - -c: the level's requests in flight per host (8): with one template
//     per worker, that is how many requests one host gets at once;
//   - -bs: the job's hosts, at most 25 (adapt.Pacing.BulkHosts);
//   - -mhe: the level's host error budget (15);
//   - -timeout and -retries: the level's (10 s, 1);
//   - -ss template-spray when the job has more than one host, so each
//     template moves across the hosts and no host takes the whole rate.
//
// A value a person set in a settings layer (tenant, sensor, profile, scan)
// or in the sensor's scanner config replaces the level's for that flag.
// The job's caps (scan windows, program rules), the local policy and the
// operator's ceilings (SENSOR_NUCLEI_MAX_*) cap the result in every case.

import (
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sensor/internal/toolrun"
)

// chosenLimits says which of nuclei's pacing flags a person chose (a
// settings layer or the scanner's config); the others follow the level.
type chosenLimits struct {
	Rate        bool `json:"rate,omitempty"`
	Concurrency bool `json:"concurrency,omitempty"`
	Bulk        bool `json:"bulk,omitempty"`
	HostErrors  bool `json:"host_errors,omitempty"`
	Strategy    bool `json:"strategy,omitempty"`
	Timeout     bool `json:"timeout,omitempty"`
}

// hosts is how many distinct hosts the run covers (at least 1).
func (s *Scanner) hosts() int { return max(s.jobHosts, 1) }

// forTargets is a copy of the scanner for a run over targets: the pacing
// flags depend on how many distinct hosts the list names.
func (s *Scanner) forTargets(targets []string) *Scanner {
	c := *s
	c.jobHosts = distinctHosts(targets)
	return &c
}

// distinctHosts counts the distinct hosts of targets (URLs, host:port,
// names or addresses); a target whose host cannot be read counts as its own.
func distinctHosts(targets []string) int {
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		h := reach.HostOf(t)
		if h == "" {
			h = t
		}
		seen[h] = struct{}{}
	}
	return len(seen)
}

// pacedLimits lowers the rate, concurrency and bulk size a person did not
// choose to the level's values for the run's host count.
func (s *Scanner) pacedLimits(rate, concurrency, bulk int) (int, int, int) {
	p := toolrun.Pacing()
	if !s.chosen.Rate {
		rate = min(rate, p.JobRate(s.hosts()))
	}
	if !s.chosen.Concurrency {
		concurrency = min(concurrency, p.TargetInflight)
	}
	if !s.chosen.Bulk {
		bulk = min(bulk, p.BulkHosts(s.hosts()))
	}
	return rate, concurrency, bulk
}

// hostErrors is the -mhe value: the person's, else the level's budget.
func (s *Scanner) hostErrors() int {
	if s.chosen.HostErrors && s.MaxHostErrors > 0 {
		return s.MaxHostErrors
	}
	return toolrun.Pacing().HostErrorBudget
}

// requestTimeout is the -timeout value in seconds: the person's, else the
// lower of the resolved value (a job's budget may shorten it) and the
// level's.
func (s *Scanner) requestTimeout() int {
	lvl := int(toolrun.Pacing().RequestTimeout.Seconds())
	switch {
	case s.chosen.Timeout && s.RequestTimeout > 0:
		return s.RequestTimeout
	case s.RequestTimeout > 0:
		return min(s.RequestTimeout, lvl)
	}
	return lvl
}

// scanStrategy is the -ss value ("" passes none): the person's, else
// template-spray for a run over several hosts.
func (s *Scanner) scanStrategy() string {
	if s.chosen.Strategy || (s.ScanStrategy != "" && s.ScanStrategy != "auto") {
		if s.ScanStrategy == "auto" {
			return ""
		}
		return s.ScanStrategy
	}
	if s.hosts() > 1 {
		return "template-spray"
	}
	return ""
}

// retries is the -retries value: the person's (or the scanner's config,
// when above one), else the level's.
func (s *Scanner) retries() int {
	if s.retriesSet || s.Retries > 1 {
		return s.Retries
	}
	return toolrun.Pacing().Retries
}

// ChooseLimits marks the scanner's RateLimit and Concurrency as an
// operator's choice (the sensor's scanner config), so they replace the
// pacing level's values instead of being lowered to them.
func (s *Scanner) ChooseLimits(rate, concurrency bool) {
	s.chosen.Rate = s.chosen.Rate || rate
	s.chosen.Concurrency = s.chosen.Concurrency || concurrency
}

// withChosen is a copy of the scanner that knows which pacing flags a
// person chose for this scan (toolrun.Chosen); the scanner's own config
// choices stay.
func (s *Scanner) withChosen(opts *core.ScanOptions) *Scanner {
	c := *s
	c.chosen = chosenLimits{
		Rate:        s.chosen.Rate || toolrun.Chosen(opts, "rate_limit"),
		Concurrency: s.chosen.Concurrency || toolrun.Chosen(opts, "concurrency"),
		Bulk:        s.chosen.Bulk || toolrun.Chosen(opts, "bulk_size"),
		HostErrors:  toolrun.Chosen(opts, "max_host_errors"),
		Strategy:    toolrun.Chosen(opts, "scan_strategy"),
		Timeout:     toolrun.Chosen(opts, "timeout"),
	}
	return &c
}
