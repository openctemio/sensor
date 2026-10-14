package recon

// httpx in batch mode (research note 125 in openctem): one process over the
// whole target list instead of one per target. httpx isolates its targets
// itself: it probes them with its own concurrency, a host that does not
// answer costs its own per-request timeout and retries, and the run goes
// on. The per-target budget becomes httpx's per-request timeout. Each
// target is settled the moment httpx prints its first line (the task's
// progress moves while the run goes on); a target with no line when httpx
// exits gets an explicit outcome: failed when httpx finished, unfinished
// when the job stopped it.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/reachobs"
	"github.com/openctemio/sensor/internal/recon/httpx"
)

// listRun is what a batch run settled.
type listRun struct {
	failed       []failedTarget
	toolFailures int
	lastToolErr  error
	stopErr      error
	unfinished   []string
	obs          []reachobs.Obs
}

// listOptions are the options of a batch run: the scanner's, with the
// run's rate, concurrency and resolvers and the scan's own arguments, as
// each per-target run gets them.
func (s *Scanner) listOptions(rate, threads int, resolvers []string, opts *core.ScanOptions) core.ReconOptions {
	ro := s.Options
	ro.Target = ""
	ro.RateLimit = rate
	ro.Threads = threads
	ro.Resolvers = resolvers
	if opts != nil {
		ro.ExtraArgs = append(append([]string(nil), ro.ExtraArgs...), opts.ExtraArgs...)
		if len(opts.Env) > 0 {
			ro.Env = mergeEnv(ro.Env, opts.Env)
		}
		ro.Verbose = ro.Verbose || opts.Verbose
	}
	return ro
}

// errNoRecord: httpx finished without a line for the target (with -probe
// it prints one for every input it read).
var errNoRecord = errors.New("httpx printed no result for the target")

// runList runs targets through one httpx process; budget is the per-target
// budget (0: none). Results go into in.
func (s *Scanner) runList(ctx context.Context, hx *httpx.Scanner, targets []string, ro core.ReconOptions, budget time.Duration, in *ctis.ReconToCTISInput, settle settleFunc) listRun {
	index := make(map[string]int, len(targets))
	for i, t := range targets {
		if _, dup := index[t]; !dup {
			index[t] = i
		}
	}
	var mu sync.Mutex
	lines := make(map[int]*bytes.Buffer, len(targets))
	onLine := func(input string, line []byte) {
		i, ok := index[input]
		if !ok {
			return // not one of the job's targets: never settles anything
		}
		mu.Lock()
		b, seen := lines[i]
		if !seen {
			b = &bytes.Buffer{}
			lines[i] = b
		}
		b.Write(line)
		b.WriteByte('\n')
		mu.Unlock()
		if !seen {
			core.TargetDone(ctx, targets[i])
			if settle != nil {
				settle(i, nil)
			}
		}
	}
	res, err := hx.ScanList(ctx, targets, &ro, hx.RequestTimeout(budget), onLine)
	var lr listRun
	runErr := err
	if runErr == nil {
		runErr = runError(res)
	}
	stopped := ctx.Err()
	mu.Lock()
	defer mu.Unlock()
	for i, t := range targets {
		if index[t] != i {
			continue
		}
		if b, ok := lines[i]; ok {
			// Settled done at its first line; its lines are its result.
			if r, perr := hx.ResultFor(t, b.Bytes()); perr == nil {
				appendResult(in, r)
				lr.obs = append(lr.obs, hx.ReachObservations(t, r)...)
			}
			continue
		}
		if stopped != nil {
			lr.unfinished = append(lr.unfinished, t)
			continue
		}
		te := &targetError{err: errNoRecord}
		if runErr != nil {
			te.err = fmt.Errorf("%w (%w)", errNoRecord, runErr)
		}
		lr.failed = append(lr.failed, failedTarget{Target: t, Error: te.Error()})
		lr.toolFailures++
		lr.lastToolErr = te.err
		core.TargetDone(ctx, t)
		if settle != nil {
			settle(i, te)
		}
	}
	if stopped != nil {
		lr.stopErr = stopped
	}
	if in.ScannerVersion == "" {
		in.ScannerVersion = hx.Version()
	}
	return lr
}
