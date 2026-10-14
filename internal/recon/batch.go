package recon

import (
	"context"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
)

// batchTool is a recon tool that scans a whole target list in one run with
// its own concurrency, rate limit and per-probe timeouts, and attributes each
// record to the input target it came from. One process for the list keeps
// the tool's native power: its workers stay busy across hosts, and one slow
// or dead host costs only its own probes' timeouts, never a process start
// per target or a sequence of per-target kills.
//
// ScanBatch returns the result of every target it has output for (a target
// with no record, e.g. a host with no open port, may be absent). err is a
// failure of the run itself (the tool could not start, or exited with an
// error and no output); the results it returns are still those it read.
type batchTool interface {
	core.ReconScanner
	ScanBatch(ctx context.Context, targets []string, opts *core.ReconOptions) (map[string]*core.ReconResult, error)
}

// settleFn records one target's outcome (scanTargets' settleTarget).
type settleFn func(i int, t string, ro *core.ReconOptions, res *core.ReconResult, err error, timedOut bool)

// runBatch runs the whole list through bt and settles every target once
// the run ends. A run the job's end stopped settles the targets it has
// records for and returns the others as unfinished; a run that failed as a
// whole fails every target it has no record for (a tool-level failure, so
// a run that failed on every target fails the job).
func runBatch(ctx context.Context, bt batchTool, targets []string, ro core.ReconOptions, settle settleFn) (stopErr error, unfinished []string) {
	// The per-target budget is not a kill in a batch: it cannot tell which
	// target is slow. The tool's own per-probe timeout bounds each target,
	// the job's context bounds the run.
	ro.Timeout = 0
	results, runErr := bt.ScanBatch(ctx, targets, &ro)
	stopErr = ctx.Err()
	for i, t := range targets {
		res, ok := results[t]
		switch {
		case ok:
			settle(i, t, &ro, res, nil, false)
		case stopErr != nil:
			unfinished = append(unfinished, t)
		case runErr != nil:
			settle(i, t, &ro, nil, fmt.Errorf("%s: %w", bt.Name(), runErr), false)
		default:
			// The run completed and printed nothing for the target: an
			// outcome, not a failure.
			settle(i, t, &ro, &core.ReconResult{ScannerName: bt.Name(), ReconType: bt.Type(), Target: t}, nil, false)
		}
	}
	return stopErr, unfinished
}
