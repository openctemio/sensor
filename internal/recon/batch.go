package recon

import (
	"context"
	"fmt"
	"time"

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
// with no record, e.g. a host with no open port, may be absent; a result
// with Error set fails that target). err is a failure of the run itself
// (the tool could not start, or exited with an error and no output); the
// results it returns are still those it read.
//
// budget is the platform's per-target budget (0: none): never a kill, at
// most the tool's own per-probe timeout. seen, called as the run goes, says
// a target's first record arrived: a tool whose records stream (httpx's
// JSON lines) settles that target at once, so the task's progress moves
// during the run. seen must only name targets of the list; a tool that
// reads its output at the end never calls it.
type batchTool interface {
	core.ReconScanner
	ScanBatch(ctx context.Context, targets []string, opts *core.ReconOptions, budget time.Duration, seen func(target string)) (map[string]*core.ReconResult, error)
}

// settleFn records one target's outcome (scanTargets' settleTarget).
type settleFn func(i int, t string, ro *core.ReconOptions, res *core.ReconResult, err error, timedOut bool)

// runBatch runs the whole list through bt. A target the tool says it has
// seen is settled done at once (early: the heartbeat's progress and the tool
// child's target status); every target gets its final outcome once the run
// ends. A run the job's end stopped settles the targets it has
// records for and returns the others as unfinished; a run that failed as a
// whole fails every target it has no record for (a tool-level failure, so
// a run that failed on every target fails the job).
func runBatch(ctx context.Context, bt batchTool, targets []string, ro core.ReconOptions, settle settleFn, early func(i int)) (unfinished []string, stopErr error) {
	// The per-target budget is not a kill in a batch: it cannot tell which
	// target is slow. The tool's own per-probe timeout (from the budget)
	// bounds each target, the job's context bounds the run.
	budget := ro.Timeout
	ro.Timeout = 0
	index := make(map[string]int, len(targets))
	for i, t := range targets {
		if _, dup := index[t]; !dup {
			index[t] = i
		}
	}
	seen := func(t string) {
		if i, ok := index[t]; ok && early != nil {
			early(i)
		}
	}
	results, runErr := bt.ScanBatch(ctx, targets, &ro, budget, seen)
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
	return unfinished, stopErr
}

// batchable reports whether bt can run the list as one process now: a tool
// may need a mode for it (httpx needs its JSON output, which names each
// record's input).
func batchable(bt batchTool) bool {
	if b, ok := bt.(interface{ Batchable() bool }); ok {
		return b.Batchable()
	}
	return true
}
