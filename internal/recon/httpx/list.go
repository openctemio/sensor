package httpx

// Batch mode: one httpx process over the whole target list (-l), with
// httpx's own concurrency (-threads) and per-request timeout (-timeout),
// its JSON lines read from stdout as it prints them. httpx keeps going past
// a host that does not answer (that host costs its own timeout and
// retries), and with -probe it prints at least one line for every input,
// a failed one included, so a target is settled the moment its first line
// arrives (research note 125 in openctem).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// MinRequestTimeout is the shortest per-request timeout batch mode gives
// httpx, whatever the per-target budget.
const MinRequestTimeout = 2 * time.Second

// Batchable reports whether the scanner can run a target list as one
// process: its output must be JSON lines, which name their input.
func (s *Scanner) Batchable() bool { return s.OutputJSON }

// RequestTimeout is the per-request timeout (-timeout) for a per-target
// budget: the budget shared by the first try and the retries, at least
// MinRequestTimeout, and never longer than the settings' timeout
// (TimeoutSeconds). Without a budget it is the settings' timeout; 0 (httpx's
// own default) without either.
func (s *Scanner) RequestTimeout(budget time.Duration) time.Duration {
	set := time.Duration(s.TimeoutSeconds) * time.Second
	if budget <= 0 {
		return set
	}
	d := max(budget/time.Duration(max(s.Retries, 0)+1), MinRequestTimeout)
	if set > 0 && set < d {
		return set
	}
	return d
}

// timeoutArgs is -timeout for d in whole seconds (rounded up), or nothing
// for 0.
func timeoutArgs(d time.Duration) []string {
	if d <= 0 {
		return nil
	}
	return []string{"-timeout", fmt.Sprintf("%d", int((d+time.Second-1)/time.Second))}
}

// ScanList probes targets with one httpx process. onLine is told every JSON
// line httpx prints, with the input it names, as it is printed (from one
// goroutine). The returned result is the process's (exit code, error); the
// lines are the caller's to parse per target (ResultFor). requestTimeout,
// when positive, is httpx's per-request -timeout.
func (s *Scanner) ScanList(ctx context.Context, targets []string, opts *core.ReconOptions, requestTimeout time.Duration, onLine func(input string, line []byte)) (*core.ReconResult, error) {
	start := time.Now()
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	list, err := os.CreateTemp("", "httpx-targets-*.txt") // created 0600
	if err != nil {
		return nil, fmt.Errorf("httpx: target list: %w", err)
	}
	listFile := list.Name()
	defer os.Remove(listFile) //nolint:errcheck // best-effort cleanup
	_, werr := list.WriteString(strings.Join(targets, "\n") + "\n")
	if cerr := list.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, fmt.Errorf("httpx: target list: %w", werr)
	}
	o := core.ReconOptions{}
	if opts != nil {
		o = *opts
	}
	o.InputFile = listFile
	args := append(s.buildArgs("", &o), timeoutArgs(requestTimeout)...)
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}
	if s.Verbose {
		fmt.Printf("[httpx] %d targets, args: %v\n", len(targets), args)
	}
	res := &core.ReconResult{ScannerName: s.Name(), ScannerVersion: s.version, ReconType: s.Type(),
		Target: strings.Join(targets, ","), StartedAt: start.Unix()}
	exec, err := core.StreamScanner(ctx, &core.ExecConfig{Binary: binary, Args: args, Verbose: s.Verbose}, func(line string, isError bool) {
		if isError || onLine == nil {
			return
		}
		b := bytes.TrimSpace([]byte(line))
		if len(b) == 0 || b[0] != '{' {
			return
		}
		var head struct {
			Input string `json:"input"`
		}
		if json.Unmarshal(b, &head) != nil || head.Input == "" {
			return
		}
		onLine(head.Input, b)
	})
	res.FinishedAt = time.Now().Unix()
	res.DurationMs = time.Since(start).Milliseconds()
	if exec != nil {
		res.ExitCode = exec.ExitCode
		if exec.Error != nil && err == nil {
			err = exec.Error
		}
	}
	if err != nil {
		res.ExitCode = -1
		res.Error = err.Error()
		if errors.Is(err, core.ErrScannerOutputTooLarge) {
			res.Error = "httpx printed more than the output limit"
		}
	}
	return res, nil
}

// ResultFor is one target's result from the JSON lines httpx printed for it.
func (s *Scanner) ResultFor(target string, lines []byte) (*core.ReconResult, error) {
	liveHosts, technologies, err := s.parseOutput(lines)
	if err != nil {
		return nil, fmt.Errorf("failed to parse httpx output: %w", err)
	}
	return &core.ReconResult{ScannerName: s.Name(), ScannerVersion: s.version, ReconType: s.Type(), Target: target,
		LiveHosts: liveHosts, Technologies: technologies, RawOutput: stripHeaders(lines)}, nil
}

// errNoRecord: httpx finished without a line for the target (with -probe it
// prints at least one for every input it read).
const errNoRecord = "httpx printed no result for the target"

// ScanBatch probes targets with one httpx process (the recon batch
// mechanism): its per-request -timeout comes from the per-target budget,
// and each target is reported to seen the moment httpx prints its first
// line for it. A line naming an input the list does not carry is ignored.
// When httpx finishes, a target with no line gets a result with Error set
// (it failed); when the run was stopped, it gets none (unfinished).
func (s *Scanner) ScanBatch(ctx context.Context, targets []string, opts *core.ReconOptions, budget time.Duration, seen func(target string)) (map[string]*core.ReconResult, error) {
	want := make(map[string]bool, len(targets))
	for _, t := range targets {
		want[t] = true
	}
	var mu sync.Mutex
	lines := make(map[string]*bytes.Buffer, len(targets))
	res, err := s.ScanList(ctx, targets, opts, s.RequestTimeout(budget), func(input string, line []byte) {
		if !want[input] {
			return
		}
		mu.Lock()
		b, ok := lines[input]
		if !ok {
			b = &bytes.Buffer{}
			lines[input] = b
		}
		b.Write(line)
		b.WriteByte('\n')
		mu.Unlock()
		if !ok && seen != nil {
			seen(input)
		}
	})
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]*core.ReconResult, len(targets))
	for t, b := range lines {
		r, perr := s.ResultFor(t, b.Bytes())
		if perr != nil {
			continue
		}
		// A target with lines completed, whatever the exit status of the run.
		r.StartedAt, r.FinishedAt, r.DurationMs = res.StartedAt, res.FinishedAt, res.DurationMs
		out[t] = r
	}
	var runErr error
	switch {
	case res.Error != "":
		runErr = errors.New(res.Error)
	case res.ExitCode != 0:
		runErr = fmt.Errorf("httpx exited with status %d", res.ExitCode)
	}
	if runErr == nil && ctx.Err() == nil {
		for _, t := range targets {
			if _, ok := out[t]; !ok {
				out[t] = &core.ReconResult{ScannerName: s.Name(), ScannerVersion: s.version, ReconType: s.Type(), Target: t,
					ExitCode: res.ExitCode, Error: errNoRecord}
			}
		}
	}
	return out, runErr
}
