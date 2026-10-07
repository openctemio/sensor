package toolrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Tools whose output the sensor parses with the scan's parse options (the
// asset, branch and commit of the command: trivy, semgrep, betterleaks,
// codeql) run out of process too, but return the scanner's raw output
// rather than CTIS records: the parse needs the command's context, which
// the child never sees, and a parse without it would file findings on no
// asset. The child runs the scanner's direct path in the task sandbox and
// writes two artifacts, which the runtime reads back from the task
// directory (no symlink escape, size and digest checked):
//
//   - RawArtifact: the scanner's output, byte for byte;
//   - resultArtifact: exit code, stderr and version of the run.
//
// The parent returns them as the core.ScanResult the direct path returns,
// so the existing parser sees the same bytes.

// RawArtifact is the artifact holding a raw-output tool's output.
const RawArtifact = "raw-output"

const resultArtifact = "scan-result.json"

// MaxRawStderr bounds the stderr a child hands back.
const MaxRawStderr = 64 << 10

type rawResult struct {
	ScannerVersion string `json:"scanner_version,omitempty"`
	ExitCode       int    `json:"exit_code"`
	Stderr         string `json:"stderr,omitempty"`
}

// EmitRaw is the child side: it writes res's output and outcome as the
// task's artifacts and marks every target done.
func EmitRaw(ctx tool.Context, task tool.Task, res *core.ScanResult) error {
	if res == nil {
		return tool.Failed(errors.New("no scan result"))
	}
	w, err := ctx.Artifact(RawArtifact, "application/octet-stream")
	if err != nil {
		return err
	}
	if _, err := w.Write(res.RawOutput); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	stderr := res.Stderr
	if len(stderr) > MaxRawStderr {
		stderr = stderr[len(stderr)-MaxRawStderr:]
	}
	b, err := json.Marshal(rawResult{ScannerVersion: res.ScannerVersion, ExitCode: res.ExitCode, Stderr: stderr})
	if err != nil {
		return err
	}
	if w, err = ctx.Artifact(resultArtifact, "application/json"); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	for _, t := range task.Targets {
		ctx.TargetDone(t)
	}
	return nil
}

// RunRaw runs one task of the raw-output tool t out of process (as Run)
// and returns the scanner's result as the direct path does. A task that
// failed returns its categorized error.
func RunRaw(ctx context.Context, t tool.Tool, targets []string, local any, o toolhost.RunOptions) (*core.ScanResult, *toolhost.Outcome, error) {
	name := t.Manifest().Name
	raw, err := json.Marshal(local)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: encode the task: %w", name, err)
	}
	task := withJob(ctx, tool.Task{Targets: Targets(targets, ""), Local: raw})
	h, ro := current(o)
	out, err := h.RunBuiltin(ctx, t, task, ro)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, err)
	}
	if out.Err != nil {
		return nil, out, fmt.Errorf("%s: %w", name, out.Err)
	}
	var data, meta []byte
	var gotData, gotMeta bool
	for _, a := range out.Artifacts {
		switch a.Name {
		case RawArtifact:
			data, gotData = a.Data, true
		case resultArtifact:
			meta, gotMeta = a.Data, true
		}
	}
	if !gotData || !gotMeta {
		return nil, out, fmt.Errorf("%s: the tool returned no output", name)
	}
	var rr rawResult
	if err := json.Unmarshal(meta, &rr); err != nil {
		return nil, out, fmt.Errorf("%s: unreadable scan result: %w", name, err)
	}
	return &core.ScanResult{
		ScannerName:    name,
		ScannerVersion: rr.ScannerVersion,
		DurationMs:     out.Duration.Milliseconds(),
		ExitCode:       rr.ExitCode,
		RawOutput:      data,
		Stderr:         rr.Stderr,
	}, out, nil
}
