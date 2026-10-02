// Package scanproc runs the sensor's scanning tools (the platform-mode
// executors and the content refresh) the way the SDK's own exec helpers run
// scanners (api RFC-035 §5.3, defect B6): in their own process group, so a
// canceled context kills a wrapper's children too and nothing outlives the
// command, and at the scanner priority (nice, best-effort I/O and an OOM
// score above the sensor's; SENSOR_SCANNER_PRIORITY).
//
// Version probes and tool installation do not need it.
package scanproc

import (
	"bytes"
	"errors"
	"os/exec"
	"strconv"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Start starts cmd as a scanner: core.ConfigureScannerProcess before it and
// core.ApplyScannerPriority right after. Finish it with Wait.
func Start(cmd *exec.Cmd) error {
	core.ConfigureScannerProcess(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	core.ApplyScannerPriority(cmd)
	return nil
}

// Wait is cmd.Wait, then kills what is left of the scanner's process group
// (core.ReapScannerProcess).
func Wait(cmd *exec.Cmd) error {
	err := cmd.Wait()
	core.ReapScannerProcess(cmd)
	return err
}

// Run is exec.Cmd.Run for a scanner (Start, then Wait).
func Run(cmd *exec.Cmd) error {
	if err := Start(cmd); err != nil {
		return err
	}
	return Wait(cmd)
}

// stderrCap is how much standard error Output keeps at each end, as
// exec.Cmd.Output does.
const stderrCap = 32 << 10

// Output is exec.Cmd.Output for a scanner: the standard output, and when
// cmd.Stderr is nil, the *exec.ExitError of a failed run carries the
// standard error in Stderr (its first and last 32 KiB), which callers report.
func Output(cmd *exec.Cmd) ([]byte, error) {
	if cmd.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr *prefixSuffix
	if cmd.Stderr == nil {
		stderr = &prefixSuffix{n: stderrCap}
		cmd.Stderr = stderr
	}
	err := Run(cmd)
	if stderr != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			ee.Stderr = stderr.bytes()
		}
	}
	return stdout.Bytes(), err
}

// prefixSuffix keeps the first and the last n bytes written to it.
type prefixSuffix struct {
	n       int
	prefix  []byte
	suffix  []byte // a ring once full; off is where the next byte goes
	off     int
	skipped int64
}

func (w *prefixSuffix) Write(p []byte) (int, error) {
	total := len(p)
	if room := w.n - len(w.prefix); room > 0 {
		k := min(room, len(p))
		w.prefix = append(w.prefix, p[:k]...)
		p = p[k:]
	}
	if len(p) > w.n {
		w.skipped += int64(len(p) - w.n)
		p = p[len(p)-w.n:]
	}
	for len(p) > 0 {
		if len(w.suffix) < w.n {
			k := min(w.n-len(w.suffix), len(p))
			w.suffix = append(w.suffix, p[:k]...)
			p = p[k:]
			continue
		}
		k := copy(w.suffix[w.off:], p)
		w.skipped += int64(k)
		w.off = (w.off + k) % w.n
		p = p[k:]
	}
	return total, nil
}

func (w *prefixSuffix) bytes() []byte {
	if w.suffix == nil {
		return w.prefix
	}
	var b bytes.Buffer
	b.Grow(len(w.prefix) + len(w.suffix) + 50)
	b.Write(w.prefix)
	if w.skipped > 0 {
		b.WriteString("\n... omitting " + strconv.FormatInt(w.skipped, 10) + " bytes ...\n")
	}
	b.Write(w.suffix[w.off:])
	b.Write(w.suffix[:w.off])
	return b.Bytes()
}
