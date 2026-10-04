package content

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanproc"
)

// run executes a tool for a refresh or a check. It gets the scanner
// environment allowlist (never the sensor's API key), minus the variables
// named in drop, plus extra. Its proxy variables follow the content proxy
// (SENSOR_CONTENT_PROXY, else the platform proxy; api RFC-034), not the
// scanners' SENSOR_SCAN_PROXY: a content download is not a scan.
func run(ctx context.Context, binary string, args []string, drop []string, extra map[string]string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // fixed tool binary, arguments built here
	env := core.ContentEnviron(extra)
	if len(drop) > 0 {
		kept := env[:0]
		for _, kv := range env {
			name, _, _ := strings.Cut(kv, "=")
			if !containsString(drop, name) {
				kept = append(kept, kv)
			}
		}
		env = kept
	}
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Downloads and unpacking run at scanner priority, in their own process
	// group: a canceled refresh kills all of it (api RFC-035 B6).
	if err := scanproc.Run(cmd); err != nil {
		msg := strings.TrimSpace(lastLines(stderr.String(), 3))
		if msg == "" {
			return stdout.Bytes(), fmt.Errorf("%s %s: %w", binary, firstArg(args), err)
		}
		return stdout.Bytes(), fmt.Errorf("%s %s: %w: %s", binary, firstArg(args), err, msg)
	}
	return stdout.Bytes(), nil
}

// runCapture is run for a check whose exit status and stderr are its
// result (nuclei -validate exits 1 and lists the failures on stderr): it
// returns both instead of an error for a non-zero exit. err is set only
// when the tool could not run (not found, killed by ctx).
func runCapture(ctx context.Context, binary string, args []string, extra map[string]string) (stdout, stderr []byte, code int, err error) {
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // fixed tool binary, arguments built here
	cmd.Env = core.ContentEnviron(extra)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := scanproc.Run(cmd)
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exitErr) && ctx.Err() == nil:
		code = exitErr.ExitCode()
	default:
		return out.Bytes(), errb.Bytes(), -1, runErr
	}
	return out.Bytes(), errb.Bytes(), code, nil
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
