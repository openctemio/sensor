package content

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// run executes a tool for a refresh or a check. It gets the scanner
// environment allowlist (never the sensor's API key), minus the variables
// named in drop, plus extra.
func run(ctx context.Context, binary string, args []string, drop []string, extra map[string]string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // fixed tool binary, arguments built here
	env := core.ScannerEnviron(extra)
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
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(lastLines(stderr.String(), 3))
		if msg == "" {
			return stdout.Bytes(), fmt.Errorf("%s %s: %w", binary, firstArg(args), err)
		}
		return stdout.Bytes(), fmt.Errorf("%s %s: %w: %s", binary, firstArg(args), err, msg)
	}
	return stdout.Bytes(), nil
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
