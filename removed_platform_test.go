package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runMainInChild re-runs this test binary with args as the sensor's command
// line, so main() (which calls os.Exit) runs in its own process.
func runMainInChild(t *testing.T, test string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$")
	cmd.Env = append(os.Environ(), "SENSOR_TEST_MAIN_ARGS="+strings.Join(args, "\x1f"))
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run child: %v", err)
	}
	return string(out), code
}

// inChild runs main with the arguments the parent passed and reports whether
// this process is that child.
func inChild() bool {
	v, ok := os.LookupEnv("SENSOR_TEST_MAIN_ARGS")
	if !ok {
		return false
	}
	os.Args = append([]string{"openctemio-sensor"}, strings.Split(v, "\x1f")...)
	main()
	return true
}

// -platform was removed: it must say so and exit 2, not fail as an unknown
// flag or start anything.
func TestPlatformFlagExplainsRemoval(t *testing.T) {
	if inChild() {
		return
	}
	out, code := runMainInChild(t, "TestPlatformFlagExplainsRemoval",
		"-platform", "-bootstrap-token", "x", "-enable-recon", "-enable-vulnscan=false")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; output:\n%s", code, out)
	}
	if !strings.Contains(out, "-platform mode has been removed") || !strings.Contains(out, "-daemon") {
		t.Fatalf("output does not explain the removal:\n%s", out)
	}
}

// The other platform-mode flags stay accepted (and ignored) so that a command
// line still carrying them does not fail on flag parsing.
func TestRemovedPlatformFlagsAreAccepted(t *testing.T) {
	if inChild() {
		return
	}
	out, code := runMainInChild(t, "TestRemovedPlatformFlagsAreAccepted",
		"-bootstrap-token", "x", "-enable-recon", "-enable-secrets", "-enable-assets",
		"-enable-pipeline", "-enable-vulnscan=true", "-version")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; output:\n%s", code, out)
	}
	if strings.Contains(out, "flag provided but not defined") {
		t.Fatalf("a removed flag is no longer accepted:\n%s", out)
	}
}
