//go:build linux

package scanproc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// alive reports whether pid is a live (non-zombie) process.
func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || s[i+2] != 'Z'
}

func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("process %d (the scanner's child) outlived the scanner", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func childPID(t *testing.T, file string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := os.ReadFile(file)
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatal("the wrapper never wrote its child's pid")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A canceled scan kills the whole process group: a wrapper script's
// background child dies with it. Plain exec.CommandContext kills only the
// wrapper and leaves the child running.
func TestOutput_CancelKillsWrapperChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 60 & echo $! > "+pidFile+"; wait")
		_, err := Output(cmd)
		done <- err
	}()
	pid := childPID(t, pidFile)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a canceled scanner reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Output did not return after cancel")
	}
	waitGone(t, pid)
}

// A scanner that exits leaving a background child behind does not outlive
// the command.
func TestRun_ReapsLeftoverChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c", "sleep 60 >/dev/null 2>&1 & echo $! > "+pidFile)
	if err := Run(cmd); err != nil {
		t.Fatal(err)
	}
	waitGone(t, childPID(t, pidFile))
}

// Output keeps exec.Cmd.Output's contract: stdout returned, and a failed
// run's *exec.ExitError carries stderr (callers report it), unless the
// caller set Stderr itself.
func TestOutput_ExitErrorCarriesStderr(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c", "echo out; echo boom >&2; exit 3")
	out, err := Output(cmd)
	if string(out) != "out\n" {
		t.Fatalf("stdout = %q", out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 || string(ee.Stderr) != "boom\n" {
		t.Fatalf("err = %#v", err)
	}

	var own bytes.Buffer
	cmd = exec.CommandContext(context.Background(), "/bin/sh", "-c", "echo boom >&2; exit 1")
	cmd.Stderr = &own
	_, err = Output(cmd)
	if !errors.As(err, &ee) || ee.Stderr != nil || own.String() != "boom\n" {
		t.Fatalf("err = %#v, own stderr %q", err, own.String())
	}

	cmd = exec.CommandContext(context.Background(), "/bin/true")
	cmd.Stdout = &own
	if _, err := Output(cmd); err == nil {
		t.Fatal("Output with Stdout set must fail like exec.Cmd.Output")
	}
}

// Stderr past the cap keeps its first and last stderrCap bytes.
func TestPrefixSuffix(t *testing.T) {
	w := &prefixSuffix{n: 4}
	for _, s := range []string{"ab", "cdefg", "hijklmnop", "q"} {
		if n, err := w.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatal(n, err)
		}
	}
	// abcdefghijklmnopq: prefix abcd, suffix nopq, 9 bytes omitted.
	if got, want := string(w.bytes()), "abcd\n... omitting 9 bytes ...\nnopq"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	short := &prefixSuffix{n: 4}
	_, _ = short.Write([]byte("abcdef"))
	if got := string(short.bytes()); got != "abcdef" {
		t.Fatalf("got %q", got)
	}
}

// The scanner runs at the scanner priority sensorkit sets
// (SENSOR_SCANNER_PRIORITY): nice +10 relative to the sensor.
func TestStart_AppliesScannerPriority(t *testing.T) {
	core.SetScannerPriority(&core.ScannerPriority{Nice: 10, IOLevel: -1})
	t.Cleanup(func() { core.SetScannerPriority(nil) })
	v, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := min(20-v+10, 19)
	out, err := Output(exec.CommandContext(context.Background(), "/bin/sh", "-c", "sleep 0.3; cut -d' ' -f19 /proc/$$/stat"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != strconv.Itoa(want) {
		t.Fatalf("scanner nice = %s, want %d", got, want)
	}
}
