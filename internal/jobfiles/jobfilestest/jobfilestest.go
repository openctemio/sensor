// Package jobfilestest checks, in a scanner's tests, that a file the scanner
// keeps for one job is private to that job: it lies under the private task
// root, the job's context grants it, and in the real tool sandbox a task of
// another job cannot read it while the job's own task can.
//
// A test package that uses AssertJobPrivate calls RunToolIfRequested first in
// its TestMain: the test binary is the sandbox launcher and the reading tool.
package jobfilestest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// readTool is the first argument that makes the test binary a tool that
// reads the file named by the second and prints OK or ERR.
const readTool = "__jobfilestest-read"

// RunToolIfRequested makes the test binary the sandbox launcher or the
// reading tool when it was started as one; it returns otherwise. Call it
// first in TestMain.
func RunToolIfRequested() {
	executor.RunLauncherIfRequested()
	if len(os.Args) > 2 && os.Args[1] == readTool {
		if _, err := os.ReadFile(os.Args[2]); err != nil {
			fmt.Println("ERR", err)
			os.Exit(3)
		}
		fmt.Println("OK")
		os.Exit(0)
	}
}

// Sandbox makes the real tool sandbox (required mode, the sensor's own
// backend) the current backend and returns the function that restores the
// previous one. ok is false, and nothing changes, where this host cannot
// give the sandbox; the caller then checks what it can without it.
func Sandbox(t *testing.T) (restore func(), ok bool) {
	t.Helper()
	b, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, WorkRoot: t.TempDir(),
		Limits: executor.Limits{Processes: 64}})
	if err != nil {
		t.Logf("sandbox not available here: %v", err)
		return func() {}, false
	}
	prev := executor.Current()
	executor.SetCurrent(b)
	return func() { executor.SetCurrent(prev) }, true
}

// AssertUnderTaskRoot fails t unless path lies under the private task root,
// which the sandbox hides from every task that is not granted it.
func AssertUnderTaskRoot(t *testing.T, path string) {
	t.Helper()
	root := executor.TaskRoot()
	if !strings.HasPrefix(path, root+string(filepath.Separator)) {
		t.Fatalf("job file %s is outside the private task root %s: another job's task can read it", path, root)
	}
}

// AssertJobPrivate fails t unless path lies under the private task root and
// jobCtx (the context the scanner runs the job's tool with) grants it. Where
// the real sandbox is available it also runs the reading tool: a task of
// another job (no grant, or a grant of its own) must not read path, the
// job's own task must.
func AssertJobPrivate(t *testing.T, jobCtx context.Context, path string) {
	t.Helper()
	AssertUnderTaskRoot(t, path)
	granted := false
	for _, p := range executor.ReadPathsFrom(jobCtx) {
		if path == p || strings.HasPrefix(path, p+string(filepath.Separator)) {
			granted = true
		}
	}
	if !granted {
		t.Fatalf("the job's context does not grant %s (grants %v): its own tool cannot read it", path, executor.ReadPathsFrom(jobCtx))
	}

	restore, ok := Sandbox(t)
	if !ok {
		return
	}
	defer restore()

	if out := readInTask(context.Background(), t, path); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("another job's task read %s: %q", path, out)
	}
	other := executor.WithReadPaths(context.Background(), t.TempDir())
	if out := readInTask(other, t, path); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("another job's task with a grant of its own read %s: %q", path, out)
	}
	if out := readInTask(jobCtx, t, path); out != "OK" {
		t.Fatalf("the job's own task could not read %s: %q", path, out)
	}
}

// readInTask runs the test binary as a tool through core.ExecuteScanner (the
// path every scanner run takes) and returns what it printed.
func readInTask(ctx context.Context, t *testing.T, file string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	res, err := core.ExecuteScanner(ctx, &core.ExecConfig{Binary: exe, Args: []string{readTool, file}, Timeout: 30 * time.Second})
	if res == nil {
		t.Fatalf("no result from the reading tool: %v", err)
	}
	return strings.TrimSpace(string(res.Stdout))
}
