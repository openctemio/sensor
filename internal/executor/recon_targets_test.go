package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestMergeTargets(t *testing.T) {
	got := mergeTargets(" a.example.com ", []string{"b.example.com", "a.example.com", "", "c.example.com"})
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeTargets = %v, want %v", got, want)
	}
	if got := mergeTargets("", nil); len(got) != 0 {
		t.Fatalf("empty input must give no targets, got %v", got)
	}
}

func TestWriteTargetList(t *testing.T) {
	path, err := writeTargetList([]string{"a.example.com", "b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(path) }()
	data, _ := os.ReadFile(path)
	if string(data) != "a.example.com\nb.example.com\n" {
		t.Fatalf("content = %q", data)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
		}
	}
	// A target cannot smuggle another line into the list.
	if _, err := writeTargetList([]string{"a.example.com\n169.254.169.254"}); err == nil {
		t.Fatal("newline inside a target must be rejected")
	}
}

// Target-bearing flags in extra_args would bypass the SSRF guard.
func TestValidateExtraArgsRejectsTargetFlags(t *testing.T) {
	for _, arg := range []string{"-u", "-target=http://169.254.169.254", "-l", "-list", "-d", "-dL", "-host", "--url", "-domain=internal.corp"} {
		if err := validateExtraArgs([]string{arg}); err == nil {
			t.Errorf("%s must be rejected", arg)
		}
	}
	if err := validateExtraArgs([]string{"-silent", "-timeout", "10"}); err != nil {
		t.Errorf("benign args rejected: %v", err)
	}
}

// fakeTool returns a cliToolExecutor whose binary records its arguments, and
// the list file contents when one is passed, so the exact CLI invocation can
// be asserted without the real recon tools.
func fakeTool(t *testing.T, targetFlag, listFlag string) (*cliToolExecutor, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script binary")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "args")
	script := filepath.Join(dir, "tool.sh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + record + "\n" +
		"prev=''\nfor a in \"$@\"; do if [ \"$prev\" = '" + listFlag + "' ]; then cat \"$a\" >> " + record + ".list; fi; prev=\"$a\"; done\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return &cliToolExecutor{name: "httpx", binary: script, targetFlag: targetFlag, listFlag: listFlag}, record
}

func TestCLIToolPassesEveryTarget(t *testing.T) {
	t.Setenv("SENSOR_ALLOW_PRIVATE_TARGETS", "")
	tool, record := fakeTool(t, "-u", "-l")

	// several targets: list file via the list flag
	if _, err := tool.Execute(context.Background(), ToolOptions{Targets: []string{"8.8.8.8", "1.1.1.1"}}); err != nil && !strings.Contains(err.Error(), "parse") {
		t.Fatalf("execute: %v", err)
	}
	args, _ := os.ReadFile(record)
	if !strings.Contains(string(args), "-l\n") || strings.Contains(string(args), "-u\n") {
		t.Fatalf("expected list flag, got args:\n%s", args)
	}
	list, _ := os.ReadFile(record + ".list")
	if string(list) != "8.8.8.8\n1.1.1.1\n" {
		t.Fatalf("list file = %q", list)
	}

	// one target: the single-target flag, as before
	_ = os.Remove(record)
	if _, err := tool.Execute(context.Background(), ToolOptions{Target: "8.8.8.8", Targets: []string{"8.8.8.8"}}); err != nil && !strings.Contains(err.Error(), "parse") {
		t.Fatalf("execute: %v", err)
	}
	args, _ = os.ReadFile(record)
	if !strings.Contains(string(args), "-u\n8.8.8.8\n") {
		t.Fatalf("expected -u 8.8.8.8, got:\n%s", args)
	}
}

// Every target is still checked by the SSRF guard before anything runs.
func TestCLIToolRejectsBlockedTargetInList(t *testing.T) {
	t.Setenv("SENSOR_ALLOW_PRIVATE_TARGETS", "")
	tool, record := fakeTool(t, "-u", "-l")
	_, err := tool.Execute(context.Background(), ToolOptions{Targets: []string{"8.8.8.8", "169.254.169.254"}})
	if err == nil {
		t.Fatal("a blocked target in the list must stop the run")
	}
	if _, statErr := os.Stat(record); statErr == nil {
		t.Fatal("the tool must not run when a target is rejected")
	}
}
