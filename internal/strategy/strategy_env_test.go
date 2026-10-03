package strategy

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GetChangedFiles runs git with the scanner environment: git, and any
// command the scanned repository's configuration makes it run, must not
// see the sensor's API key. A fake git records the environment it got.
func TestGetChangedFiles_GitDoesNotSeeSensorSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake git")
	}
	dir := t.TempDir()
	dump := filepath.Join(dir, "env.txt")
	fake := "#!/bin/sh\nenv > " + dump + "\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(fake), 0o700); err != nil { //nolint:gosec // test fake binary must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if p, err := exec.LookPath("git"); err != nil || p != filepath.Join(dir, "git") {
		t.Fatalf("fake git not first on PATH: %s %v", p, err)
	}
	t.Setenv("API_KEY", "must_not_leak")
	t.Setenv("SENSOR_API_KEY", "must_not_leak")
	t.Setenv("GITHUB_TOKEN", "must_not_leak")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "safe.directory")
	t.Setenv("GIT_CONFIG_VALUE_0", "*")

	if _, err := GetChangedFiles(dir, "b", "a"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dump) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	env := string(raw)
	if strings.Contains(env, "must_not_leak") {
		t.Fatalf("git saw a sensor secret:\n%s", env)
	}
	for _, want := range []string{"PATH=", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=*"} {
		if !strings.Contains(env, want) {
			t.Fatalf("git env lacks %s:\n%s", want, env)
		}
	}
}
