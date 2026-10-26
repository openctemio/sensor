package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit"
)

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// The reported crash: SENSOR_CONTENT_DIR on a directory the sensor's user
// cannot write ("content: mkdir ...: permission denied").
func TestCheckDataDirsNamesTheUnwritableContentDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a non-root unix user")
	}
	data := t.TempDir()
	if err := os.Chmod(data, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(data, 0o755) })
	t.Setenv(sensorkit.EnvOutboxDir, "")
	t.Setenv(sensorkit.EnvStateDir, "")

	err := checkDataDirs(envOf(map[string]string{"SENSOR_CONTENT_DIR": filepath.Join(data, "content")}))
	var p *sensorkit.DataDirProblem
	if !errors.As(err, &p) {
		t.Fatalf("want a DataDirProblem, got %v", err)
	}
	for _, want := range []string{filepath.Join(data, "content"), "permission denied", "chown -R", "named volume"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q:\n%s", want, err)
		}
	}
}

func TestCheckDataDirsContentOffSkipsContent(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a non-root unix user")
	}
	data := t.TempDir()
	if err := os.Chmod(data, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(data, 0o755) })
	t.Setenv(sensorkit.EnvOutboxDir, "")
	t.Setenv(sensorkit.EnvStateDir, "")

	if err := checkDataDirs(envOf(map[string]string{
		"SENSOR_CONTENT":     "off",
		"SENSOR_CONTENT_DIR": filepath.Join(data, "content"),
	})); err != nil {
		t.Fatalf("content off must not check the content dir: %v", err)
	}
}

func TestCheckDataDirsWritableOK(t *testing.T) {
	data := t.TempDir()
	t.Setenv(sensorkit.EnvOutboxDir, filepath.Join(data, "outbox"))
	t.Setenv(sensorkit.EnvStateDir, filepath.Join(data, "state"))
	t.Setenv(sensorkit.EnvStoreDir, filepath.Join(data, "store"))
	t.Setenv(sensorkit.EnvWorkspaceDir, filepath.Join(data, "workspaces"))
	if err := checkDataDirs(envOf(map[string]string{"SENSOR_CONTENT_DIR": filepath.Join(data, "content")})); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"outbox", "state", "store", "workspaces", "content"} {
		if fi, err := os.Stat(filepath.Join(data, d)); err != nil || !fi.IsDir() {
			t.Errorf("%s not created: %v", d, err)
		}
	}
}
