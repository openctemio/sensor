package recon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/toolrun"
)

// The job's exclusions (ScanOptions.ExcludeHosts, from the signed payload)
// reach naabu in the tool child as -exclude-hosts.
func TestNaabuExcludeHostsReachTheChild(t *testing.T) {
	withSensorResolver(t)
	t.Setenv(toolrun.EnvRuntime, "")
	s := naabuScanner(t)
	nb := s.Recon().(*naabu.Scanner)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(out, testdata(t, "naabu-2.6.1.jsonl"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$*\" in *'-exclude-hosts 127.0.0.9,127.0.0.64/27'*) ;; *) echo \"missing -exclude-hosts in $*\" >&2; exit 4;; esac\ncat " + out + "\n"
	nb.Binary = filepath.Join(dir, "naabu")
	if err := os.WriteFile(nb.Binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanTargets(context.Background(), []string{"127.0.0.1"}, &core.ScanOptions{ExcludeHosts: []string{"127.0.0.9", "127.0.0.64/27"}})
	if err != nil {
		t.Fatalf("exclusions did not reach the child: %v", err)
	}
	if !strings.Contains(string(res.RawOutput), "provenance") {
		t.Fatal("naabu ran in process")
	}
	// An unreadable exclusion refuses the run.
	if _, err := s.ScanTargets(context.Background(), []string{"127.0.0.1"}, &core.ScanOptions{ExcludeHosts: []string{"-p 1-65535"}}); err == nil {
		t.Fatal("an unreadable exclusion was dropped and the scan ran")
	}
}
