package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/content"
)

// A trivy that records its arguments; the content manager installs a fake
// database whose "download" is this same script.
func fakeTrivyOnPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	script := `#!/bin/sh
echo "$@" >> "` + log + `"
cache=""
while [ $# -gt 0 ]; do [ "$1" = "--cache-dir" ] && cache="$2"; shift; done
case "$*" in *) ;; esac
if [ -n "$cache" ] && [ ! -f "$cache/db/trivy.db" ]; then mkdir -p "$cache/db"; echo x > "$cache/db/trivy.db"; echo '{"Version":2,"UpdatedAt":"2026-10-02T01:00:00Z"}' > "$cache/db/metadata.json"; fi
printf '{"Version":"0.69.3","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-10-02T01:00:00Z"}}'
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(script), 0o755); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func TestTrivyToolUsesManagedDB(t *testing.T) {
	log := fakeTrivyOnPath(t)
	m, err := content.New(content.Config{Root: t.TempDir(), Logf: t.Logf}, &content.TrivyDB{
		Repositories: []string{"127.0.0.1:1/aquasec/trivy-db:2"}, Resolver: &content.OCIResolver{Scheme: "http"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := m.Refresh(context.Background(), nil, false); res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	cfg := DefaultVulnScanConfig()
	cfg.Content = m
	tool := &TrivyTool{config: &cfg.Trivy, content: m}
	if _, err := tool.Execute(context.Background(), ToolOptions{Target: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "fs ") || !strings.Contains(last, "--skip-db-update") || strings.Contains(last, cfg.Trivy.CacheDir) {
		t.Fatalf("scan not on the managed DB: %s", last)
	}
	if used := m.LastUsed("trivy"); len(used) != 1 || used[0].Name != core.ContentTrivyDB {
		t.Fatalf("used %+v", used)
	}
}
