package recon

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Every tool run goes through toolrun's host: with the kit's sink set
// (main wires kit.ToolLogSink), the run's lines, framed by "tool started /
// finished", reach the command the scan runs for (research/62 P0-2).
func TestToolRunShipsLinesToTheCommand(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	var mu sync.Mutex
	var lines []string
	ids := map[string]bool{}
	toolrun.SetLogSink(func(ctx context.Context, name string, l toolhost.LogLine) {
		mu.Lock()
		defer mu.Unlock()
		ids[core.CommandIDFromContext(ctx)] = true
		lines = append(lines, name+": "+l.Msg)
	})
	t.Cleanup(func() { toolrun.SetLogSink(nil) })

	ctx := core.WithCommandID(context.Background(), "cmd-scan-1")
	if _, err := katanaScanner(t).ScanTargets(ctx, []string{"http://127.0.0.1:18777"}, &core.ScanOptions{Capability: "crawl.web@1"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "katana: Tool katana") || !strings.Contains(joined, "started") ||
		!strings.Contains(joined, "katana: Tool katana finished: ok") {
		t.Fatalf("lifecycle lines missing:\n%s", joined)
	}
	if len(ids) != 1 || !ids["cmd-scan-1"] {
		t.Fatalf("lines were not tied to the command: %v", ids)
	}
}
