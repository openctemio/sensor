package recon

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/webscope"
	"github.com/openctemio/sensor/internal/toolrun"
)

// katana keeps to a job's web scope, in the task sandbox and on the direct
// path: a URL under a denied path never reaches the report.
func TestKatanaKeepsToTheWebScope(t *testing.T) {
	for _, runtime := range []string{"", "in-process"} {
		t.Run("runtime="+runtime, func(t *testing.T) {
			t.Setenv(toolrun.EnvRuntime, runtime)
			opts := &core.ScanOptions{Capability: "crawl.web@1", MaxTier: "T1",
				WebScope: &webscope.Scope{DenyPaths: []string{"/a.html"}}}
			res, err := katanaScanner(t).ScanTargets(context.Background(), []string{"http://127.0.0.1:18777"}, opts)
			if err != nil {
				t.Fatal(err)
			}
			out := string(res.RawOutput)
			if strings.Contains(out, "/a.html") {
				t.Fatalf("a denied URL reached the report:\n%s", out)
			}
			if !strings.Contains(out, "127.0.0.1:18777") {
				t.Fatalf("the allowed start URL is missing:\n%s", out)
			}
		})
	}
}

// SECURITY: a job with a web scope never runs a tool that cannot keep to
// it, and an invalid scope is refused, never ignored.
func TestWebScopeFailsClosed(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	ws := &webscope.Scope{DenyPaths: []string{"/logout"}}
	_, err := httpxScanner(t).ScanTargets(context.Background(), []string{"https://example.com"},
		&core.ScanOptions{Capability: "probe.http@1", WebScope: ws})
	if err == nil || !strings.Contains(err.Error(), "web scope") {
		t.Fatalf("httpx ran with a web scope: %v", err)
	}
	_, err = katanaScanner(t).ScanTargets(context.Background(), []string{"http://127.0.0.1:18777"},
		&core.ScanOptions{Capability: "crawl.web@1", WebScope: &webscope.Scope{DenyPaths: []string{"logout"}}})
	if err == nil {
		t.Fatal("an invalid web scope was accepted")
	}
}
