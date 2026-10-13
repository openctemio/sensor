package nuclei

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/webscope"
	"github.com/openctemio/sensor/internal/egressenv"
	"github.com/openctemio/sensor/internal/toolrun"
)

var denyAdmin = &webscope.Scope{DenyPaths: []string{"/admin"}}

func enforced(t *testing.T, v bool) {
	t.Helper()
	prev := webScopeEnforced
	webScopeEnforced = func() bool { return v }
	t.Cleanup(func() { webScopeEnforced = prev })
}

// nuclei declares features.web_scope, so a web-scoped capability job is no
// longer refused by the job check itself.
func TestManifestDeclaresWebScope(t *testing.T) {
	if ToolManifest.Features == nil || !ToolManifest.Features.WebScope {
		t.Fatal("nuclei does not declare features.web_scope")
	}
	t.Setenv(toolrun.EnvRuntime, "")
	if _, _, err := toolrun.ApplyJob(context.Background(), ToolManifest, settingsSchema,
		&core.ScanOptions{Capability: "vuln.templates@1", WebScope: denyAdmin}); err != nil {
		t.Fatalf("web-scoped job: %v", err)
	}
}

// SECURITY: on a sensor that does not run nuclei confined to the task's
// forwarder, a web-scoped job is refused before nuclei runs (it would run
// unrestricted), for one target and for a list; a job without a web scope
// runs as before.
func TestWebScopeRefusedUnconfined(t *testing.T) {
	enforced(t, false)
	bin, argsFile := fakeToolNuclei(t, 1)
	opts := &core.ScanOptions{Capability: "vuln.templates@1", WebScope: denyAdmin}
	if _, err := scanner(bin).Scan(context.Background(), "http://203.0.113.10", opts); !errors.Is(err, ErrWebScopeUnconfined) {
		t.Fatalf("Scan: %v", err)
	}
	if _, err := scanner(bin).ScanTargets(context.Background(), []string{"http://203.0.113.10", "http://203.0.113.11"}, opts); !errors.Is(err, ErrWebScopeUnconfined) {
		t.Fatalf("ScanTargets: %v", err)
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("nuclei ran")
	}
	if !strings.Contains(ErrWebScopeUnconfined.Error(), "web scope") {
		t.Fatalf("message %q", ErrWebScopeUnconfined)
	}
	if _, err := scanner(bin).Scan(context.Background(), "http://203.0.113.10", &core.ScanOptions{Capability: "vuln.templates@1"}); err != nil {
		t.Fatalf("a job without a web scope: %v", err)
	}
}

// SECURITY: the tool child refuses a web-scoped task when it was not given
// a forwarder (the parent's check bypassed or wrong): nuclei never runs.
func TestToolChildRefusesWebScopeWithoutForwarder(t *testing.T) {
	enforced(t, true) // the parent believes it is confined; the child is not
	t.Setenv(toolrun.EnvRuntime, "")
	bin, argsFile := fakeToolNuclei(t, 1)
	_, err := scanner(bin).Scan(context.Background(), "http://203.0.113.10", &core.ScanOptions{Capability: "vuln.templates@1", WebScope: denyAdmin})
	if err == nil || !strings.Contains(err.Error(), "web scope") {
		t.Fatalf("unconfined child: %v", err)
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("nuclei ran")
	}
}

// A web-scoped run always uses the forwarder's relay as its proxy (never
// the operator's), leaves out the template protocols the forwarder cannot
// read as HTTP or would answer for itself (ssl), and runs no headless
// browser.
func TestWebScopeArgs(t *testing.T) {
	t.Setenv(egressenv.EnvProxy, "http://127.0.0.1:1080")
	s := NewScanner()
	s.Proxy = "http://operator-proxy.internal:3128"
	s.Headless = true
	plain := s.buildArgs("https://example.com", nil)
	if i := slices.Index(plain, "-proxy"); i < 0 || plain[i+1] != s.Proxy {
		t.Fatalf("without a web scope %q: want the operator's proxy", plain)
	}
	if slices.Contains(plain, "-ept") || !slices.Contains(plain, "-headless") {
		t.Fatalf("without a web scope %q", plain)
	}
	s.webScoped = true
	args := s.buildArgs("https://example.com", nil)
	if i := slices.Index(args, "-proxy"); i < 0 || args[i+1] != "http://127.0.0.1:1080" || slices.Contains(args, s.Proxy) {
		t.Fatalf("web-scoped args %q: want only the relay as proxy", args)
	}
	i := slices.Index(args, "-ept")
	if i < 0 {
		t.Fatalf("web-scoped args %q: no -ept", args)
	}
	for _, typ := range []string{"ssl", "tcp", "javascript", "websocket", "headless", "code"} {
		if !slices.Contains(strings.Split(args[i+1], ","), typ) {
			t.Errorf("-ept %s leaves %s in", args[i+1], typ)
		}
	}
	if slices.Contains(args, "-headless") {
		t.Fatalf("web-scoped args %q run a headless browser", args)
	}
}
