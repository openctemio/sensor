package executor

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// newTestWorkspace returns a workspace with a "repo" directory inside it, and
// a directory outside it holding a "secret" file.
func newTestWorkspace(t *testing.T) (ws *Workspace, root, outside string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(base, "workspace")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "repo"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws, err = NewWorkspace([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	return ws, root, outside
}

func TestWorkspaceConfine(t *testing.T) {
	ws, root, outside := newTestWorkspace(t)
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")

	for name, target := range map[string]string{
		"absolute path in the workspace": repo,
		"relative to the workspace":      "repo",
		"the workspace itself":           root,
		"dot segments that stay inside":  filepath.Join(root, "repo", "..", "repo"),
	} {
		got, err := checkTarget(ws, "semgrep", target)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != repo && got != root {
			t.Errorf("%s: resolved to %q", name, got)
		}
	}

	for name, target := range map[string]string{
		"traversal out of the workspace":     "../outside",
		"absolute path elsewhere":            outside,
		"symlink pointing out":               filepath.Join(root, "escape"),
		"file behind an escaping symlink":    "escape/secret",
		"sensitive system path":              "/etc",
		"home expansion":                     "~/.ssh",
		"looks like a flag":                  "--config=/tmp/x",
		"does not exist":                     "missing",
		"traversal through a missing parent": "missing/../../outside",
	} {
		if got, err := checkTarget(ws, "semgrep", target); err == nil {
			t.Errorf("%s: %q was allowed (resolved to %q)", name, target, got)
		}
	}
}

func TestWorkspaceRequiresARealRoot(t *testing.T) {
	if _, err := NewWorkspace([]string{"/"}); err == nil {
		t.Error("the filesystem root must not be accepted as a workspace")
	}
	if _, err := NewWorkspace(nil); err == nil {
		t.Error("an empty workspace must be an error")
	}
	for _, target := range []string{os.TempDir(), "repo", "."} {
		if got, err := checkTarget(nil, "semgrep", target); err == nil {
			t.Errorf("without a workspace filesystem targets are refused; %q was allowed as %q", target, got)
		}
	}
}

func TestWorkspaceFromEnv(t *testing.T) {
	_, root, outside := newTestWorkspace(t)
	env := map[string]string{EnvScanRoots: root + string(filepath.ListSeparator) + outside}
	ws, err := WorkspaceFromEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok }, "/")
	if err != nil {
		t.Fatal(err)
	}
	if got := ws.Roots(); len(got) != 2 || got[0] != root || got[1] != outside {
		t.Fatalf("roots = %v", got)
	}
	// Unset: the working directory.
	ws, err = WorkspaceFromEnv(func(string) (string, bool) { return "", false }, root)
	if err != nil || ws.Roots()[0] != root {
		t.Fatalf("cwd fallback: %v, %v", ws.Roots(), err)
	}
}

func TestScanTargetPolicyByScanner(t *testing.T) {
	ws, root, _ := newTestWorkspace(t)
	repo := filepath.Join(root, "repo")

	// Code scanners: a path is confined, not DNS-resolved (the QA failure:
	// "DNS lookup failed for scanner target /work/repo").
	for _, s := range []string{"betterleaks", "gitleaks", "semgrep", "trivy", "trivy-fs", "trivy-config", "Semgrep"} {
		got, err := checkTarget(ws, s, repo)
		if err != nil || got != repo {
			t.Errorf("%s on a workspace path: got %q, %v", s, got, err)
		}
	}
	if _, err := checkTarget(ws, "betterleaks", "../../etc"); err == nil {
		t.Error("a code scanner must not escape the workspace")
	}
	// A remote repository URL still goes through the SSRF guard.
	if _, err := checkTarget(ws, "semgrep", "http://127.0.0.1/repo.git"); err == nil {
		t.Error("a code scanner's URL target must be SSRF-guarded")
	}

	// Network and unknown scanners: SSRF guard, a path is not a host.
	for _, s := range []string{"nuclei", "httpx", "", "something-new"} {
		if _, err := checkTarget(ws, s, repo); err == nil {
			t.Errorf("%q must not accept a filesystem path", s)
		}
		if _, err := checkTarget(ws, s, "http://169.254.169.254/"); err == nil {
			t.Errorf("%q must block the metadata endpoint", s)
		}
	}

	// Container images.
	for _, ref := range []string{"nginx:latest", "alpine"} {
		if _, err := checkTarget(ws, "trivy-image", ref); err != nil {
			t.Errorf("trivy-image %q: %v", ref, err)
		}
	}
	if _, err := checkTarget(ws, "trivy-image", "169.254.169.254:5000/app:1"); err == nil {
		t.Error("an image on a blocked registry host must be refused")
	}
}

// End to end through the SDK executor with the sensor's policy: a code-scan
// command reaches the scanner with the confined absolute path; a path outside
// the workspace never reaches it.
func TestScanGuard_ConfinesCodeScanTargets(t *testing.T) {
	ws, root, _ := newTestWorkspace(t)
	sc := &recordingScanner{name: "betterleaks"}
	e := core.NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(ScanTargetPolicy(ws))

	if _, err := e.Execute(context.Background(), scanCmd(t, map[string]any{"scanner": "betterleaks", "target": "repo", "scan_id": "s-1"})); err != nil {
		t.Fatalf("a workspace path must be accepted: %v", err)
	}
	if want := filepath.Join(root, "repo"); !slices.Equal(sc.got(), []string{want}) {
		t.Fatalf("scanner got %v; want %q", sc.got(), want)
	}

	sc.reset()
	if _, err := e.Execute(context.Background(), scanCmd(t, map[string]any{"scanner": "semgrep", "target": "/etc"})); err == nil {
		t.Fatal("a path outside the workspace must be refused")
	}
	if sc.got() != nil {
		t.Fatalf("scanner ran on %v", sc.got())
	}
}

// checkTarget checks one target for scanner with the sensor's policy.
func checkTarget(ws *Workspace, scanner, target string) (string, error) {
	return ScanTargetPolicy(ws).ValidateFor(context.Background(), scanner, target)
}
