package executor

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Scan targets are classified by the scanner that will receive them.
//
// Network scanners (nuclei, the recon tools, unknown scanners) take hosts and
// URLs: those go through the SSRF guard (validateScannerTarget). Code scanners
// (betterleaks, semgrep, trivy filesystem modes, ...) take a directory: a path
// target is confined to the sensor's scan workspace instead. Sending a path
// through the DNS guard refused every code scan ("DNS lookup failed for scanner
// target /work/repo"); skipping the guard for paths without confinement would
// let a dispatched job read any directory on the host (~/.ssh, /etc) back out
// as findings.

// EnvScanRoots lists the directories filesystem scan targets must live under
// (filepath.ListSeparator-separated, ':' on Unix). Unset: the directory the
// sensor was started in.
const EnvScanRoots = "SENSOR_SCAN_ROOTS"

// codeScanners take a filesystem path (or a remote repository URL) as their
// target. Everything else is treated as a network scanner.
var codeScanners = map[string]bool{
	"betterleaks":  true,
	"trufflehog":   true,
	"semgrep":      true,
	"codeql":       true,
	"bandit":       true,
	"gosec":        true,
	"checkov":      true,
	"tfsec":        true,
	"kics":         true,
	"trivy":        true,
	"trivy-fs":     true,
	"trivy-config": true,
	"trivy-full":   true,
	"trivy-image":  true,
}

// trivyScanners accept a container-image reference as well as a path.
var trivyScanners = map[string]bool{
	"trivy": true, "trivy-fs": true, "trivy-full": true, "trivy-image": true,
}

// IsCodeScanner reports whether scanner takes a filesystem path target.
func IsCodeScanner(scanner string) bool {
	return codeScanners[strings.ToLower(strings.TrimSpace(core.CanonicalScannerName(scanner)))]
}

// Workspace is the set of directories code-scanner targets are confined to.
type Workspace struct {
	roots []string // absolute, symlink-resolved
}

// NewWorkspace resolves roots (absolute, symlinks followed). A root that does
// not exist or is the filesystem root is an error: confining to "/" confines
// nothing.
func NewWorkspace(roots []string) (*Workspace, error) {
	ws := &Workspace{}
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		abs, err := filepath.Abs(r)
		if err != nil {
			return nil, fmt.Errorf("scan root %q: %w", r, err)
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, fmt.Errorf("scan root %q: %w", r, err)
		}
		if filepath.Dir(resolved) == resolved {
			return nil, fmt.Errorf("scan root %q is the filesystem root; set %s to the directory that holds the code to scan", r, EnvScanRoots)
		}
		ws.roots = append(ws.roots, resolved)
	}
	if len(ws.roots) == 0 {
		return nil, fmt.Errorf("no scan root configured")
	}
	return ws, nil
}

// WorkspaceFromEnv builds the workspace from SENSOR_SCAN_ROOTS, falling back
// to cwd (the directory the sensor runs in: /scan in the container images).
func WorkspaceFromEnv(lookup func(string) (string, bool), cwd string) (*Workspace, error) {
	if v, ok := lookup(EnvScanRoots); ok && strings.TrimSpace(v) != "" {
		return NewWorkspace(filepath.SplitList(v))
	}
	return NewWorkspace([]string{cwd})
}

// Roots returns the resolved workspace directories.
func (w *Workspace) Roots() []string {
	if w == nil {
		return nil
	}
	return append([]string(nil), w.roots...)
}

// Confine resolves a filesystem target inside the workspace and returns the
// absolute, symlink-resolved path the scanner must use. A relative target is
// taken relative to the first root. The resolved path must be a root or lie
// under one (so "..", absolute paths elsewhere and symlinks pointing out are
// refused), and must not be a sensitive host directory.
func (w *Workspace) Confine(target string) (string, error) {
	if w == nil || len(w.roots) == 0 {
		return "", fmt.Errorf("no scan workspace is configured, so filesystem targets are refused; set %s", EnvScanRoots)
	}
	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("scan target is required")
	}
	if strings.HasPrefix(target, "-") {
		return "", fmt.Errorf("scan target %q looks like a command-line flag", target)
	}
	if strings.HasPrefix(target, "~") {
		return "", fmt.Errorf("scan target %q: '~' is not expanded; use a path inside the scan workspace", target)
	}
	if strings.ContainsRune(target, 0) {
		return "", fmt.Errorf("scan target contains a NUL byte")
	}

	p := target
	if !filepath.IsAbs(p) {
		p = filepath.Join(w.roots[0], p)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(p))
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("scan target %q does not exist in the scan workspace", target)
		}
		return "", fmt.Errorf("scan target %q: %w", target, err)
	}
	for _, root := range w.roots {
		if isWithinDir(root, resolved) {
			// Defense in depth: a workspace configured over a sensitive
			// directory must still not expose it.
			if _, err := confineScanPath(resolved); err != nil {
				return "", err
			}
			return resolved, nil
		}
	}
	return "", fmt.Errorf("scan target %q is outside the scan workspace (%s)", target, strings.Join(w.roots, string(filepath.ListSeparator)))
}

// isWithinDir reports whether path is root or lies under it; both are clean
// absolute paths.
func isWithinDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

// checkScanTarget validates one target for scanner and returns the value the
// scanner must receive (a confined absolute path for filesystem targets, the
// target unchanged otherwise).
func checkScanTarget(ws *Workspace, scanner, target string) (string, error) {
	if !IsCodeScanner(scanner) {
		return target, validateScannerTarget(target)
	}
	// A remote repository URL is fetched over the network: SSRF-guard it.
	if strings.Contains(target, "://") {
		return target, validateScannerTarget(target)
	}
	name := strings.ToLower(strings.TrimSpace(scanner))
	if trivyScanners[name] && (name == "trivy-image" || isTrivyImageRef(target)) {
		// A container-image reference (nginx:latest, ghcr.io/org/app:1) is
		// pulled from its registry: guard an explicit registry host.
		return target, checkImageRegistry(target)
	}
	return ws.Confine(target)
}

// checkImageRegistry SSRF-guards the registry host of an image reference when
// the reference names one ("registry.example.com/app:1", "10.0.0.5:5000/app").
// A bare name ("nginx:latest") uses the default registry and has no host here.
func checkImageRegistry(ref string) error {
	ref = strings.TrimPrefix(ref, "docker:")
	first, _, hasPath := strings.Cut(ref, "/")
	if !hasPath || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		return nil
	}
	host := strings.Trim(first, "[]")
	if h, _, err := net.SplitHostPort(first); err == nil {
		host = h
	}
	return validateScannerTarget(host)
}
