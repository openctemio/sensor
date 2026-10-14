package executor

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Scan targets are classified by the scanner that will receive them.
//
// Network scanners (nuclei, the recon tools, unknown scanners) take hosts and
// URLs: those go through the network guard. Code scanners (betterleaks,
// semgrep, trivy filesystem modes, ...; core.IsCodeScanner) take a directory:
// a path target is confined to the sensor's scan workspace instead. Both
// checks run in the SDK executor (ScanTargetPolicy). Sending a path
// through the DNS guard refused every code scan ("DNS lookup failed for scanner
// target /work/repo"); skipping the guard for paths without confinement would
// let a dispatched job read any directory on the host (~/.ssh, /etc) back out
// as findings.

// EnvScanRoots lists the directories filesystem scan targets must live under
// (filepath.ListSeparator-separated, ':' on Unix). Unset: the directory the
// sensor was started in.
const EnvScanRoots = "SENSOR_SCAN_ROOTS"

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
