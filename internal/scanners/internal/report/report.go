// Package report decides where a scanner writes the report file it reads back.
//
// A scanner must never write into the tree it scans: the target is often
// mounted read-only (a Kubernetes volume, `docker run -v repo:/scan:ro`), two
// scans of the same tree would overwrite each other's report, and a leftover
// report would land in the user's repository.
package report

import (
	"fmt"
	"os"
	"path/filepath"
)

// Path returns the path a scanner should pass to its tool for the report, and
// a cleanup function to call once the report has been read.
//
// An absolute configured path is the caller's explicit choice: it is used as
// is and cleanup does nothing. Otherwise (empty, or relative, such as the
// scanners' default file names) the report goes into a new private
// temporary directory, under the base name of configured (or def when
// configured is empty), and cleanup removes that directory.
func Path(configured, def, scanner string) (string, func(), error) {
	if configured != "" && filepath.IsAbs(configured) {
		return configured, func() {}, nil
	}
	name := def
	if configured != "" {
		name = filepath.Base(configured)
	}
	dir, err := os.MkdirTemp("", "openctem-"+scanner+"-*")
	if err != nil {
		return "", nil, fmt.Errorf("create %s report directory: %w", scanner, err)
	}
	return filepath.Join(dir, name), func() { _ = os.RemoveAll(dir) }, nil
}
