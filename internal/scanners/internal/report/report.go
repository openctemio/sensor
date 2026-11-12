// Package report decides where a scanner writes the report file it reads back.
//
// A scanner must never write into the tree it scans: the target is often
// mounted read-only (a Kubernetes volume, `docker run -v repo:/scan:ro`), two
// scans of the same tree would overwrite each other's report, and a leftover
// report would land in the user's repository.
package report

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/openctemio/sensor/internal/jobfiles"
)

// Path returns the path a scanner should pass to its tool for the report, the
// context to run the tool with, and a cleanup function to call once the
// report has been read.
//
// An absolute configured path is the caller's explicit choice: it is used as
// is, ctx is returned unchanged and cleanup does nothing. Otherwise (empty, or
// relative, such as the scanners' default file names) the report goes into a
// new private job directory (jobfiles.Dir), under the base name of configured
// (or def when configured is empty); the returned context grants that
// directory to the job's own tool runs only, and cleanup removes it. The
// report holds the job's findings: it never goes into the system's temporary
// directory, which another organization's task on a shared sensor can read.
func Path(ctx context.Context, configured, def, scanner string) (context.Context, string, func(), error) {
	if configured != "" && filepath.IsAbs(configured) {
		return ctx, configured, func() {}, nil
	}
	name := def
	if configured != "" {
		name = filepath.Base(configured)
	}
	jctx, dir, cleanup, err := jobfiles.Dir(ctx, "openctem-"+scanner)
	if err != nil {
		return ctx, "", nil, fmt.Errorf("create %s report directory: %w", scanner, err)
	}
	return jctx, filepath.Join(dir, name), cleanup, nil
}
