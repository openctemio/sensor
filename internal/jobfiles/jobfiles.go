// Package jobfiles keeps a job's own files (a rewritten or signed copy of its
// custom templates or rules, its target list, the report its tool writes)
// where only that job's tool runs can read them.
//
// The tool sandbox leaves the system's temporary directory readable to every
// task. On a shared sensor a task of another organization, launched while a
// job runs, could read a file the sensor put there for that job: custom
// templates with their auth headers, the job's targets, its findings. A
// directory made here lies under the private task root, which the sandbox
// hides from every task, and the context returned grants it to the tool runs
// started with that context only (executor.NewJobDir). Run the tool with the
// returned context, or it cannot read the files and the scan fails visibly.
package jobfiles

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// Dir makes a private directory (0700) for one job's files and returns the
// context that grants it, the directory and a cleanup that removes it.
func Dir(ctx context.Context, prefix string) (context.Context, string, func(), error) {
	jctx, dir, err := executor.NewJobDir(ctx, prefix)
	if err != nil {
		return ctx, "", nil, fmt.Errorf("job directory: %w", err)
	}
	return jctx, dir, func() { _ = os.RemoveAll(dir) }, nil
}

// File writes content (0600) as name in a new private job directory (Dir) and
// returns the granting context, the file's path and a cleanup that removes
// the directory.
func File(ctx context.Context, prefix, name string, content []byte) (context.Context, string, func(), error) {
	jctx, dir, cleanup, err := Dir(ctx, prefix)
	if err != nil {
		return ctx, "", nil, err
	}
	path := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		cleanup()
		return ctx, "", nil, fmt.Errorf("job file: %w", err)
	}
	return jctx, path, cleanup, nil
}
