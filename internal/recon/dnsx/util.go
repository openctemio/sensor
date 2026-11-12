package dnsx

import (
	"context"
	"strings"

	"github.com/openctemio/sensor/internal/jobfiles"
)

// writeJobList writes lines, one per line, to a file in a new private job
// directory (jobfiles.File) and returns the context that grants it (run dnsx
// with it), the file's path and the cleanup. The job's hosts and labels never
// go into the system's temporary directory, where another organization's
// task on a shared sensor could read them.
func writeJobList(ctx context.Context, prefix string, lines []string) (context.Context, string, func(), error) {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return jobfiles.File(ctx, prefix, "list.txt", []byte(b.String()))
}
