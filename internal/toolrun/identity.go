package toolrun

import (
	"strings"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// IdentityHeaders is the header lines a tool that maps the job's
// identification onto its own header flags passes (features.http_identity):
// the configured lines, without any that names a header the identification
// sets (it wins), then the identification's lines (tool.Identity.HeaderLines:
// the User-Agent first, then the headers in name order). Without an
// identification the configured lines are returned unchanged.
func IdentityHeaders(task tool.Task, configured []string) []string {
	id := task.Identity
	if id.Empty() {
		return configured
	}
	out := make([]string, 0, len(configured)+len(id.Headers)+1)
	for _, h := range configured {
		if !id.Overrides(h) {
			out = append(out, h)
		}
	}
	return append(out, id.HeaderLines()...)
}

// ValidHeaderLine reports whether a "Name: value" line may go on a tool's
// argv: a name, a colon, printable characters, no leading dash (it would
// read as a flag) and no line break.
func ValidHeaderLine(h string) bool {
	name, _, ok := strings.Cut(h, ":")
	if !ok || strings.TrimSpace(name) == "" || strings.HasPrefix(h, "-") {
		return false
	}
	for _, r := range h {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
