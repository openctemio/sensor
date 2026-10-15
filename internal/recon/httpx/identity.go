package httpx

import (
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"

	"github.com/openctemio/sensor/internal/toolrun"
)

// WithIdentity returns a copy of the scanner that sends the job's
// identification (a program's User-Agent and headers) on every request:
// httpx's -H applies to all of them, and a configured header of the same
// name is dropped.
func (s *Scanner) WithIdentity(id *tool.Identity) (core.ReconScanner, error) {
	c := *s
	c.Headers = toolrun.IdentityHeaders(tool.Task{Identity: id}, s.Headers)
	for _, h := range c.Headers {
		if !toolrun.ValidHeaderLine(h) {
			return nil, fmt.Errorf("httpx: refusing header %q", h)
		}
	}
	return &c, nil
}
