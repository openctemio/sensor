package content

import (
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool/adapter"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
)

// The test binary is also the tool child of the ported nuclei: wrapped
// scans run out of process, on the managed content the parent chose.
func TestMain(m *testing.M) {
	adapter.Dispatch(nuclei.Tool)
	os.Exit(m.Run())
}
