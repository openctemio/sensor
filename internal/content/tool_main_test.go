package content

import (
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool/adapter"
	_ "github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/toolrun"
)

// The test binary is also the tool child of the ported tools (nuclei,
// trivy, ...): wrapped scans run out of process, on the managed content the
// parent chose.
func TestMain(m *testing.M) {
	adapter.Dispatch(toolrun.Registered()...)
	os.Exit(m.Run())
}
