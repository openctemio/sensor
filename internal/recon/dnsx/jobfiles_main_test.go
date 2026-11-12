package dnsx

import (
	"os"
	"testing"

	"github.com/openctemio/sensor/internal/jobfiles/jobfilestest"
)

// TestMain: this test binary is also the sandbox launcher and the reading
// tool of the job-file privacy tests (jobfilestest).
func TestMain(m *testing.M) {
	jobfilestest.RunToolIfRequested()
	os.Exit(m.Run())
}
