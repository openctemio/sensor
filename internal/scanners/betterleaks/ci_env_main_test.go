package betterleaks

import (
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
	"github.com/openctemio/sensor/internal/toolrun"
)

// TestMain clears the CI markers: converters file code findings on the CI
// job's repository when the caller names none, so a test run inside GitHub
// Actions or GitLab CI would otherwise see a repository a local run does not.
func TestMain(m *testing.M) {
	// This test binary is also the tool child of the out-of-process path.
	executor.RunLauncherIfRequested()
	adapter.Dispatch(toolrun.Registered()...)
	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	os.Exit(m.Run())
}
