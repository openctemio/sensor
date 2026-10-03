package trivy

import (
	"os"
	"testing"
)

// TestMain clears the CI markers: converters file code findings on the CI
// job's repository when the caller names none, so a test run inside GitHub
// Actions or GitLab CI would otherwise see a repository a local run does not.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	os.Exit(m.Run())
}
