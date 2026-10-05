package nuclei

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// The re-verification gives the same outcome, summary, digest and evidence
// out of process (in the task sandbox, through the runtime) as the direct
// path, for every outcome the verdict rule maps: detected, not detected,
// and each inconclusive shape (excluded tag, not installed, a nuclei exit,
// the no-templates message).
func TestValidateOutOfProcessParity(t *testing.T) {
	bin := fakeNucleiBin(t)
	for _, id := range []string{"clean-detect", "clean-nomatch", "activemq-upload", "not-installed", "exit-two", "no-tpl-exit0"} {
		t.Setenv(toolrun.EnvRuntime, "in-process")
		direct := validateWith(t, bin, id)
		t.Setenv(toolrun.EnvRuntime, "")
		oop := validateWith(t, bin, id)
		a, _ := json.Marshal(direct)
		b, _ := json.Marshal(oop)
		if string(a) != string(b) {
			t.Errorf("%s: outcomes differ\n--- direct\n%s\n--- out of process\n%s", id, a, b)
		}
	}
}

// An argument the direct path refuses (a traversal-shaped template id) is
// refused out of process too, before nuclei runs.
func TestValidateOutOfProcessRefusesSuspiciousID(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	_, err := ValidateSingleTemplate(context.Background(), ValidateOptions{Target: "http://t", TemplateID: "../etc", Binary: fakeNucleiBin(t)})
	if err == nil || !strings.Contains(err.Error(), "suspicious template id") {
		t.Fatalf("err = %v", err)
	}
}

// denyPolicy refuses the targets it lists.
type denyPolicy struct{ deny string }

func (p denyPolicy) AllowsTool(string) bool { return true }
func (p denyPolicy) CheckTarget(_ context.Context, target string) error {
	if strings.Contains(target, p.deny) {
		return os.ErrPermission
	}
	return nil
}
func (p denyPolicy) CapTimeout(d time.Duration) time.Duration { return d }
func (p denyPolicy) KillSwitchEngaged() bool                  { return false }

// The re-verify target is the task's target: the runtime admits it against
// the sensor-local policy, and a refused target never reaches nuclei.
func TestValidateOutOfProcessAdmitsTargetAgainstPolicy(t *testing.T) {
	dir := t.TempDir()
	ran := filepath.Join(dir, "ran")
	bin := filepath.Join(dir, "nuclei")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch "+ran+"\nexit 0\n"), 0o700); err != nil { //nolint:gosec // a test script must be executable
		t.Fatal(err)
	}
	toolrun.SetAdmission(denyPolicy{deny: "refused.example"}, tool.Daemon)
	t.Cleanup(func() { toolrun.SetAdmission(nil, "") })
	t.Setenv(toolrun.EnvRuntime, "")
	_, err := ValidateSingleTemplate(context.Background(), ValidateOptions{Target: "http://refused.example", TemplateID: "clean-detect", Binary: bin})
	if err == nil {
		t.Fatal("a target the local policy refuses was re-verified")
	}
	if _, serr := os.Stat(ran); serr == nil {
		t.Fatal("nuclei ran for a refused target")
	}
}

func TestValidateToolManifest(t *testing.T) {
	if err := ValidateToolManifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if ValidateToolManifest.Permissions.Network != tool.NetTargets || ValidateToolManifest.Tier != tool.T1 {
		t.Fatalf("manifest %+v", ValidateToolManifest.Permissions)
	}
}
