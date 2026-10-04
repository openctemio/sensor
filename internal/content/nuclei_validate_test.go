package content

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// validatingNuclei is a nuclei stand-in for Verify: -tl lists every .yaml
// under -t; -validate prints one "[ERR] Error occurred parsing template"
// line per template whose body contains "broken" and exits 1 if any, as
// nuclei v3.11.1 does. Both fail unless nuclei was given a private
// configuration naming the template directory (XDG_CONFIG_HOME).
func validatingNuclei(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in")
	}
	bin := filepath.Join(t.TempDir(), "nuclei")
	script := `#!/bin/sh
dir=""; validate=0
while [ $# -gt 0 ]; do
  case "$1" in
    -t) dir="$2"; shift ;;
    -validate) validate=1 ;;
  esac
  shift
done
grep -q "\"nuclei-templates-directory\":\"$dir\"" "$XDG_CONFIG_HOME/nuclei/.templates-config.json" || { echo "[FTL] no private config" >&2; exit 3; }
if [ "$validate" = 1 ]; then
  bad=$(grep -l broken $(find "$dir" -name '*.yaml'))
  [ -z "$bad" ] && exit 0
  for f in $bad; do echo "[ERR] Error occurred parsing template $f: could not compile request" >&2; done
  echo "[FTL] Could not validate templates: errors occurred during template validation" >&2
  exit 1
fi
find "$dir" -name '*.yaml' | sed 's|.*/||'
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test stand-in must be executable
		t.Fatal(err)
	}
	return bin
}

func templateDir(t *testing.T, good, broken int) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "http"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < good+broken; i++ {
		body := "id: ok\n"
		if i >= good {
			body = "id: broken\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "http", fmt.Sprintf("t%d.yaml", i)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A release passes when nuclei validates it with the configuration scans
// use, and records that it did.
func TestNucleiVerifyValidates(t *testing.T) {
	src := &NucleiTemplates{Binary: validatingNuclei(t), MinTemplates: 5}
	m := &Meta{Version: "v10.4.9"}
	if err := src.Verify(context.Background(), templateDir(t, 6, 0), m); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.Checks, "nuclei-validate") {
		t.Fatalf("checks %v", m.Checks)
	}
}

// More templates failing validation than allowed: the release is refused
// (the current version stays). Within the allowance it installs, with the
// count recorded.
func TestNucleiVerifyRefusesTemplateErrors(t *testing.T) {
	bin := validatingNuclei(t)
	dir := templateDir(t, 6, 3)

	src := &NucleiTemplates{Binary: bin, MinTemplates: 5, MaxTemplateErrors: 2}
	err := src.Verify(context.Background(), dir, &Meta{Version: "v10.4.9"})
	if err == nil || !strings.Contains(err.Error(), "3 templates fail") {
		t.Fatalf("err = %v, want 3 templates failing", err)
	}

	src.MaxTemplateErrors = 3
	m := &Meta{Version: "v10.4.9"}
	if err := src.Verify(context.Background(), dir, m); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.Checks, "nuclei-validate-3-errors") {
		t.Fatalf("checks %v", m.Checks)
	}

	// SENSOR_CONTENT_NUCLEI_MAX_TEMPLATE_ERRORS=0: none allowed.
	src.MaxTemplateErrors = -1
	if err := src.Verify(context.Background(), templateDir(t, 6, 1), &Meta{}); err == nil {
		t.Fatal("a failing template accepted with none allowed")
	}
}

func TestNucleiMaxTemplateErrorsFromEnv(t *testing.T) {
	env := func(v string) func(string) (string, bool) {
		return func(k string) (string, bool) {
			if k == EnvNucleiMaxErrors {
				return v, true
			}
			return "", false
		}
	}
	for v, want := range map[string]int{"0": -1, "25": 25} {
		s, err := SettingsFromEnv(env(v))
		if err != nil || s.NucleiMaxErrors != want {
			t.Errorf("%s=%s: %d %v, want %d", EnvNucleiMaxErrors, v, s.NucleiMaxErrors, err, want)
		}
	}
	if _, err := SettingsFromEnv(env("-1")); err == nil {
		t.Error("negative value accepted")
	}
	if (&NucleiTemplates{}).maxTemplateErrors() != DefaultNucleiMaxTemplateErrors {
		t.Error("default allowance")
	}
}

// The image's baked templates are imported with the release and archive
// digest the image build recorded, so a finding from a fresh sensor names
// its template set exactly like one from a downloaded release.
func TestNucleiBakedReleaseDigest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	baked := filepath.Join(home, "nuclei-templates")
	cfg := filepath.Join(home, ".config", "nuclei")
	for _, d := range []string{baked, cfg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(baked, "a.yaml"), []byte("id: a"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:d7cd989935f9a84943cba8a193f567db37626dbf4e526ff57ba5b1f24badd5d6"
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(cfg, BakedReleaseFile), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":"v10.4.9","digest":"` + digest + `","updated_at":"2026-09-16T14:50:00Z"}`)
	src := &NucleiTemplates{BakedDir: baked}
	_, m, ok := src.Baked()
	if !ok || m.Version != "v10.4.9" || m.Digest != digest || m.Source != "image" ||
		m.UpdatedAt == nil || !m.UpdatedAt.Equal(time.Date(2026, 9, 16, 14, 50, 0, 0, time.UTC)) {
		t.Fatalf("baked meta %+v", m)
	}

	// A malformed record is ignored: the version nuclei recorded, no digest.
	write(`{"version":"v10.4.9","digest":"md5:abc"}`)
	if err := os.WriteFile(filepath.Join(cfg, ".templates-config.json"), []byte(`{"nuclei-templates-version":"v10.4.8"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, m, _ = src.Baked(); m.Version != "v10.4.8" || m.Digest != "" {
		t.Fatalf("malformed record used: %+v", m)
	}
}

// A baked set is dated by its release, not by the image build: a release
// published after the baked one but before the build must not read as a
// rollback, and a forced refresh of the very same content is no rollback.
func TestBakedSetDatedByReleaseAndForcedSameContent(t *testing.T) {
	baked := t.TempDir()
	if err := os.WriteFile(filepath.Join(baked, "data"), []byte("v10.4.9"), 0o644); err != nil {
		t.Fatal(err)
	}
	released := time.Date(2026, 9, 16, 14, 50, 0, 0, time.UTC)
	src := fakeImporter{fakeSource: newFake(), dir: baked}
	src.meta = &Meta{Version: "v10.4.9", Digest: "sha256:aa", UpdatedAt: &released, Source: "image"}
	src.set("v10.4.9", "sha256:aa", released)
	m := newTestManager(t, src)

	// An image without a recorded release date is dated by its build: the
	// same release, forced, is still the same content, not a rollback.
	built := released.Add(18 * 24 * time.Hour)
	old := fakeImporter{fakeSource: newFake(), dir: baked}
	old.meta = &Meta{Version: "v10.4.9", Digest: "sha256:aa", UpdatedAt: &built, Source: "image"}
	old.set("v10.4.9", "sha256:aa", released)
	if res := newTestManager(t, old).Refresh(context.Background(), nil, true); res[0].Err != nil {
		t.Fatalf("forced refresh of the baked release: %v", res[0].Err)
	}
	// A newer release (published before any image build of today) installs.
	src.set("v10.5.0", "sha256:bb", released.Add(48*time.Hour))
	if res := m.Refresh(context.Background(), nil, false); !res[0].Refreshed {
		t.Fatalf("newer release %+v", res[0])
	}
	// An older one is still refused.
	src.set("v10.4.8", "sha256:cc", released.Add(-48*time.Hour))
	if res := m.Refresh(context.Background(), nil, false); res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "rollback") {
		t.Fatalf("older release %+v", res[0])
	}
}
