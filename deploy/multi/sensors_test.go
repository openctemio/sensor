package multi

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The kit's script runs against a docker stub that records every call, so
// these tests never touch a real container or volume.

const dockerStub = `#!/usr/bin/env bash
echo "$*" >>"$STUB_LOG"
case "$1 $2" in
  "compose config")
    case " $* " in
      *" --images "*) echo "ghcr.io/openctemio/sensor:v0.31.0" ;;
      *" --services "*) ;;
    esac ;;
  "image inspect") echo "nonroot" ;;
  "compose logs") echo "Paired: sensor ok" ;;
esac
exit 0
`

func setup(t *testing.T) (dir string, run func(args ...string) (string, error), calls func() string) {
	t.Helper()
	dir = t.TempDir()
	bin := t.TempDir()
	logf := filepath.Join(t.TempDir(), "calls.log")
	if err := os.WriteFile(logf, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(dockerStub), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"sensors.sh", "compose.yaml", ".env.example"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if f == "sensors.sh" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, mode); err != nil {
			t.Fatal(err)
		}
	}
	env, _ := os.ReadFile(filepath.Join(dir, ".env.example"))
	_ = os.WriteFile(filepath.Join(dir, ".env"), env, 0o600)
	if err := os.MkdirAll(filepath.Join(dir, "seccomp"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "seccomp", "sensor-v0.31.0.json"), []byte(`{"defaultAction":"x"}`), 0o644)
	run = func(args ...string) (string, error) {
		cmd := exec.Command("bash", append([]string{filepath.Join(dir, "sensors.sh")}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "STUB_LOG="+logf)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	calls = func() string { b, _ := os.ReadFile(logf); return string(b) }
	if out, err := run("add", "acme", "--api-url", "https://x.example.com"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if out, err := run("add", "beta"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	return dir, run, calls
}

func TestRepairArguments(t *testing.T) {
	_, run, calls := setup(t)
	for name, args := range map[string][]string{
		"no name":      {"repair"},
		"unknown name": {"repair", "nobody", "--pairing-code", "ABCD-EFGH", "--yes"},
		"no code":      {"repair", "acme", "--yes"},
		"short code":   {"repair", "acme", "--pairing-code", "ABC-EFGH", "--yes"},
		"letter I":     {"repair", "acme", "--pairing-code", "ABCD-EFGI", "--yes"},
		"letter U":     {"repair", "acme", "--pairing-code", "UBCD-EFGH", "--yes"},
		"bad flag":     {"repair", "acme", "--pairing-code", "ABCD-EFGH", "--bogus"},
		"path name":    {"repair", "../acme", "--pairing-code", "ABCD-EFGH", "--yes"},
	} {
		before := calls()
		if out, err := run(args...); err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
		if calls() != before {
			t.Errorf("%s: touched docker before refusing: %s", name, strings.TrimPrefix(calls(), before))
		}
	}
	// Without a terminal and without --yes it refuses and changes nothing.
	before := calls()
	if _, err := run("repair", "acme", "--pairing-code", "ABCD-EFGH"); err == nil {
		t.Error("repair went ahead without confirmation")
	}
	if calls() != before {
		t.Error("repair touched docker without confirmation")
	}
}

func TestRepairWipesOnlyTheIdentity(t *testing.T) {
	dir, run, calls := setup(t)
	out, err := run("repair", "acme", "--pairing-code", "abcd-efgh", "--yes")
	if err != nil {
		t.Fatalf("repair: %v\n%s", err, out)
	}
	if !strings.Contains(out, "This replaces the key of acme. Its current key keeps working until you approve the re-pair in the console, unless you revoked it there.") {
		t.Errorf("warning missing:\n%s", out)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "sensors", "acme", "sensor.env"))
	// Normalised: upper case, with the dash.
	if !strings.Contains(string(env), "SENSOR_PAIRING_CODE=ABCD-EFGH") && !strings.Contains(out, "Cleared the spent pairing code") {
		t.Errorf("code not written:\n%s", env)
	}
	log := calls()
	var rm string
	for _, l := range strings.Split(log, "\n") {
		if strings.HasPrefix(l, "run ") {
			rm = l
		}
	}
	for _, want := range []string{"--rm", "--network none", "--read-only", "--cap-drop ALL", "--user 65532:65532",
		"-v openctem-sensors_acme-data:/var/lib/openctem", "--entrypoint rm", "-rf /var/lib/openctem/state/identity"} {
		if !strings.Contains(rm, want) {
			t.Errorf("wipe command lacks %q: %s", want, rm)
		}
	}
	for _, bad := range []string{"outbox", "store", "content", "docker.sock", "beta"} {
		if strings.Contains(log, bad) {
			t.Errorf("repair mentions %q: %s", bad, log)
		}
	}
	if strings.Count(rm, "/var/lib/openctem") != 2 { // the mount and the one path
		t.Errorf("rm must name one path: %s", rm)
	}
	stop := strings.Index(log, "compose stop acme")
	wipe := strings.Index(log, "run --rm")
	pair := strings.Index(log, "compose up -d --force-recreate acme")
	if stop < 0 || wipe < stop || pair < wipe {
		t.Errorf("order must be stop, wipe, pair:\n%s", log)
	}
}

func TestRepairAcceptsCodeWithoutDash(t *testing.T) {
	dir, run, _ := setup(t)
	// Keep the code in the file: make pair fail to find "Paired" is not
	// needed, the env file is checked before pair clears it.
	if err := os.WriteFile(filepath.Join(dir, "sensors", "acme", "sensor.env"), []byte("SENSOR_PAIRING_CODE=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run("repair", "acme", "--pairing-code", "k7m2q9xa", "--yes")
	if err != nil {
		t.Fatalf("repair: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Wrote the pairing code") {
		t.Errorf("code not written:\n%s", out)
	}
}

func TestRemove(t *testing.T) {
	dir, run, calls := setup(t)
	if out, err := run("remove", "nobody", "--yes"); err == nil {
		t.Errorf("unknown sensor accepted\n%s", out)
	}
	if out, err := run("remove", "acme", "--bogus"); err == nil {
		t.Errorf("bad flag accepted\n%s", out)
	}
	if _, err := run("remove", "acme"); err == nil {
		t.Error("remove went ahead without confirmation")
	}
	if _, err := os.Stat(filepath.Join(dir, "sensors", "acme")); err != nil {
		t.Fatal("refused remove deleted the sensor")
	}

	out, err := run("remove", "acme", "--yes")
	if err != nil {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	if strings.Contains(calls(), "volume rm") {
		t.Error("remove without --purge deleted the volume")
	}
	if !strings.Contains(calls(), "compose rm -sf acme") || strings.Contains(calls(), "rm -sf beta") {
		t.Errorf("must remove only acme's service: %s", calls())
	}
	if !strings.Contains(out, "Revoke access") {
		t.Errorf("console reminder missing:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "sensors", "acme")); err == nil {
		t.Error("sensors/acme stayed")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	cf := raw[strings.Index(string(raw), "\nservices:"):] // the header comments name acme
	if strings.Contains(string(cf), "  acme:") || strings.Contains(string(cf), "acme-data") ||
		strings.Contains(string(cf), "sensors/acme/") {
		t.Errorf("acme blocks stayed in compose.yaml:\n%s", cf)
	}
	for _, keep := range []string{"  beta:", "beta-data: {}", "sensors/beta/policy", "  # sensors.sh add: new services above this line"} {
		if !strings.Contains(string(cf), keep) {
			t.Errorf("compose.yaml lost %q:\n%s", keep, cf)
		}
	}

	out, err = run("remove", "beta", "--purge", "--yes")
	if err != nil {
		t.Fatalf("purge: %v\n%s", err, out)
	}
	if !strings.Contains(calls(), "volume rm openctem-sensors_beta-data") || strings.Contains(calls(), "volume rm openctem-sensors_acme") {
		t.Errorf("purge must delete only beta's volume: %s", calls())
	}
	if !strings.Contains(out, "outbox") || !strings.Contains(out, "lost") {
		t.Errorf("purge must say the outbox is lost:\n%s", out)
	}
}
