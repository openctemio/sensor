package multi

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
      *" --images "*) echo "ghcr.io/openctemio/sensor:$STUB_VERSION" ;;
      *" --services "*) [ -n "${STUB_SERVICES:-}" ] && echo "$STUB_SERVICES" ;;
    esac ;;
  "image inspect") echo "nonroot" ;;
  "compose logs") printf '%b\n' "${STUB_LOGS:-Paired: sensor ok}" ;;
  "compose ps") echo "${STUB_STATE:-running}" ;;
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
	// The release the kit pins (.env.example), so a version bump never breaks this.
	version := ""
	for _, l := range strings.Split(string(env), "\n") {
		if v, ok := strings.CutPrefix(l, "SENSOR_VERSION="); ok {
			version = strings.TrimSpace(v)
		}
	}
	t.Setenv("STUB_VERSION", version)
	_ = os.WriteFile(filepath.Join(dir, "seccomp", "sensor-"+version+".json"), []byte(`{"defaultAction":"x"}`), 0o644)
	run = func(args ...string) (string, error) {
		cmd := exec.Command("bash", append([]string{filepath.Join(dir, "sensors.sh")}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "STUB_LOG="+logf)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	calls = func() string { b, _ := os.ReadFile(logf); return string(b) }
	if out, err := run("add", "acme", "--api-url", "https://x.example.com", "--no-start"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if out, err := run("add", "beta", "--no-start"); err != nil {
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

func TestAddStartsAndPairsInOneCommand(t *testing.T) {
	dir, run, calls := setup(t)
	before := calls()
	out, err := run("add", "gamma", "--api-url", "https://x.example.com/")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	log := strings.TrimPrefix(calls(), before)
	for _, want := range []string{"compose up -d gamma", "compose logs -f --no-log-prefix --tail 200 gamma"} {
		if !strings.Contains(log, want) {
			t.Errorf("add did not %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "beta") || strings.Contains(log, "acme") {
		t.Errorf("add touched another sensor:\n%s", log)
	}
	if !strings.Contains(out, "gamma is paired and running") || !strings.Contains(out, "follows your organization's scope") {
		t.Errorf("output:\n%s", out)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "sensors", "gamma", "sensor.env"))
	if !strings.Contains(string(env), "SENSOR_API_URL=https://x.example.com\n") {
		t.Errorf("api url not normalised:\n%s", env)
	}
	// No policy at install: the line is there to uncomment, never active.
	for _, l := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(l, "SENSOR_LOCAL_POLICY=") {
			t.Errorf("an active local policy was written: %s", l)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "sensors", "gamma", "policy", "sensor-policy.yaml")); err == nil {
		t.Error("a policy file was written for a kit that does not need one")
	}
	cf, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if strings.Contains(string(cf), "    SENSOR_LOCAL_POLICY:") {
		t.Error("the kit's compose.yaml still requires a local policy for every sensor")
	}
}

func TestAddArguments(t *testing.T) {
	dir, run, calls := setup(t)
	pem := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(pem, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o644)
	notPEM := filepath.Join(t.TempDir(), "ca.txt")
	_ = os.WriteFile(notPEM, []byte("hello"), 0o644)
	for name, args := range map[string][]string{
		"no api url":   {"add", "delta"},
		"bad api url":  {"add", "delta", "--api-url", "ftp://x"},
		"missing ca":   {"add", "delta", "--api-url", "https://x.example.com", "--ca-file", "/nonexistent"},
		"ca not a PEM": {"add", "delta", "--api-url", "https://x.example.com", "--ca-file", notPEM},
	} {
		before := calls()
		if out, err := run(args...); err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
		if calls() != before {
			t.Errorf("%s: touched docker before refusing", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "sensors", "delta")); err == nil {
			t.Errorf("%s: left sensors/delta behind", name)
		}
	}
	out, err := run("add", "delta", "--api-url", "https://x.example.com", "--ca-file", pem, "--no-start")
	if err != nil {
		t.Fatalf("add with a CA: %v\n%s", err, out)
	}
	ca, err := os.Stat(filepath.Join(dir, "sensors", "delta", "policy", "platform-ca.pem"))
	if err != nil || ca.Mode().Perm() != 0o644 {
		t.Fatalf("CA not installed: %v", err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "sensors", "delta", "sensor.env"))
	if !strings.Contains(string(env), "\nSENSOR_CA_CERT_FILE=/etc/openctem/policy/platform-ca.pem\n") {
		t.Errorf("CA not configured:\n%s", env)
	}
	if st, _ := os.Stat(filepath.Join(dir, "sensors", "delta", "sensor.env")); st.Mode().Perm() != 0o600 {
		t.Errorf("sensor.env mode %v", st.Mode().Perm())
	}
}

// A directory set up with an older kit reads a policy file for every sensor:
// add writes one that narrows nothing (no active allow list) and says so.
func TestAddInAnOlderKitWritesAFileThatNarrowsNothing(t *testing.T) {
	dir, run, _ := setup(t)
	cf := filepath.Join(dir, "compose.yaml")
	raw, _ := os.ReadFile(cf)
	old := strings.Replace(string(raw), "    SENSOR_KILL_SWITCH_FILE:", "    SENSOR_LOCAL_POLICY: /etc/openctem/policy/sensor-policy.yaml\n    SENSOR_KILL_SWITCH_FILE:", 1)
	_ = os.WriteFile(cf, []byte(old), 0o644)
	out, err := run("add", "omega", "--no-start")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	p, err := os.ReadFile(filepath.Join(dir, "sensors", "omega", "policy", "sensor-policy.yaml"))
	if err != nil || regexp.MustCompile(`(?m)^\s*allow:`).Match(p) {
		t.Fatalf("older kit: the file must exist and hold no active allow list: %v\n%s", err, p)
	}
	if !strings.Contains(out, "reads a local policy file") {
		t.Errorf("older kit not explained:\n%s", out)
	}
}

func TestStopStartDownNeverDeleteVolumes(t *testing.T) {
	_, run, calls := setup(t)
	for _, args := range [][]string{{"stop", "acme"}, {"start", "acme"}, {"down"}} {
		if out, err := run(args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	log := calls()
	for _, want := range []string{"compose stop acme", "compose up -d acme", "compose down --remove-orphans"} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q:\n%s", want, log)
		}
	}
	for _, bad := range []string{" -v", "--volumes", "volume rm"} {
		if strings.Contains(log, bad) {
			t.Errorf("stop/start/down ran %q:\n%s", bad, log)
		}
	}
	if out, err := run("stop", "nobody"); err == nil {
		t.Errorf("stop of an unknown sensor accepted\n%s", out)
	}
}

func TestStatusSaysWhatEachSensorWaitsFor(t *testing.T) {
	_, run, _ := setup(t)
	t.Setenv("STUB_SERVICES", "acme")
	for logs, want := range map[string]string{
		"Pair this sensor: open https://x.example.com/activate?code=K7QM-4ZTD\n  Code: K7QM-4ZTD":    "waiting for approval: open https://x.example.com/activate?code=K7QM-4ZTD",
		"Paired: sensor acme\nPreflight: 12 passed, 0 failed":                                        "running and paired",
		"pairing: the platform's TLS certificate is signed by an authority this host does not trust": "certificate authority is not trusted",
	} {
		t.Setenv("STUB_LOGS", logs)
		out, err := run("status")
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("logs %q: status %v\n%s", logs, err, out)
		}
	}
}

// upgrade shows docker's pull progress: a silent pull looked like a hang.
func TestUpgradePullShowsProgress(t *testing.T) {
	raw, err := os.ReadFile("sensors.sh")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`docker pull (-q|--quiet)|docker pull[^\n]*>/dev/null`).Match(raw) {
		t.Error("upgrade pulls quietly; show docker's progress")
	}
	if !strings.Contains(string(raw), `timeout "$PULL_TIMEOUT_SECONDS" docker pull`) {
		t.Error("upgrade's pull has no timeout")
	}
}
