package multi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The kit's script runs against a docker stub that records every call, so
// these tests never touch a real container or volume.

const dockerStub = `#!/usr/bin/env bash
echo "$*" >>"$STUB_LOG"
case " $* " in
  *" verify-blob "*) [ -n "${STUB_COSIGN_FAIL:-}" ] && exit 1 ;;
esac
case "$1 $2" in
  "compose config")
    [ -n "${STUB_CONFIG_FAIL:-}" ] && exit 1
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

// testCA writes a PEM bundle of n self-signed CA certificates and returns
// the path with each certificate's common name and SHA-256 (lowercase hex).
func testCA(t *testing.T, n int) (path string, names, sums []string) {
	t.Helper()
	var bundle []byte
	for i := 0; i < n; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("Test Private CA %d", i+1)
		tpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(der)
		names = append(names, name)
		sums = append(sums, hex.EncodeToString(sum[:]))
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	path = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, names, sums
}

func readEnv(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "sensors", name, "sensor.env"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetCASha256(t *testing.T) {
	dir, run, calls := setup(t)
	upper := strings.ToUpper(strings.Repeat("ab", 32))
	colons := strings.TrimSuffix(strings.Repeat(strings.ToUpper("cd")+":", 32), ":")
	out, err := run("set-ca", "acme", "--sha256", colons)
	if err != nil {
		t.Fatalf("set-ca: %v\n%s", err, out)
	}
	want := strings.Repeat("cd", 32)
	env := readEnv(t, dir, "acme")
	if !strings.Contains(env, "\nSENSOR_CA_SHA256="+want+"\n") || strings.Count(env, "SENSOR_CA_SHA256=") != 1 {
		t.Errorf("pin not written once:\n%s", env)
	}
	if strings.Contains(env, "# SENSOR_CA_SHA256=") {
		t.Errorf("the commented example stayed beside the pin:\n%s", env)
	}
	// A second call replaces it; a list is kept in order.
	second := upper + "," + want
	if out, err := run("set-ca", "acme", "--sha256", second); err != nil {
		t.Fatalf("second set-ca: %v\n%s", err, out)
	}
	env = readEnv(t, dir, "acme")
	if !strings.Contains(env, "\nSENSOR_CA_SHA256="+strings.ToLower(upper)+","+want+"\n") || strings.Count(env, "SENSOR_CA_SHA256=") != 1 {
		t.Errorf("pin not replaced:\n%s", env)
	}
	if st, _ := os.Stat(filepath.Join(dir, "sensors", "acme", "sensor.env")); st.Mode().Perm() != 0o600 {
		t.Errorf("sensor.env mode %v", st.Mode().Perm())
	}
	if c := calls(); strings.Count(c, "compose up -d --force-recreate acme") != 2 {
		t.Errorf("acme was not recreated each time:\n%s", c)
	}
	// Other sensors keep their own env file.
	if strings.Contains(readEnv(t, dir, "beta"), "\nSENSOR_CA_SHA256=") {
		t.Error("beta got the pin")
	}
	if !strings.Contains(out, "status") {
		t.Errorf("no hint how to verify:\n%s", out)
	}
}

func TestSetCARefusals(t *testing.T) {
	dir, run, calls := setup(t)
	pem, _, _ := testCA(t, 1)
	notPEM := filepath.Join(t.TempDir(), "x.txt")
	_ = os.WriteFile(notPEM, []byte("hello"), 0o644)
	good := strings.Repeat("ab", 32)
	for name, args := range map[string][]string{
		"no name":        {"set-ca"},
		"unknown sensor": {"set-ca", "nobody", "--sha256", good},
		"path name":      {"set-ca", "../acme", "--sha256", good},
		"nothing given":  {"set-ca", "acme"},
		"both":           {"set-ca", "acme", "--sha256", good, "--file", pem},
		"short hex":      {"set-ca", "acme", "--sha256", good[:62]},
		"not hex":        {"set-ca", "acme", "--sha256", strings.Repeat("zz", 32)},
		"one bad of two": {"set-ca", "acme", "--sha256", good + ",abc"},
		"empty":          {"set-ca", "acme", "--sha256", ""},
		"not a PEM":      {"set-ca", "acme", "--file", notPEM},
		"missing file":   {"set-ca", "acme", "--file", "/nonexistent"},
		"bad flag":       {"set-ca", "acme", "--bogus"},
	} {
		before, envBefore := calls(), readEnv(t, dir, "acme")
		if out, err := run(args...); err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
		if calls() != before {
			t.Errorf("%s: touched docker before refusing", name)
		}
		if readEnv(t, dir, "acme") != envBefore {
			t.Errorf("%s: changed the env file", name)
		}
	}
}

func TestSetCAFile(t *testing.T) {
	dir, run, calls := setup(t)
	pem, names, sums := testCA(t, 2)
	out, err := run("set-ca", "acme", "--file", pem)
	if err != nil {
		t.Fatalf("set-ca --file: %v\n%s", err, out)
	}
	dst := filepath.Join(dir, "sensors", "acme", "policy", "platform-ca.pem")
	st, err := os.Stat(dst)
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("CA not installed 0644: %v", err)
	}
	want, _ := os.ReadFile(pem)
	if got, _ := os.ReadFile(dst); string(got) != string(want) {
		t.Error("the installed file differs from the given one")
	}
	env := readEnv(t, dir, "acme")
	if !strings.Contains(env, "\nSENSOR_CA_CERT_FILE=/etc/openctem/policy/platform-ca.pem\n") || strings.Contains(env, "# SENSOR_CA_CERT_FILE=") {
		t.Errorf("CA not configured:\n%s", env)
	}
	if st, _ := os.Stat(filepath.Join(dir, "sensors", "acme", "sensor.env")); st.Mode().Perm() != 0o600 {
		t.Errorf("sensor.env mode %v", st.Mode().Perm())
	}
	for i := range names {
		if !strings.Contains(out, names[i]) || !strings.Contains(out, sums[i]) {
			t.Errorf("output lacks certificate %d (%s %s):\n%s", i+1, names[i], sums[i], out)
		}
	}
	if !strings.Contains(calls(), "compose up -d --force-recreate acme") {
		t.Errorf("acme not recreated:\n%s", calls())
	}
}

func TestAddWithCASha256AndCAFilePrintsFingerprints(t *testing.T) {
	dir, run, _ := setup(t)
	good := strings.Repeat("AB:", 31) + "AB"
	pem, names, sums := testCA(t, 2)
	if out, err := run("add", "bad", "--api-url", "https://x.example.com", "--ca-sha256", "xyz", "--no-start"); err == nil {
		t.Errorf("bad pin accepted\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "sensors", "bad")); err == nil {
		t.Error("left sensors/bad behind")
	}
	out, err := run("add", "delta", "--api-url", "https://x.example.com", "--ca-sha256", good, "--ca-file", pem, "--no-start")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	env := readEnv(t, dir, "delta")
	if !strings.Contains(env, "\nSENSOR_CA_SHA256="+strings.Repeat("ab", 32)+"\n") || strings.Contains(env, "# SENSOR_CA_SHA256=<") && strings.Count(env, "SENSOR_CA_SHA256=") != 2 {
		t.Errorf("pin not written:\n%s", env)
	}
	for i := range names {
		if !strings.Contains(out, names[i]) || !strings.Contains(out, sums[i]) {
			t.Errorf("add output lacks certificate %d:\n%s", i+1, out)
		}
	}
	// Without a pin the env file carries the commented example only.
	if e := readEnv(t, dir, "beta"); strings.Contains(e, "\nSENSOR_CA_SHA256=") || !strings.Contains(e, "# SENSOR_CA_SHA256=") {
		t.Errorf("beta env:\n%s", e)
	}
}

func TestPrivateCAHintsPointToSetCA(t *testing.T) {
	_, run, _ := setup(t)
	t.Setenv("STUB_SERVICES", "acme")
	t.Setenv("STUB_LOGS", "pairing: the platform's TLS certificate is signed by an authority this host does not trust")
	out, err := run("status")
	if err != nil || !strings.Contains(out, "set-ca acme --sha256") {
		t.Errorf("status hint: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile("sensors.sh")
	if strings.Contains(string(raw), "add it again with --ca-file") {
		t.Error("pair still says to remove and add again")
	}
}

// Self-update: fixture release files served from a local directory.

type kitFixture struct{ base string }

func newKit(t *testing.T, version string) kitFixture {
	t.Helper()
	root := t.TempDir()
	d := filepath.Join(root, version)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	tpl, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"deploy-multi-sensors.sh":   "#!/usr/bin/env bash\necho new kit script\n",
		"deploy-multi-compose.yaml": string(tpl) + "# new template marker\n",
		"deploy-multi-README.md":    "new readme\n",
		"deploy-multi-env.example":  "SENSOR_VERSION=" + version + "\n",
	}
	var sums strings.Builder
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(c))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	_ = os.WriteFile(filepath.Join(d, "deploy-multi.SHA256SUMS"), []byte(sums.String()), 0o644)
	_ = os.WriteFile(filepath.Join(d, "deploy-multi.SHA256SUMS.sigstore.json"), []byte("{}"), 0o644)
	t.Setenv("SENSORS_RELEASE_BASE", "file://"+root)
	return kitFixture{base: d}
}

// legacyKit makes the directory's compose.yaml what an older kit wrote: the
// template hard-wires a local policy file.
func legacyKit(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, "compose.yaml")
	b, _ := os.ReadFile(p)
	n := strings.Replace(string(b), "    SENSOR_KILL_SWITCH_FILE", "    SENSOR_LOCAL_POLICY: /etc/openctem/policy/sensor-policy.yaml\n    SENSOR_KILL_SWITCH_FILE", 1)
	if n == string(b) {
		t.Fatal("legacy edit did not apply")
	}
	if err := os.WriteFile(p, []byte(n), 0o644); err != nil {
		t.Fatal(err)
	}
}

func treeHash(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			fmt.Fprintf(h, "%s %o %x\n", p, info.Mode().Perm(), sha256.Sum256(b))
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}

func TestSelfUpdateConvertsLegacyKitAndKeepsSensors(t *testing.T) {
	dir, run, calls := setup(t)
	legacyKit(t, dir)
	_ = os.WriteFile(filepath.Join(dir, "sensors", "acme", "policy", "sensor-policy.yaml"),
		[]byte("apiVersion: x\ntargets:\n  allow:\n    - 203.0.113.0/24\n"), 0o644)
	// A hand edit inside a sensor's block survives.
	cf, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	edited := strings.Replace(string(cf), "  acme:\n    <<: *sensor\n", "  acme:\n    <<: *sensor\n    mem_limit: 8g\n", 1)
	if edited == string(cf) {
		t.Fatal("block edit did not apply")
	}
	_ = os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(edited), 0o644)
	newKit(t, "v0.99.0")
	before := treeHash(t, filepath.Join(dir, "sensors"))
	out, err := run("self-update", "v0.99.0")
	if err != nil {
		t.Fatalf("self-update: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	g := string(got)
	for _, w := range []string{"# new template marker", "\n  acme:\n", "    mem_limit: 8g\n", "\n  beta:\n", "acme-data: {}", "beta-data: {}", "  # sensors.sh add: new services above this line"} {
		if !strings.Contains(g, w) {
			t.Errorf("merged compose.yaml lacks %q:\n%s", w, g)
		}
	}
	if strings.Contains(g, "    SENSOR_LOCAL_POLICY:") {
		t.Error("the legacy hard-wired policy is still there")
	}
	if strings.Count(g, "\nservices:\n") != 1 || strings.Count(g, "  # sensors.sh add: new services above this line") != 1 {
		t.Errorf("sections duplicated:\n%s", g)
	}
	baks, _ := filepath.Glob(filepath.Join(dir, "compose.yaml.bak-*"))
	if len(baks) != 1 {
		t.Fatalf("backups: %v", baks)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != edited {
		t.Error("backup is not the previous compose.yaml")
	}
	if s, _ := os.ReadFile(filepath.Join(dir, "sensors.sh")); !strings.Contains(string(s), "new kit script") {
		t.Error("sensors.sh not replaced")
	}
	if st, _ := os.Stat(filepath.Join(dir, "sensors.sh")); st.Mode().Perm() != 0o755 {
		t.Errorf("sensors.sh mode %v", st.Mode().Perm())
	}
	if r, _ := os.ReadFile(filepath.Join(dir, "README.md")); string(r) != "new readme\n" {
		t.Error("README.md not replaced")
	}
	if treeHash(t, filepath.Join(dir, "sensors")) != before {
		t.Error("sensors/ changed")
	}
	if !strings.Contains(out, "NOTE:") || !strings.Contains(out, "SENSOR_LOCAL_POLICY=") {
		t.Errorf("no note about the narrowing policy file:\n%s", out)
	}
	if c := calls(); !strings.Contains(c, "verify-blob") || !strings.Contains(c, "release.yml@refs/tags/v0.99.0") {
		t.Errorf("signature not verified against the release workflow at that tag:\n%s", c)
	}
	for _, bad := range []string{"volume", "down", "rm "} {
		if strings.Contains(calls(), "compose "+bad) {
			t.Errorf("self-update ran docker %s", bad)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".self-update.*")); len(left) != 0 {
		t.Errorf("temp dir left: %v", left)
	}
}

func TestSelfUpdateRefusals(t *testing.T) {
	dir, run, _ := setup(t)
	legacyKit(t, dir)
	for name, prep := range map[string]func(k kitFixture){
		"bad checksum": func(k kitFixture) {
			_ = os.WriteFile(filepath.Join(k.base, "deploy-multi-compose.yaml"), []byte("tampered\n"), 0o644)
		},
		"file not listed": func(k kitFixture) {
			_ = os.WriteFile(filepath.Join(k.base, "deploy-multi.SHA256SUMS"), []byte("00  deploy-multi-README.md\n"), 0o644)
		},
		"bad signature": func(k kitFixture) { t.Setenv("STUB_COSIGN_FAIL", "1") },
		"missing file":  func(k kitFixture) { _ = os.Remove(filepath.Join(k.base, "deploy-multi-env.example")) },
	} {
		k := newKit(t, "v0.99.0")
		prep(k)
		beforeFiles := map[string]string{}
		for _, f := range []string{"compose.yaml", "sensors.sh", "README.md", ".env.example"} {
			b, _ := os.ReadFile(filepath.Join(dir, f))
			beforeFiles[f] = string(b)
		}
		sens := treeHash(t, filepath.Join(dir, "sensors"))
		if out, err := run("self-update", "v0.99.0"); err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
		for f, c := range beforeFiles {
			if b, _ := os.ReadFile(filepath.Join(dir, f)); string(b) != c {
				t.Errorf("%s: %s changed", name, f)
			}
		}
		if baks, _ := filepath.Glob(filepath.Join(dir, "*.bak-*")); len(baks) != 0 {
			t.Errorf("%s: backups written before verification: %v", name, baks)
		}
		if treeHash(t, filepath.Join(dir, "sensors")) != sens {
			t.Errorf("%s: sensors/ changed", name)
		}
		t.Setenv("STUB_COSIGN_FAIL", "")
	}
	for name, args := range map[string][]string{
		"no version": {"self-update"},
		"not semver": {"self-update", "latest"},
	} {
		if out, err := run(args...); err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
	}
	t.Setenv("SENSORS_RELEASE_BASE", "http://example.com")
	if out, err := run("self-update", "v0.99.0"); err == nil {
		t.Errorf("plain http base accepted\n%s", out)
	}
}

func TestSelfUpdateRestoresWhenComposeDoesNotValidate(t *testing.T) {
	dir, run, _ := setup(t)
	legacyKit(t, dir)
	newKit(t, "v0.99.0")
	t.Setenv("STUB_CONFIG_FAIL", "1")
	before, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if out, err := run("self-update", "v0.99.0"); err == nil {
		t.Fatalf("accepted a compose.yaml that does not validate\n%s", out)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "compose.yaml")); string(after) != string(before) {
		t.Error("compose.yaml not restored")
	}
	if s, _ := os.ReadFile(filepath.Join(dir, "sensors.sh")); strings.Contains(string(s), "new kit script") {
		t.Error("sensors.sh replaced although validation failed")
	}
}

func TestUpgradeOffersSelfUpdateButNeverSilently(t *testing.T) {
	dir, run, _ := setup(t)
	legacyKit(t, dir)
	newKit(t, "v0.99.0")
	_ = os.WriteFile(filepath.Join(dir, "seccomp", "sensor-v0.99.0.json"), []byte(`{"defaultAction":"x"}`), 0o644)
	before, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	out, err := run("upgrade", "v0.99.0")
	if err != nil {
		t.Fatalf("upgrade: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "compose.yaml")); string(after) != string(before) {
		t.Error("upgrade replaced compose.yaml without being asked")
	}
	if !strings.Contains(out, "self-update v0.99.0") {
		t.Errorf("no offer:\n%s", out)
	}
	if out, err := run("upgrade", "--self-update", "v0.99.0"); err != nil {
		t.Fatalf("upgrade --self-update: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "compose.yaml")); strings.Contains(string(after), "SENSOR_LOCAL_POLICY:") ||
		!strings.Contains(string(after), "# new template marker") {
		t.Error("upgrade --self-update did not update compose.yaml")
	}
}

func TestSetPolicyAllowAllWritesV2ForANewSensor(t *testing.T) {
	dir, run, calls := setup(t)
	t.Setenv("STUB_VERSION", "v0.99.0")
	pol := filepath.Join(dir, "sensors", "acme", "policy", "sensor-policy.yaml")
	_ = os.WriteFile(pol, []byte("old policy\n"), 0o600)
	out, err := run("set-policy", "acme", "--allow-all")
	if err != nil {
		t.Fatalf("set-policy: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(pol)
	if !strings.Contains(string(b), "apiVersion: openctem.io/sensor-policy/v2") || !strings.Contains(string(b), `allow: ["*"]`) {
		t.Errorf("not a v2 allow-all file:\n%s", b)
	}
	if st, _ := os.Stat(pol); st.Mode().Perm() != 0o644 {
		t.Errorf("policy mode %v", st.Mode().Perm())
	}
	baks, _ := filepath.Glob(pol + ".bak-*")
	if len(baks) != 1 {
		t.Fatalf("backups: %v", baks)
	}
	if o, _ := os.ReadFile(baks[0]); string(o) != "old policy\n" {
		t.Error("backup is not the previous file")
	}
	env := readEnv(t, dir, "acme")
	if !strings.Contains(env, "\nSENSOR_LOCAL_POLICY=/etc/openctem/policy/sensor-policy.yaml\n") || strings.Contains(env, "# SENSOR_LOCAL_POLICY=") {
		t.Errorf("env not set:\n%s", env)
	}
	if st, _ := os.Stat(filepath.Join(dir, "sensors", "acme", "sensor.env")); st.Mode().Perm() != 0o600 {
		t.Errorf("sensor.env mode %v", st.Mode().Perm())
	}
	if !strings.Contains(calls(), "compose up -d --force-recreate acme") {
		t.Errorf("not recreated:\n%s", calls())
	}
	if strings.Contains(readEnv(t, dir, "beta"), "\nSENSOR_LOCAL_POLICY=") {
		t.Error("beta changed")
	}
}

func TestSetPolicyAllowAllFallsBackToV1ForAnOldSensor(t *testing.T) {
	dir, run, calls := setup(t)
	t.Setenv("STUB_VERSION", "v0.33.0")
	out, err := run("set-policy", "acme", "--allow-all")
	if err != nil {
		t.Fatalf("set-policy: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "sensors", "acme", "policy", "sensor-policy.yaml"))
	s := string(b)
	if !strings.Contains(s, "sensor-policy/v1") || !strings.Contains(s, "0.0.0.0/0") || !strings.Contains(s, `"::/0"`) || strings.Contains(s, `allow: ["*"]`) {
		t.Errorf("not the v1 form:\n%s", s)
	}
	if !strings.Contains(out, "v1") || !strings.Contains(out, "domain") {
		t.Errorf("does not say what v1 means:\n%s", out)
	}
	if !strings.Contains(calls(), "compose up -d --force-recreate acme") {
		t.Error("not recreated")
	}
	// A sensor on a non-release tag is treated as old, not guessed.
	t.Setenv("STUB_VERSION", "latest")
	if out, err := run("set-policy", "beta", "--allow-all"); err != nil || !strings.Contains(out, "v1") {
		t.Errorf("latest: %v\n%s", err, out)
	}
}

func TestSetPolicyPlatformScopeKeepsTheFile(t *testing.T) {
	dir, run, calls := setup(t)
	t.Setenv("STUB_VERSION", "v0.99.0")
	if out, err := run("set-policy", "acme", "--allow-all"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := run("set-policy", "acme", "--platform-scope"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	env := readEnv(t, dir, "acme")
	if strings.Contains(env, "\nSENSOR_LOCAL_POLICY=") || !strings.Contains(env, "# SENSOR_LOCAL_POLICY=") {
		t.Errorf("reference not removed:\n%s", env)
	}
	if _, err := os.Stat(filepath.Join(dir, "sensors", "acme", "policy", "sensor-policy.yaml")); err != nil {
		t.Error("the policy file was deleted")
	}
	if strings.Count(calls(), "compose up -d --force-recreate acme") != 2 {
		t.Error("not recreated each time")
	}
}

func TestSetPolicyRefusals(t *testing.T) {
	_, run, calls := setup(t)
	for name, args := range map[string][]string{
		"no name":      {"set-policy"},
		"unknown name": {"set-policy", "nobody", "--allow-all"},
		"path name":    {"set-policy", "../acme", "--allow-all"},
		"no mode":      {"set-policy", "acme"},
		"bad flag":     {"set-policy", "acme", "--bogus"},
	} {
		before := calls()
		if out, err := run(args...); err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
		if calls() != before {
			t.Errorf("%s: touched docker", name)
		}
	}
}
