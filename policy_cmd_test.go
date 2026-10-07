package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPolicyV1 = "apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: [203.0.113.0/24]}\ntools: {allow: [nuclei]}\n"
const testPolicyV2 = "apiVersion: openctem.io/sensor-policy/v2\ntargets: {allow: [203.0.113.0/24, 198.51.100.0/24]}\ntools: {allow: [nuclei, httpx]}\nmanaged: {accept: false}\n"

func runPolicy(t *testing.T, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = runPolicyCommand(args, &o, &e)
	return code, o.String(), e.String()
}

func writePolicy(t *testing.T, dir, name, doc string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sum(doc string) string {
	s := sha256.Sum256([]byte(doc))
	return hex.EncodeToString(s[:])
}

func TestPolicyValidateAndDigest(t *testing.T) {
	t.Setenv("SENSOR_ALLOWED_RANGES", "")
	t.Setenv("SENSOR_ALLOWED_PORTS", "")
	dir := t.TempDir()
	v1, v2 := writePolicy(t, dir, "v1.yaml", testPolicyV1), writePolicy(t, dir, "v2.yaml", testPolicyV2)
	if code, out, _ := runPolicy(t, "validate", v1); code != 0 || !strings.Contains(out, "valid (schema v1)") {
		t.Errorf("validate v1: %d %s", code, out)
	}
	if code, out, _ := runPolicy(t, "validate", v2); code != 0 || !strings.Contains(out, "valid (schema v2)") {
		t.Errorf("validate v2: %d %s", code, out)
	}
	if code, out, _ := runPolicy(t, "digest", v1); code != 0 || strings.TrimSpace(out) != "sha256:"+sum(testPolicyV1) {
		t.Errorf("digest: %d %q", code, out)
	}
	// Negative: what the sensor would refuse to start with.
	for name, doc := range map[string]string{
		"v2 key in v1": "apiVersion: openctem.io/sensor-policy/v1\nmanaged: {accept: false}\n",
		"unknown key":  "apiVersion: openctem.io/sensor-policy/v2\nallow_everything: true\n",
		"bad version":  "apiVersion: openctem.io/sensor-policy/v9\n",
	} {
		p := writePolicy(t, dir, "bad.yaml", doc)
		if code, _, errOut := runPolicy(t, "validate", p); code != 1 || !strings.Contains(errOut, "invalid") {
			t.Errorf("%s: %d %s", name, code, errOut)
		}
	}
	ww := writePolicy(t, dir, "ww.yaml", testPolicyV1)
	_ = os.Chmod(ww, 0o666)
	if code, _, _ := runPolicy(t, "validate", ww); code != 1 {
		t.Error("world-writable policy validated")
	}
	if code, _, _ := runPolicy(t, "frobnicate"); code != 2 {
		t.Error("unknown subcommand")
	}
}

func TestPolicyExplain(t *testing.T) {
	dir := t.TempDir()
	p := writePolicy(t, dir, "p.yaml", testPolicyV1)
	if code, out, _ := runPolicy(t, "explain", p, "-target", "203.0.113.5", "-tool", "nuclei"); code != 0 || !strings.Contains(out, "admitted") {
		t.Errorf("allowed job: %d %s", code, out)
	}
	if code, out, _ := runPolicy(t, "explain", "-target", "192.0.2.1", p); code != 1 || !strings.Contains(out, "rule targets.allow (denied_by_policy)") {
		t.Errorf("outside target: %d %s", code, out)
	}
	if code, out, _ := runPolicy(t, "explain", p, "-target", "203.0.113.5", "-tool", "semgrep"); code != 1 || !strings.Contains(out, "rule tools.allow") {
		t.Errorf("tool outside: %d %s", code, out)
	}
	if code, _, _ := runPolicy(t, "explain", p); code != 2 {
		t.Error("missing -target accepted")
	}
	// A wildcard pattern is not a host: refused with its own reason.
	if code, out, _ := runPolicy(t, "explain", p, "-target", "*.example.com"); code != 1 || !strings.Contains(out, "rule targets (wildcard_pattern)") {
		t.Errorf("wildcard: %d %s", code, out)
	}
}

// install: only the reviewed bytes (hash), only a policy this sensor reads,
// atomically, 0644, never through a symlink or into a directory anyone can
// write.
func TestPolicyInstall(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	if err := os.Mkdir(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(etc, "sensor-policy.yaml")
	src := writePolicy(t, dir, "download.yaml", testPolicyV2)

	// Dry run changes nothing.
	if code, out, _ := runPolicy(t, "install", src, "-expect-sha256", sum(testPolicyV2), "-dest", dest, "-dry-run"); code != 0 || !strings.Contains(out, "dry run") {
		t.Fatalf("dry run: %d %s", code, out)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("dry run wrote the file")
	}

	code, out, errOut := runPolicy(t, "install", src, "-expect-sha256", "sha256:"+strings.ToUpper(sum(testPolicyV2)), "-dest", dest)
	if code != 0 || !strings.Contains(out, "installed") || !strings.Contains(out, "before: none") {
		t.Fatalf("install: %d %s %s", code, out, errOut)
	}
	st, err := os.Stat(dest)
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("installed file: %v %v", err, st.Mode())
	}
	got, _ := os.ReadFile(dest)
	if string(got) != testPolicyV2 {
		t.Fatal("installed bytes differ")
	}
	if left, _ := filepath.Glob(filepath.Join(etc, ".sensor-policy.yaml.tmp-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}

	// Negatives: nothing is written.
	tampered := writePolicy(t, dir, "tampered.yaml", strings.Replace(testPolicyV2, "accept: false", "accept: true", 1))
	invalid := writePolicy(t, dir, "invalid.yaml", "apiVersion: openctem.io/sensor-policy/v1\nmanaged: {accept: false}\n")
	for name, args := range map[string][]string{
		"hash mismatch":   {"install", tampered, "-expect-sha256", sum(testPolicyV2), "-dest", dest},
		"invalid policy":  {"install", invalid, "-expect-sha256", sum("apiVersion: openctem.io/sensor-policy/v1\nmanaged: {accept: false}\n"), "-dest", dest},
		"no hash":         {"install", src, "-dest", dest},
		"short hash":      {"install", src, "-expect-sha256", "abcd", "-dest", dest},
		"relative dest":   {"install", src, "-expect-sha256", sum(testPolicyV2), "-dest", "etc/p.yaml"},
		"source is a dir": {"install", dir, "-expect-sha256", sum(testPolicyV2), "-dest", dest},
	} {
		if code, _, _ := runPolicy(t, args...); code == 0 {
			t.Errorf("%s: installed", name)
		}
		if b, _ := os.ReadFile(dest); string(b) != testPolicyV2 {
			t.Fatalf("%s: the installed policy changed", name)
		}
	}

	// A symlink at the destination is never followed or replaced.
	link := filepath.Join(etc, "link.yaml")
	if err := os.Symlink(filepath.Join(dir, "elsewhere.yaml"), link); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runPolicy(t, "install", src, "-expect-sha256", sum(testPolicyV2), "-dest", link); code == 0 || !strings.Contains(errOut, "not a regular file") {
		t.Errorf("symlink dest: %d %s", code, errOut)
	}
	// A destination directory anyone can write is refused.
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(open, 0o777)
	if code, _, errOut := runPolicy(t, "install", src, "-expect-sha256", sum(testPolicyV2), "-dest", filepath.Join(open, "p.yaml")); code == 0 || !strings.Contains(errOut, "writable by every user") {
		t.Errorf("open dir: %d %s", code, errOut)
	}
}
