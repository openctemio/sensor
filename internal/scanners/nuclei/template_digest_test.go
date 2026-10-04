package nuclei

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTemplate(t *testing.T, root, rel, body string) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTemplateDigest(t *testing.T) {
	root := t.TempDir()
	p := writeTemplate(t, root, "http/a.yaml", "id: a\n")
	sum := sha256.Sum256([]byte("id: a\n"))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got, ok := TemplateDigest(p, []string{root}); !ok || got != want {
		t.Fatalf("digest %q %v, want %q", got, ok, want)
	}
	// Another template content, another digest: the closure evaluator
	// tells a changed template apart from the same one.
	if err := os.WriteFile(p, []byte("id: a\n# tightened matcher\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := TemplateDigest(p, []string{root}); got == want {
		t.Fatal("digest unchanged after the template changed")
	}
}

// template-path comes from scanner output: a file outside the run's
// template directories is never read, directly or through a symlink.
func TestTemplateDigestStaysInsideRoots(t *testing.T) {
	root := t.TempDir()
	outside := writeTemplate(t, t.TempDir(), "secret.yaml", "token: x\n")
	if _, ok := TemplateDigest(outside, []string{root}); ok {
		t.Fatal("file outside the template roots hashed")
	}
	if _, ok := TemplateDigest(filepath.Join(root, "..", filepath.Base(filepath.Dir(outside)), "secret.yaml"), []string{root}); ok {
		t.Fatal("dot-dot path outside the roots hashed")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(root, "link.yaml")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		if _, ok := TemplateDigest(link, []string{root}); ok {
			t.Fatal("symlink escaping the template roots hashed")
		}
	}
	if _, ok := TemplateDigest(root, []string{root}); ok {
		t.Fatal("a directory hashed")
	}
	if _, ok := TemplateDigest(filepath.Join(root, "missing.yaml"), []string{root}); ok {
		t.Fatal("missing file hashed")
	}
}

func TestAnnotateTemplateDigests(t *testing.T) {
	root := t.TempDir()
	p := writeTemplate(t, root, "http/a.yaml", "id: a\n")
	want, _ := TemplateDigest(p, []string{root})
	out := "" +
		`{"template-id":"a","template-path":"` + p + `","response":"<html>&amp;</html>"}` + "\n" +
		"not json\n" +
		`{"template-id":"b","template-path":"/etc/passwd"}` + "\n" +
		`{"template-id":"c","template-path":"` + p + `","template-digest":"sha256:forged"}` + "\n"
	got := string(annotateTemplateDigests([]byte(out), []string{root}))
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines %q", lines)
	}
	if !strings.Contains(lines[0], `"template-digest":"`+want+`"`) || !strings.Contains(lines[0], `<html>&amp;</html>`) {
		t.Errorf("line 1 %s", lines[0])
	}
	if lines[1] != "not json" || strings.Contains(lines[2], "template-digest") {
		t.Errorf("non-result or outside lines changed: %q %q", lines[1], lines[2])
	}
	if strings.Contains(lines[3], "forged") || !strings.Contains(lines[3], want) {
		t.Errorf("a digest in the output is replaced by the sensor's own: %s", lines[3])
	}
	// Nothing to annotate: the output is returned as it was.
	same := []byte(`{"template-id":"x"}` + "\n")
	if string(annotateTemplateDigests(same, []string{root})) != string(same) {
		t.Error("output without template paths changed")
	}
}

// A re-verification of a managed set records the digest of the template it
// selected, whether the template matched or not.
func TestValidateRecordsTemplateDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in")
	}
	tpl := t.TempDir()
	p := writeTemplate(t, tpl, "http/clean-nomatch.yaml", "id: clean-nomatch\n")
	want, _ := TemplateDigest(p, []string{tpl})
	// nuclei prints -tl paths relative to its templates directory when it
	// has one (the private configuration names it).
	bin := filepath.Join(t.TempDir(), "nuclei")
	script := `#!/bin/sh
for a in "$@"; do [ "$a" = -tl ] && { [ -n "$XDG_CONFIG_HOME" ] && echo "http/clean-nomatch.yaml"; exit 0; }; done
exit 0
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test stand-in must be executable
		t.Fatal(err)
	}
	res, err := ValidateSingleTemplate(context.Background(), ValidateOptions{
		Target: "http://t", TemplateID: "clean-nomatch", Binary: bin,
		TemplatesDir: tpl, TemplatesVersion: "v10.4.9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeNotDetected || res.TemplateDigest != want || res.Evidence["template_digest"] != want {
		t.Fatalf("result %+v, want not_detected with digest %s", res, want)
	}
}
