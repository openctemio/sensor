package nuclei

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func TestBuiltinTemplatesAreWellFormed(t *testing.T) {
	ids := BuiltinTemplateIDs()
	if len(ids) == 0 {
		t.Fatal("no compiled-in templates")
	}
	for _, id := range ids {
		raw, ok := BuiltinTemplate(id)
		if !ok {
			t.Fatalf("%s: listed but not readable", id)
		}
		if err := core.CheckNucleiCustomTemplate(raw); err != nil {
			t.Errorf("%s: fails the custom-template content check: %v", id, err)
		}
		if !strings.Contains(string(raw), "id: "+id+"\n") {
			t.Errorf("%s: the file's id line does not match its name", id)
		}
		if !TagAllowedForValidation(id) || !TemplateTagsAllowed(tagsOf(string(raw))) {
			t.Errorf("%s: carries a class a re-check never runs", id)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", "openctem-backup-file-signature.yaml", "nope"} {
		if _, ok := BuiltinTemplate(bad); ok {
			t.Errorf("BuiltinTemplate(%q) resolved", bad)
		}
	}
}

func tagsOf(raw string) []string {
	for _, l := range strings.Split(raw, "\n") {
		if t, ok := strings.CutPrefix(strings.TrimSpace(l), "tags:"); ok {
			return strings.Split(strings.TrimSpace(t), ",")
		}
	}
	return nil
}

// The backup check reads the file's own bytes: GET of the exact URL, a
// non-HTML 200, and a signature at the start of the body. A status alone
// never matches, and nothing but GET is sent.
func TestBackupFileSignatureTemplateShape(t *testing.T) {
	raw, ok := BuiltinTemplate(BackupFileSignatureID)
	if !ok {
		t.Fatal("the backup file signature template is not compiled in")
	}
	s := string(raw)
	for _, want := range []string{
		"method: GET",
		`- "{{BaseURL}}"`,
		"matchers-condition: and",
		"status:\n          - 200",
		"negative: true",
		"text/html",
		`"504b0304"`, // zip
		`"1f8b08"`,   // gzip
		`"ustar"`,    // tar
		"MySQL dump", "PostgreSQL database dump",
		"max-size:",
		"redirects: false",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("template lacks %q", want)
		}
	}
	for _, bad := range []string{"POST", "PUT", "DELETE", "PATCH", "payloads", "raw:", "fuzzing", "headless", "code:"} {
		if strings.Contains(s, bad) {
			t.Errorf("template carries %q: it must be a plain GET check", bad)
		}
	}
}

// The platform asks for the check by id. The sensor runs its compiled-in copy
// signed for this run (nuclei keeps -disable-unsigned-templates), reports
// the compiled-in content's digest, and a missing id still reads as "not
// installed", never as "ran, no match".
func TestValidateRunsABuiltinTemplateByID(t *testing.T) {
	bin := fakeNucleiBin(t)
	res := validateWith(t, bin, BackupFileSignatureID)
	if res.Outcome != OutcomeDetected || !res.Matched {
		t.Fatalf("outcome = %q matched = %v, want detected", res.Outcome, res.Matched)
	}
	if res.TemplateID != BackupFileSignatureID {
		t.Errorf("template id = %q", res.TemplateID)
	}
	raw, _ := BuiltinTemplate(BackupFileSignatureID)
	sum := sha256.Sum256(raw)
	if want := "sha256:" + hex.EncodeToString(sum[:]); res.TemplateDigest != want {
		t.Errorf("digest = %q, want the compiled-in content's %q", res.TemplateDigest, want)
	}

	if other := validateWith(t, bin, "no-such-template"); other.Outcome != OutcomeInconclusive {
		t.Errorf("unknown id outcome = %q, want inconclusive", other.Outcome)
	}
}

func TestValidateBuiltinTemplateKeepsTheSignatureRequirement(t *testing.T) {
	signed, path, cleanup, err := signBuiltinTemplate(BackupFileSignatureID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(signed.certPEM) == 0 || path == "" {
		t.Fatal("no certificate or path")
	}
	args, err := buildValidateArgs(ValidateOptions{Target: "http://t/backup.zip", TemplatePath: path})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "-disable-unsigned-templates") {
		t.Errorf("args %v lack -disable-unsigned-templates", args)
	}
}
