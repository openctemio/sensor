package nuclei

import (
	"strings"
	"testing"
)

func TestTagAllowedForValidation(t *testing.T) {
	cases := map[string]bool{
		"cve":         true,
		"tech":        true,
		"detect":      true,
		"":            true,
		"dos":         false,
		"fuzz":        false,
		"fuzzing":     false, // contains "fuzz"
		"intrusive":   false,
		"brute-force": false,
		"bruteforce":  false,
		"network-dos": false, // contains "dos"
	}
	for tag, want := range cases {
		if got := TagAllowedForValidation(tag); got != want {
			t.Errorf("TagAllowedForValidation(%q) = %v, want %v", tag, got, want)
		}
	}
}

func TestTemplateTagsAllowed(t *testing.T) {
	if !TemplateTagsAllowed([]string{"cve", "rce", "apache"}) {
		t.Error("clean tag set should be allowed")
	}
	if TemplateTagsAllowed([]string{"cve", "intrusive"}) {
		t.Error("a set containing an excluded tag must be rejected")
	}
	if !TemplateTagsAllowed(nil) {
		t.Error("empty tag set should be allowed")
	}
}

func TestBuildValidateArgs_DetectionOnlySafety(t *testing.T) {
	args, err := buildValidateArgs(ValidateOptions{
		Target:     "https://example.com",
		TemplateID: "apache-struts-rce",
	})
	if err != nil {
		t.Fatalf("buildValidateArgs: %v", err)
	}
	joined := strings.Join(args, " ")

	// Single-template selection by id.
	if !argPairPresent(args, "-id", "apache-struts-rce") {
		t.Errorf("args missing -id apache-struts-rce: %v", args)
	}
	// Target.
	if !argPairPresent(args, "-u", "https://example.com") {
		t.Errorf("args missing -u target: %v", args)
	}
	// The destructive classes must be excluded.
	etags := argValue(args, "-etags")
	for _, ex := range []string{"dos", "fuzz", "intrusive", "brute-force"} {
		if !strings.Contains(etags, ex) {
			t.Errorf("-etags %q missing excluded class %q", etags, ex)
		}
	}
	// Machine-readable, non-interactive, no auto-update.
	for _, want := range []string{"-jsonl", "-silent", "-disable-update-check"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	// A rate limit is always set.
	if argValue(args, "-rate-limit") == "" {
		t.Errorf("args missing -rate-limit: %v", args)
	}
}

func TestBuildValidateArgs_RejectsBadInput(t *testing.T) {
	bad := []ValidateOptions{
		{Target: "", TemplateID: "x"},                           // no target
		{Target: "https://x", TemplateID: "", TemplatePath: ""}, // no template
		{Target: "https://x", TemplatePath: "../../etc/passwd"}, // traversal path
		{Target: "https://x", TemplateID: "a/b"},                // id with slash
		{Target: "https://x", TemplateID: "../evil"},            // id traversal
		{Target: "https://x", TemplateID: "-oob"},               // flag-injection id
		{Target: "https://x", TemplateID: "some-dos-template"},  // destructive class
		{Target: "https://x", TemplateID: "http-fuzz-check"},    // fuzz class
	}
	for i, opts := range bad {
		if _, err := buildValidateArgs(opts); err == nil {
			t.Errorf("case %d: expected error for %+v", i, opts)
		}
	}
}

func TestBuildValidateArgs_TemplatePath(t *testing.T) {
	args, err := buildValidateArgs(ValidateOptions{
		Target:       "https://example.com",
		TemplatePath: "cves/2021/CVE-2021-44228.yaml",
	})
	if err != nil {
		t.Fatalf("buildValidateArgs: %v", err)
	}
	if !argPairPresent(args, "-t", "cves/2021/CVE-2021-44228.yaml") {
		t.Errorf("args missing -t template path: %v", args)
	}
}

func TestValidateClamps(t *testing.T) {
	if got := validateTimeout(0); got.Seconds() != 30 {
		t.Errorf("default timeout = %v, want 30s", got)
	}
	if got := validateTimeout(9999); got.Seconds() != 30 {
		t.Errorf("oversized timeout should clamp to default 30s, got %v", got)
	}
	if got := validateTimeout(45); got.Seconds() != 45 {
		t.Errorf("in-range timeout = %v, want 45s", got)
	}
	if got := validateRateLimit(0); got != defaultValidateRateLimit {
		t.Errorf("default rate limit = %d, want %d", got, defaultValidateRateLimit)
	}
	if got := validateRateLimit(99999); got != defaultValidateRateLimit {
		t.Errorf("oversized rate limit should clamp to default, got %d", got)
	}
	if got := validateRateLimit(10); got != 10 {
		t.Errorf("in-range rate limit = %d, want 10", got)
	}
}

func TestSanitizeValidationEvidence(t *testing.T) {
	r := Result{
		TemplateID:  "apache-struts-rce",
		Matched:     "https://example.com/struts",
		MatcherName: "status",
		Type:        "http",
		Response:    strings.Repeat("A", maxValidateEvidenceBytes*2),
	}
	r.Info.Severity = "high"
	r.Info.Tags = []string{"cve", "rce"}

	ev := sanitizeValidationEvidence(r)
	if ev["template_id"] != "apache-struts-rce" {
		t.Errorf("template_id = %v", ev["template_id"])
	}
	if ev["matched_at"] != "https://example.com/struts" {
		t.Errorf("matched_at = %v", ev["matched_at"])
	}
	excerpt, _ := ev["response_excerpt"].(string)
	if len(excerpt) <= maxValidateEvidenceBytes || len(excerpt) > maxValidateEvidenceBytes+len("...[truncated]") {
		t.Errorf("response excerpt not bounded to %d bytes: len=%d", maxValidateEvidenceBytes, len(excerpt))
	}
	// Must not leak request or curl-command.
	if _, ok := ev["request"]; ok {
		t.Error("evidence must not include the raw request")
	}
}

// --- helpers ---

func argValue(args []string, flag string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func argPairPresent(args []string, flag, val string) bool {
	return argValue(args, flag) == val
}
