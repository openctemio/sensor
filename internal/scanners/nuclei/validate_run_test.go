package nuclei

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNuclei is a stand-in for nuclei 3.11.1 with what matters here, as
// observed on the real binary:
//
//   - `-tl` prints a "Listing available nuclei templates for <dir>" header on
//     stdout, then one path per template the -id/-etags selection keeps;
//   - a run whose selection keeps no template prints
//     "[FTL] Could not run nuclei: no templates provided for scan" on stderr
//     and exits 1;
//   - a run prints one JSON line per match and exits 0; with -ms, also one
//     line per request that did not match ("matcher-status":false, with
//     the request and response) or failed ("error").
//
// Templates: "clean-detect" (tags misc) matches, "clean-nomatch" (tags cve)
// does not, "activemq-upload" carries the intrusive tag (as CVE-2016-3088
// does). "exit-two" runs and exits 2; "no-tpl-exit0" prints the no-templates
// message with exit 0; "req-error" runs and its request fails; listing
// "list-fails" exits 3 (the lookup itself fails). (The scanner environment is allowlisted, so the
// behavior is keyed on the id, not on environment variables.)
const fakeNuclei = `#!/bin/sh
list=0; id=""; etags=""; ms=0
while [ $# -gt 0 ]; do
  case "$1" in
    -tl) list=1 ;;
    -ms) ms=1 ;;
    -id) id="$2"; shift ;;
    -etags) etags="$2"; shift ;;
  esac
  shift
done
selected=""
case "$id" in
  clean-detect|clean-nomatch|exit-two|no-tpl-exit0|token-detect|req-error) selected="$id" ;;
  activemq-upload) case ",$etags," in *,intrusive,*) ;; *) selected="$id" ;; esac ;;
esac
if [ "$list" = 1 ]; then
  if [ "$id" = list-fails ]; then echo "[FTL] Could not load templates: busy" >&2; exit 3; fi
  echo ""
  echo "Listing available  nuclei templates for /home/openctem/nuclei-templates"
  [ -n "$selected" ] && echo "/tpl/$selected.yaml"
  exit 0
fi
if [ "$selected" = no-tpl-exit0 ]; then
  echo "[FTL] Could not run nuclei: no templates provided for scan" >&2; exit 0
fi
if [ "$selected" = exit-two ]; then echo "[ERR] boom" >&2; exit 2; fi
if [ -z "$selected" ]; then
  echo "[FTL] Could not run nuclei: no templates provided for scan" >&2; exit 1
fi
if [ "$selected" = token-detect ]; then
  echo '{"template-id":"token-detect","info":{"name":"d","severity":"info","tags":["misc"]},"type":"http","matched-at":"http://ops:hunter2@t/admin?api_key=sk-live-SECRET123","matcher-name":"m"}'
  exit 0
fi
if [ "$selected" = clean-detect ]; then
  printf '%s\n' '{"template-id":"clean-detect","info":{"name":"d","severity":"info","tags":["misc"]},"type":"http","matched-at":"http://t/robots.txt","matcher-name":"m","matcher-status":true,"request":"GET /robots.txt HTTP/1.1\r\nHost: t\r\nCookie: sid=fakesid0000\r\n\r\n","response":"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDisallow: /admin\n","curl-command":"curl -H '"'"'Cookie: sid=fakesid0000'"'"' http://t/robots.txt"}'
fi
if [ "$selected" = clean-nomatch ] && [ "$ms" = 1 ]; then
  printf '%s\n' '{"template-id":"clean-nomatch","info":{"name":"n","severity":"info","tags":["cve"]},"type":"http","matched-at":"http://t/vuln","matcher-status":false,"request":"GET /vuln HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer fakebearer9999\r\n\r\n","response":"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnot found\n"}'
fi
if [ "$selected" = req-error ]; then
  printf '%s\n' '{"template-id":"req-error","info":{"name":"e","severity":"info","tags":["cve"]},"type":"http","matched-at":"http://t/x?token=fakequerytoken","matcher-status":false,"error":"Get \"http://t/x?token=fakequerytoken\": dial tcp: i/o timeout"}'
fi
exit 0
`

func fakeNucleiBin(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(p, []byte(fakeNuclei), 0o700); err != nil { //nolint:gosec // a test script must be executable
		t.Fatal(err)
	}
	return p
}

func validateWith(t *testing.T, bin, id string) *ValidateResult {
	t.Helper()
	res, err := ValidateSingleTemplate(context.Background(), ValidateOptions{
		Target:     "http://t",
		TemplateID: id,
		Binary:     bin,
	})
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return res
}

// A retest that did not run the template must never read as "fixed".
func TestValidateSingleTemplate_NotRunIsNeverNotDetected(t *testing.T) {
	bin := fakeNucleiBin(t)
	cases := map[string]struct {
		id string
	}{
		// The template carries an excluded tag: -etags drops it.
		"excluded tag": {id: "activemq-upload"},
		// Not installed. nuclei 3.x's -tl header made the old check say
		// "installed" for any id.
		"not installed": {id: "no-such-template"},
		// Another nuclei failure.
		"nuclei exit 2": {id: "exit-two"},
		// The no-templates message even with exit 0.
		"no templates, exit 0": {id: "no-tpl-exit0"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := validateWith(t, bin, tc.id)
			if res.Outcome != OutcomeInconclusive {
				t.Fatalf("outcome = %q (%s), want inconclusive", res.Outcome, res.Summary)
			}
		})
	}
}

func TestValidateSingleTemplate_RanOutcomes(t *testing.T) {
	bin := fakeNucleiBin(t)
	if res := validateWith(t, bin, "clean-nomatch"); res.Outcome != OutcomeNotDetected {
		t.Errorf("a template that ran and did not match: outcome = %q (%s), want not_detected", res.Outcome, res.Summary)
	}
	res := validateWith(t, bin, "clean-detect")
	if res.Outcome != OutcomeDetected || !res.Matched || res.MatchedAt != "http://t/robots.txt" {
		t.Errorf("a template that matched: %+v, want detected at http://t/robots.txt", res)
	}
}

// SECURITY: a credential in the matched URL never reaches the verdict's
// summary or matched-at (they become retest reasons on the platform).
func TestValidateSingleTemplate_MatchedURLRedacted(t *testing.T) {
	res := validateWith(t, fakeNucleiBin(t), "token-detect")
	if res.Outcome != OutcomeDetected {
		t.Fatalf("outcome %q (%s)", res.Outcome, res.Summary)
	}
	for _, leaked := range []string{"sk-live-SECRET123", "hunter2"} {
		if strings.Contains(res.Summary, leaked) || strings.Contains(res.MatchedAt, leaked) {
			t.Fatalf("%s leaked: summary %q matched_at %q", leaked, res.Summary, res.MatchedAt)
		}
	}
}

func TestIsTemplateFile(t *testing.T) {
	cases := map[string]bool{
		"/home/openctem/nuclei-templates/http/cves/2021/CVE-2021-41773.yaml": true,
		"/tpl/x.YML":  true,
		"/tpl/x.json": true,
		"Listing available  nuclei templates for /home/openctem/nuclei-templates": false,
		"[INF] Templates loaded: 1": false,
		"":                          false,
		"/tpl/README.md":            false,
	}
	for line, want := range cases {
		if got := isTemplateFile(line); got != want {
			t.Errorf("isTemplateFile(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestLastStderrLine(t *testing.T) {
	got := lastStderrLine([]byte("[\x1b[34mINF\x1b[0m] x\n[\x1b[35mFTL\x1b[0m] Could not run nuclei: no templates provided for scan\n\n"))
	if got != "[FTL] Could not run nuclei: no templates provided for scan" {
		t.Errorf("lastStderrLine = %q", got)
	}
	if got := lastStderrLine(nil); got != "no output" {
		t.Errorf("empty stderr = %q", got)
	}
}

// With -ms, a template that ran and did not match carries the attempt's
// exchange (raw, credentials marked); a template whose requests failed is
// inconclusive with an error class that never quotes the URL.
func TestValidateSingleTemplate_AttemptEvidence(t *testing.T) {
	bin := fakeNucleiBin(t)
	res := validateWith(t, bin, "clean-nomatch")
	if res.Outcome != OutcomeNotDetected || len(res.EvidenceItems) != 1 {
		t.Fatalf("outcome %q items %d (%s)", res.Outcome, len(res.EvidenceItems), res.Summary)
	}
	ex := res.EvidenceItems[0]
	if ex.HTTP == nil || ex.HTTP.Response == nil || ex.HTTP.Response.Status != 404 || ex.Label != "attempt (no match)" {
		t.Fatalf("attempt %+v", ex)
	}
	if len(ex.Sensitive) == 0 {
		t.Fatalf("the Authorization value is not marked: %+v", ex)
	}

	res = validateWith(t, bin, "clean-detect")
	if res.Outcome != OutcomeDetected || len(res.EvidenceItems) != 2 || res.EvidenceItems[1].Kind != "curl" {
		t.Fatalf("match evidence %+v", res.EvidenceItems)
	}
	if len(res.EvidenceItems[1].Sensitive) == 0 {
		t.Fatalf("the curl command repeats the cookie unmarked: %+v", res.EvidenceItems[1])
	}

	res = validateWith(t, bin, "req-error")
	if res.Outcome != OutcomeInconclusive || !strings.Contains(res.Summary, "timeout") || len(res.EvidenceItems) != 0 {
		t.Fatalf("a failed request: %+v", res)
	}
	if strings.Contains(res.Summary, "fakequerytoken") || strings.Contains(fmt.Sprint(res.Evidence), "fakequerytoken") {
		t.Fatalf("the error quoted the URL: %+v", res)
	}
}

// A lookup that failed (nuclei -tl erroring or timing out, e.g. on a sensor
// busy validating a new template release) is inconclusive and says so; it
// never claims the template is not installed. A template the lookup did not
// find still says not installed.
func TestValidateSingleTemplate_LookupFailureIsNotNotInstalled(t *testing.T) {
	bin := fakeNucleiBin(t)
	res := validateWith(t, bin, "list-fails")
	if res.Outcome != OutcomeInconclusive {
		t.Fatalf("outcome = %q (%s), want inconclusive", res.Outcome, res.Summary)
	}
	if strings.Contains(res.Summary, "not installed") || !strings.Contains(res.Summary, "could not look up") {
		t.Fatalf("summary = %q, want a lookup failure, not \"not installed\"", res.Summary)
	}
	if res.Evidence["lookup_failed"] != true {
		t.Fatalf("evidence = %v, want lookup_failed", res.Evidence)
	}
	res = validateWith(t, bin, "no-such-template")
	if !strings.Contains(res.Summary, "not installed") {
		t.Fatalf("a template the lookup did not find: summary = %q", res.Summary)
	}
}
