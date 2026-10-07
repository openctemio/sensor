package nuclei

import (
	"context"
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
//   - a run prints one JSON line per match and exits 0.
//
// Templates: "clean-detect" (tags misc) matches, "clean-nomatch" (tags cve)
// does not, "activemq-upload" carries the intrusive tag (as CVE-2016-3088
// does). "exit-two" runs and exits 2; "no-tpl-exit0" prints the no-templates
// message with exit 0. (The scanner environment is allowlisted, so the
// behavior is keyed on the id, not on environment variables.)
const fakeNuclei = `#!/bin/sh
list=0; id=""; etags=""
while [ $# -gt 0 ]; do
  case "$1" in
    -tl) list=1 ;;
    -id) id="$2"; shift ;;
    -etags) etags="$2"; shift ;;
  esac
  shift
done
selected=""
case "$id" in
  clean-detect|clean-nomatch|exit-two|no-tpl-exit0|token-detect) selected="$id" ;;
  activemq-upload) case ",$etags," in *,intrusive,*) ;; *) selected="$id" ;; esac ;;
esac
if [ "$list" = 1 ]; then
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
  echo '{"template-id":"clean-detect","info":{"name":"d","severity":"info","tags":["misc"]},"type":"http","matched-at":"http://t/robots.txt","matcher-name":"m"}'
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
