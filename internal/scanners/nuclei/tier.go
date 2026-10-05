package nuclei

// Non-intrusive by default (api docs/rfcs/RFC-036-easm.md, tier T1;
// research/22 E2 in openctemio/openctem): a nuclei scan never runs templates
// that log in with default credentials, brute-force, fuzz, flood or are
// marked intrusive. Before, the sensor passed no -etags on a scan, so a
// default scan of a customer's external host ran its default-login and
// intrusive templates, and only managed template sets had the release's
// .nuclei-ignore. The exclusion is now on the command line of every run,
// the sensor's own templates and the platform's custom templates alike.
//
// Measured on nuclei v3.11.1: -etags drops a template however it was
// selected (a -t directory, an explicit -t file, -id, -tags naming the
// excluded tag), and only -itags / -include-tags re-admits one, so those
// two flags are refused in a scan's extra args (DangerousToolFlags already
// refuses -it / -include-templates).

import (
	"fmt"
	"slices"
	"strings"
)

// T1ExcludedTags are the template tags a scan at the default, non-intrusive
// tier never runs: RFC-036 T7's list (intrusive, default-login, fuzz, dos,
// bruteforce) with the spellings the template set uses, plus
// BaselineIgnoreTags (the release's own default exclusions). A scan cannot
// select one (withSettings refuses it) and cannot remove one.
var T1ExcludedTags = mergeTags(
	[]string{"intrusive", "default-login", "dos", "fuzz", "fuzzing", "bruteforce", "brute-force"},
	BaselineIgnoreTags,
)

// tierOverrideFlags are nuclei flags that re-admit templates -etags
// excluded. They never arrive in a scan's extra args.
var tierOverrideFlags = []string{"itags", "include-tags"}

// excludedTags is the -etags value of a run: T1ExcludedTags, then the
// scanner's own exclusions (an operator's or a scan's), without duplicates.
func (s *Scanner) excludedTags() []string {
	return mergeTags(T1ExcludedTags, s.ExcludeTags)
}

// checkTierTags refuses a tag list (a scan's tags setting) that selects a
// template class the default tier excludes: the scan fails with the reason
// instead of running with that tag silently filtered out.
func checkTierTags(tags []string) error {
	for _, t := range tags {
		if slices.Contains(T1ExcludedTags, t) {
			return fmt.Errorf("tag %q selects intrusive templates (default logins, brute force, fuzzing, denial of service); the sensor runs nuclei non-intrusive only", t)
		}
	}
	return nil
}

// checkTierExtraArgs refuses extra args that would re-admit excluded
// templates.
func checkTierExtraArgs(args []string) error {
	for _, a := range args {
		name := strings.ToLower(strings.TrimLeft(strings.TrimSpace(a), "-"))
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if strings.HasPrefix(strings.TrimSpace(a), "-") && slices.Contains(tierOverrideFlags, name) {
			return fmt.Errorf("extra arg %q is not allowed: it re-admits intrusive templates the sensor excludes", a)
		}
	}
	return nil
}

// mergeTags joins tag lists in order, without duplicates or blanks.
func mergeTags(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, t := range l {
			t = strings.TrimSpace(t)
			if t != "" && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	return out
}
