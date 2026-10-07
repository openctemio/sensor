package nuclei

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/toolrun"
)

// RFC-011.2 Phase 2b — single-template, non-destructive re-verification.
//
// The validation engine (CTEM Stage-4) re-runs a finding's OWN detection
// template to confirm the exposure condition still exists ("controlled
// non-destructive proof"), one rung above safe-check reachability. This is
// proof-of-exposure, NOT exploitation: detection/matcher templates only, never a
// weaponized payload.
//
// This primitive is the sdk-go half of the sensor bump: it runs exactly one
// template against exactly one target, with the destructive template classes
// excluded, bounded by a caller timeout and per-asset rate limit, and returns a
// boolean match + sanitized evidence. The sensor wraps it with SSRF-guarded
// target validation and the command-id audit log; the api maps the outcome into
// the confirm-or-downgrade verdict.

// ExcludedValidationTags are the nuclei template classes never run for
// re-verification: they are destructive or noisy (denial-of-service, fuzzing,
// brute-force, default-credential logins) rather than a non-intrusive
// detection. Enforced two ways — passed
// to nuclei as -etags so such templates never execute, and re-checked on any
// result that comes back (defense-in-depth against a mis-tagged template).
var ExcludedValidationTags = []string{"dos", "fuzz", "intrusive", "brute-force", "bruteforce", "default-login"}

// defaultValidateRateLimit is a conservative per-asset request rate for a
// single-template re-verify (well below the 150 rps scan default): a re-verify
// touches one asset and must not look like an attack.
const defaultValidateRateLimit = 20

// maxValidateEvidenceBytes bounds any response excerpt kept as evidence.
const maxValidateEvidenceBytes = 2048

// ValidateOutcome is the re-verification result, using the same vocabulary the
// api validation-evidence pipeline already maps to a verdict (detected →
// reproducible, not_detected → not_reproducible, inconclusive → no change).
type ValidateOutcome string

const (
	// OutcomeDetected: the template matched — the exposure is still reproducible.
	OutcomeDetected ValidateOutcome = "detected"
	// OutcomeNotDetected: the template ran and did NOT match — no longer reproducible.
	OutcomeNotDetected ValidateOutcome = "not_detected"
	// OutcomeInconclusive: the template could not be run authoritatively (not
	// installed, nuclei error, or a mis-tagged/destructive result was discarded).
	// The api maps this to NO state change, so it can never cause a false downgrade.
	OutcomeInconclusive ValidateOutcome = "inconclusive"
)

// ValidateOptions configures a single-template re-verification.
type ValidateOptions struct {
	// Target is the URL or host to re-verify. The caller (sensor) MUST have
	// already passed it through the SSRF guard; this package does not resolve or
	// re-guard it.
	Target string
	// TemplateID selects the template by nuclei id (`-id`). Preferred: it is the
	// finding's own detection signature. A CVE id (CVE-YYYY-NNNN) is a valid id.
	TemplateID string
	// TemplatePath selects a template file (`-t`). Used only when no id is known.
	// Rejected if it contains a path-traversal shape.
	TemplatePath string
	// TimeoutSeconds bounds the whole run. Clamped to (0, 120]; default 30.
	TimeoutSeconds int
	// RateLimit is requests/second against the asset. Clamped to [1, 150];
	// default 20.
	RateLimit int
	// MaxRateLimit is the operator's ceiling (SENSOR_NUCLEI_MAX_RATE_LIMIT,
	// see LimitsFromEnv); RateLimit never exceeds it. 0: no ceiling beyond
	// the clamp above.
	MaxRateLimit int
	// Binary overrides the nuclei binary path (default "nuclei").
	Binary string
	// TemplatesDir is the template set a TemplateID is looked up in (and run
	// from), when the templates are managed outside nuclei's own directory.
	// Empty: nuclei's configured templates directory.
	TemplatesDir string
	// TemplatesVersion is the release of TemplatesDir. With TemplatesDir
	// set, both nuclei runs get a private configuration naming that
	// directory and release (NewConfigHome), so templates that load helper
	// files run and the release's exclusion list applies.
	TemplatesVersion string
	// Verbose streams nuclei output to logs.
	Verbose bool
}

// ValidateResult is the outcome of a single-template re-verification.
type ValidateResult struct {
	Outcome     ValidateOutcome
	Matched     bool
	TemplateID  string
	MatcherName string
	MatchedAt   string
	Severity    string
	Summary     string
	// TemplateDigest is "sha256:<hex>" of the template file the run
	// selected (empty when no template was runnable or it could not be
	// read): the closure evaluator counts a re-check only when it ran the
	// content the finding was recorded with (api research 18, O6).
	TemplateDigest string
	// Evidence is a small, sanitized map safe to persist (no secrets, no full
	// response bodies): matched-at, matcher name, severity, tags, and a bounded
	// response excerpt.
	Evidence map[string]any
	// EvidenceItems are the run's HTTP exchange (the match, or the attempt
	// that did not match) and its curl command, raw with sensitive values
	// marked (CTIS 1.6). The platform masks them; nothing here logs them.
	EvidenceItems []ctis.EvidenceItem `json:"evidence_items,omitempty"`
}

// TagAllowedForValidation reports whether a single template tag is permitted for
// re-verification (i.e. not a destructive/noisy class).
func TagAllowedForValidation(tag string) bool {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" {
		return true
	}
	for _, ex := range ExcludedValidationTags {
		if tag == ex || strings.Contains(tag, ex) {
			return false
		}
	}
	return true
}

// TemplateTagsAllowed reports whether every tag on a template is permitted. An
// empty tag set is allowed (nuclei -etags already excluded the bad classes at
// run time; this is the belt-and-braces check on what came back).
func TemplateTagsAllowed(tags []string) bool {
	for _, t := range tags {
		if !TagAllowedForValidation(t) {
			return false
		}
	}
	return true
}

func validateTimeout(seconds int) time.Duration {
	if seconds <= 0 || seconds > 120 {
		seconds = 30
	}
	return time.Duration(seconds) * time.Second
}

// validateRateLimit is rl when it is set and at most DefaultRateLimit, else
// defaultValidateRateLimit, and never above ceiling when one is set (the
// operator's SENSOR_NUCLEI_MAX_RATE_LIMIT).
func validateRateLimit(rl, ceiling int) int {
	if rl <= 0 || rl > DefaultRateLimit {
		rl = defaultValidateRateLimit
	}
	if ceiling > 0 && rl > ceiling {
		rl = ceiling
	}
	return rl
}

// buildValidateArgs assembles the nuclei arguments for a single-template,
// detection-only run. Pure and unit-tested: the safety flags (-etags excluding
// dos/fuzz/intrusive, -id/-t single-template selection) must be present and no
// path-traversal template path may pass.
func buildValidateArgs(opts ValidateOptions) ([]string, error) {
	target := strings.TrimSpace(opts.Target)
	if target == "" {
		return nil, fmt.Errorf("validate: target is required")
	}
	id := strings.TrimSpace(opts.TemplateID)
	path := strings.TrimSpace(opts.TemplatePath)
	if id == "" && path == "" {
		return nil, fmt.Errorf("validate: a template id or path is required")
	}
	if path != "" && (strings.Contains(path, "..") || strings.HasPrefix(path, "-")) {
		return nil, fmt.Errorf("validate: refusing suspicious template path %q", path)
	}
	if id != "" && (strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") || strings.HasPrefix(id, "-")) {
		return nil, fmt.Errorf("validate: refusing suspicious template id %q", id)
	}
	if !TagAllowedForValidation(id) {
		return nil, fmt.Errorf("validate: template id %q maps to an excluded (destructive) class", id)
	}

	args := []string{
		"-jsonl",
		"-silent",
		"-no-color",
		"-disable-update-check",
		// Re-verification runs official templates only: signed ones.
		"-disable-unsigned-templates",
		// A line for every request, matched or not (matcher-status): a
		// non-match is the attempt's evidence, an error is no verdict.
		"-ms",
		"-u", target,
	}
	if id != "" {
		if dir := strings.TrimSpace(opts.TemplatesDir); dir != "" {
			if strings.HasPrefix(dir, "-") {
				return nil, fmt.Errorf("validate: refusing suspicious templates dir %q", dir)
			}
			args = append(args, "-t", dir)
		}
		args = append(args, "-id", id)
	} else {
		args = append(args, "-t", path)
	}
	// Non-negotiable safety: exclude destructive/noisy template classes so a
	// re-verify can never run a DoS/fuzz/brute-force/intrusive template even if
	// the selected id/path somehow resolved to one.
	args = append(args, "-etags", strings.Join(ExcludedValidationTags, ","))
	args = append(args, "-rate-limit", fmt.Sprintf("%d", validateRateLimit(opts.RateLimit, opts.MaxRateLimit)))
	return args, nil
}

// ValidateSingleTemplate runs one detection template against one target and
// returns the match + sanitized evidence. It returns not_detected only when
// the template actually ran and did not match. A template that is not
// installed, one the run would exclude (an excluded tag class, unsigned), a
// nuclei exit other than 0, or a run that errored are all inconclusive, so
// the api verdict rule can never turn an unverifiable run into a downgrade
// (an RFC-039 retest would otherwise close a live finding as fixed).
func ValidateSingleTemplate(ctx context.Context, opts ValidateOptions) (*ValidateResult, error) {
	if toolrun.OutOfProcess() {
		return validateOutOfProcess(ctx, opts)
	}
	return validateSingleTemplateDirect(ctx, opts)
}

// validateSingleTemplateDirect is ValidateSingleTemplate in this process
// (the tool child, or the in-process rollback).
func validateSingleTemplateDirect(ctx context.Context, opts ValidateOptions) (*ValidateResult, error) {
	binary := opts.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	args, err := buildValidateArgs(opts)
	if err != nil {
		return nil, err
	}

	templatesDir := strings.TrimSpace(opts.TemplatesDir)
	var env map[string]string
	if templatesDir != "" {
		home, err := NewConfigHome(templatesDir, opts.TemplatesVersion)
		if err != nil {
			return nil, err
		}
		defer func() { _ = home.Close() }()
		env = home.Env()
	}

	// The digest of the template this run executes: the file -tl selects
	// for an id, or the file named by TemplatePath.
	digest := ""
	roots := []string{firstNonEmptyString(templatesDir, GetTemplateDir())}

	// Correctness guard: a `-id` the run would not execute (not installed, or
	// tagged with an excluded class) yields no result line, which must not
	// read as "ran, no match". Confirm the run has a template first, with the
	// same tag exclusions; if we cannot confirm, stay inconclusive.
	if id := strings.TrimSpace(opts.TemplateID); id != "" {
		path, runnable, terr := templateRunnable(ctx, binary, id, templatesDir, env, opts.Verbose)
		if runnable {
			digest, _ = TemplateDigest(resolveTemplatePath(path, roots[0]), roots)
		}
		if terr != nil {
			// The lookup itself failed (a timeout, nuclei exiting non-zero):
			// that says nothing about whether the template is installed.
			return &ValidateResult{
				Outcome:    OutcomeInconclusive,
				TemplateID: id,
				Summary: fmt.Sprintf("could not look up the nuclei template for signature %q (%s); re-verify not upgraded beyond reachability",
					id, lastStderrLine([]byte(terr.Error()))),
				Evidence: map[string]any{"template_id": id, "lookup_failed": true},
			}, nil //nolint:nilerr // an inconclusive lookup is a normal outcome, not an execution error
		}
		if !runnable {
			return &ValidateResult{
				Outcome:    OutcomeInconclusive,
				TemplateID: id,
				Summary: fmt.Sprintf("no runnable nuclei template for signature %q (not installed, or tagged %s); re-verify not upgraded beyond reachability",
					id, strings.Join(ExcludedValidationTags, "/")),
				Evidence: map[string]any{"template_id": id, "installed": false, "runnable": false},
			}, nil //nolint:nilerr // a template the run would not execute is a normal skip, not an execution error
		}
	} else {
		digest, _ = TemplateDigest(resolveTemplatePath(strings.TrimSpace(opts.TemplatePath), roots[0]), roots)
	}

	// Never verbose: the output holds the raw request and response, which
	// are never logged.
	res, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:     binary,
		Args:       args,
		Env:        env,
		Timeout:    validateTimeout(opts.TimeoutSeconds),
		WritePaths: sandboxWritePaths(env, ""),
	})
	out, err := ValidateSingleTemplateResult(res, err, opts)
	if out != nil && digest != "" {
		out.TemplateDigest = digest
		if out.Evidence == nil {
			out.Evidence = map[string]any{}
		}
		out.Evidence["template_digest"] = digest
	}
	return out, err
}

// ValidateSingleTemplateResult turns a re-verification run's execution
// result into its outcome (see ValidateSingleTemplate).
func ValidateSingleTemplateResult(res *core.ExecResult, err error, opts ValidateOptions) (*ValidateResult, error) {
	if err != nil || res.Error != nil {
		reason := "nuclei execution failed"
		if err != nil {
			reason = err.Error()
		} else if res.Error != nil {
			reason = res.Error.Error()
		}
		return &ValidateResult{
			Outcome:    OutcomeInconclusive,
			TemplateID: opts.TemplateID,
			Summary:    fmt.Sprintf("re-verify inconclusive: %s", reason),
			Evidence:   map[string]any{"template_id": opts.TemplateID},
		}, nil //nolint:nilerr // surfaced as an inconclusive outcome, not a hard error
	}

	// nuclei exits non-zero when it ran nothing ("no templates provided for
	// scan": the template was excluded, unsigned or missing) or failed. Exit
	// 0 with that message is treated the same. Only a clean run counts.
	if res.ExitCode != 0 || strings.Contains(string(res.Stderr), noTemplatesMessage) {
		return &ValidateResult{
			Outcome:    OutcomeInconclusive,
			TemplateID: opts.TemplateID,
			Summary:    fmt.Sprintf("re-verify inconclusive: nuclei did not run the template (exit %d: %s)", res.ExitCode, lastStderrLine(res.Stderr)),
			Evidence:   map[string]any{"template_id": opts.TemplateID, "exit_code": res.ExitCode},
		}, nil
	}

	results, perr := statusLines(res.Stdout)
	if perr != nil {
		return &ValidateResult{
			Outcome:    OutcomeInconclusive,
			TemplateID: opts.TemplateID,
			Summary:    "re-verify inconclusive: could not parse nuclei output",
			Evidence:   map[string]any{"template_id": opts.TemplateID},
		}, nil
	}

	// With -ms every request gives a line: matches, attempts that did not
	// match and requests that failed.
	matches, attempts, failures := splitResults(results)
	if len(matches) == 0 {
		if len(failures) > 0 && len(attempts) == 0 {
			// The template ran but its requests failed: no verdict.
			return &ValidateResult{
				Outcome:    OutcomeInconclusive,
				TemplateID: opts.TemplateID,
				Summary:    "re-verify inconclusive: the template's requests failed (" + errorClass(failures[0].Error) + ")",
				Evidence:   map[string]any{"template_id": opts.TemplateID, "error_class": errorClass(failures[0].Error)},
			}, nil
		}
		out := &ValidateResult{
			Outcome:    OutcomeNotDetected,
			Matched:    false,
			TemplateID: opts.TemplateID,
			Summary:    "exposure no longer reproducible: detection template did not match",
			Evidence:   map[string]any{"template_id": opts.TemplateID},
		}
		if len(attempts) > 0 {
			// The attempt that did not match is the proof of the fix.
			out.EvidenceItems = exchangeEvidence(attempts[0].Result, false)
		}
		return out, nil
	}

	r := matches[0]
	if !TemplateTagsAllowed(r.Info.Tags) {
		// A mis-tagged destructive template slipped through -etags: discard the
		// result and stay inconclusive rather than report a match from a template
		// we would never have chosen to run.
		return &ValidateResult{
			Outcome:    OutcomeInconclusive,
			TemplateID: r.TemplateID,
			Summary:    "re-verify inconclusive: matched template carries an excluded tag; discarded",
			Evidence:   map[string]any{"template_id": r.TemplateID, "tags": r.Info.Tags},
		}, nil
	}
	return &ValidateResult{
		Outcome:       OutcomeDetected,
		Matched:       true,
		TemplateID:    r.TemplateID,
		MatcherName:   r.MatcherName,
		MatchedAt:     redactURL(r.Matched),
		Severity:      r.Info.Severity,
		Summary:       fmt.Sprintf("exposure still reproducible: template %q matched at %s", r.TemplateID, redactURL(r.Matched)),
		Evidence:      sanitizeValidationEvidence(r),
		EvidenceItems: exchangeEvidence(r, true),
	}, nil
}

// noTemplatesMessage is what nuclei prints (and exits 1 with) when the
// selection leaves no template to run.
const noTemplatesMessage = "no templates provided for scan"

// maxStderrSummary bounds the nuclei stderr quoted in a summary.
const maxStderrSummary = 200

// lastStderrLine is the last non-empty stderr line, without color codes and
// bounded, for a summary.
func lastStderrLine(stderr []byte) string {
	lines := strings.Split(ansiEscape.ReplaceAllString(string(stderr), ""), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return capText(l, maxStderrSummary)
		}
	}
	return "no output"
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// templateRunnable reports whether a re-verification run of id would execute
// a template: `-tl` (template list) filtered by the id and by the same
// excluded tags as the run. A run error (e.g. templates not downloaded,
// offline, a non-zero exit) returns (false, err) so the caller stays
// inconclusive.
//
// nuclei 3.x prints a "Listing available nuclei templates for <dir>" header
// on stdout before the paths, so only lines that name a template file count.
func templateRunnable(ctx context.Context, binary, id, templatesDir string, env map[string]string, verbose bool) (path string, runnable bool, err error) {
	args := []string{"-tl"}
	if templatesDir != "" {
		args = append(args, "-t", templatesDir)
	}
	args = append(args, "-id", id, "-etags", strings.Join(ExcludedValidationTags, ","),
		"-silent", "-no-color", "-disable-update-check")
	res, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:     binary,
		Args:       args,
		Env:        env,
		Timeout:    30 * time.Second,
		Verbose:    verbose,
		WritePaths: sandboxWritePaths(env, ""),
	})
	if err != nil {
		return "", false, err
	}
	if res.Error != nil {
		return "", false, res.Error
	}
	if res.ExitCode != 0 {
		return "", false, fmt.Errorf("nuclei -tl exited %d: %s", res.ExitCode, lastStderrLine(res.Stderr))
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if l := strings.TrimSpace(line); isTemplateFile(l) {
			return l, true, nil
		}
	}
	return "", false, nil
}

// isTemplateFile reports whether a `-tl` output line names a template file.
func isTemplateFile(line string) bool {
	if line == "" || strings.HasPrefix(line, "[") || strings.ContainsAny(line, " \t") {
		return false
	}
	l := strings.ToLower(line)
	return strings.HasSuffix(l, ".yaml") || strings.HasSuffix(l, ".yml") || strings.HasSuffix(l, ".json")
}

// sanitizeValidationEvidence extracts a small, secret-free evidence map from a
// nuclei result: identity + a bounded response excerpt, never the full
// request/response or extracted secrets.
func sanitizeValidationEvidence(r Result) map[string]any {
	ev := map[string]any{
		"template_id":  r.TemplateID,
		"matcher_name": r.MatcherName,
		"matched_at":   redactURL(r.Matched),
		"severity":     r.Info.Severity,
		"type":         r.Type,
	}
	if len(r.Info.Tags) > 0 {
		ev["tags"] = r.Info.Tags
	}
	if r.Response != "" {
		ev["response_excerpt"] = capText(redactResponse(r.Response, r.Info.Tags, r.ExtractedResults), maxValidateEvidenceBytes)
	}
	return ev
}
