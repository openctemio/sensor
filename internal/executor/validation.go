package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
)

// Validation (CTEM Stage-4, RFC-011) — safe-check executor.
//
// The API enqueues a `validate` command carrying a finding + a target address.
// This executor runs a NON-INTRUSIVE reachability re-check (TCP connect, honest
// primitive for ATT&CK T1046 "network service discovery") and reports an
// outcome that the API maps back into finding evidence:
//
//	detected      → target still reachable (exposure not fixed)
//	not_detected  → target no longer reachable (fix stood → finding resolved)
//	inconclusive  → could not tell (timeouts, no clear refusal)
//	error         → target refused by the SSRF guard / bad input
//
// It reuses the same target guard as the scanners (validateScannerTarget), so a
// validate job can never be turned into an SSRF probe of loopback / IMDS /
// RFC1918 space (unless the operator opted into private targets).

// validateCommandType is the command Type the API sets for validation jobs
// (mirrors api CommandTypeValidate). Kept local to avoid an api dependency.
const validateCommandType = "validate"

// nucleiExecutorKind is the ExecutorKind the API sets when it wants the deeper
// re-verify rung: re-run the finding's OWN detection template (RFC-011.2 Phase
// 2b). Anything else on a validate command is handled as safe-check.
const nucleiExecutorKind = "nuclei"

// nucleiValidateRateLimit bounds requests/second for a single-asset re-verify.
// Deliberately far below the scan default (150 rps): a re-verify touches one
// asset with one template and must not look like an attack.
const nucleiValidateRateLimit = 20

// validateJobPayload mirrors the API's ValidateCommandPayload (the wire contract).
type validateJobPayload struct {
	JobID        string `json:"job_id"`
	FindingID    string `json:"finding_id"`
	ExecutorKind string `json:"executor_kind"`
	Technique    string `json:"technique"`
	Target       struct {
		AssetID string `json:"asset_id"`
		Type    string `json:"type"`
		Address string `json:"address"`
	} `json:"target"`
	TimeoutSeconds int `json:"timeout_seconds"`
	// TemplateID / CVEID carry the finding's own detection signature for a
	// KindNuclei re-verify (RFC-011.2 Phase 2b). Empty for a safe-check job.
	TemplateID string `json:"template_id,omitempty"`
	CVEID      string `json:"cve_id,omitempty"`
}

// ValidatingCommandExecutor wraps an inner command executor and handles
// `validate` commands itself (safe-check), delegating everything else. It
// implements core.CommandExecutor so it can be dropped into the command poller.
type ValidatingCommandExecutor struct {
	inner   core.CommandExecutor
	verbose bool
	// workspace confines code-scanner (filesystem) targets; nil refuses them.
	workspace *Workspace
	// nucleiTemplates returns the managed nuclei templates directory, its
	// release (version and archive digest) and a release func for a
	// re-verification; nil: nuclei's own directory.
	nucleiTemplates func(ctx context.Context) (string, core.ContentInfo, func())
	// local is the sensor-local policy (api RFC-040 §5.7); nil: none. A
	// reload (SIGHUP) replaces it while commands run.
	local atomic.Pointer[core.LocalPolicy]
	// cmdLog is the logger of the command a context runs for (sensorkit
	// Kit.CommandLogger): lines reach the command's log on the platform.
	cmdLog func(ctx context.Context) *slog.Logger
}

// SetCommandLogger makes validation write its steps to the command's log on
// the platform (sensorkit Kit.CommandLogger).
func (e *ValidatingCommandExecutor) SetCommandLogger(f func(ctx context.Context) *slog.Logger) {
	e.cmdLog = f
}

// logf writes one line to the command's log (nothing without a logger).
func (e *ValidatingCommandExecutor) logf(ctx context.Context, level slog.Level, msg string, args ...any) {
	if e.cmdLog != nil {
		e.cmdLog(ctx).Log(ctx, level, msg, args...)
	}
}

// SetLocalPolicy makes validate jobs obey the sensor-local policy behind the
// command poller's admission check: the target is checked again, the
// safe-check connects only through the policy's guarded dialer (the
// addresses it checked, never a second resolution), and a nuclei
// re-verification runs at most at rate.max_rps.
func (e *ValidatingCommandExecutor) SetLocalPolicy(lp *core.LocalPolicy) {
	e.local.Store(lp)
}

// SetNucleiTemplates makes nuclei re-verifications look their template up in
// the sensor's managed template set (internal/content).
func (e *ValidatingCommandExecutor) SetNucleiTemplates(f func(ctx context.Context) (string, core.ContentInfo, func())) {
	e.nucleiTemplates = f
}

// SetWorkspace sets the directories code-scanner targets are confined to.
// Without one, filesystem targets are refused.
func (e *ValidatingCommandExecutor) SetWorkspace(ws *Workspace) {
	e.workspace = ws
}

// NewValidatingCommandExecutor wraps inner so validate commands run a safe-check.
func NewValidatingCommandExecutor(inner core.CommandExecutor, verbose bool) *ValidatingCommandExecutor {
	return &ValidatingCommandExecutor{inner: inner, verbose: verbose}
}

// scanCommandType is the command Type the API sets for scan jobs. Its targets
// come from ingested asset data, so they are attacker-influenceable.
const scanCommandType = "scan"

// scanJobPayload is the subset of a scan command this executor inspects. The
// API writes a single "target" for single-scanner jobs and a "targets" array
// for multi-target ones (internal/app/scan/trigger.go), so both are checked.
type scanJobPayload struct {
	Scanner       string   `json:"scanner"`
	ScannerName   string   `json:"scanner_name"`
	PreferredTool string   `json:"preferred_tool"`
	Target        string   `json:"target"`
	Targets       []string `json:"targets"`
}

// scanner names the tool that will receive the targets; the API writes it as
// "scanner" (the field the SDK executor reads) and "scanner_name", pipeline
// steps as "preferred_tool".
func (p scanJobPayload) scanner() string {
	for _, s := range []string{p.Scanner, p.ScannerName, p.PreferredTool} {
		if s != "" {
			return s
		}
	}
	return ""
}

// Execute runs the safe-check for validate commands, guards scan targets, and
// otherwise delegates.
func (e *ValidatingCommandExecutor) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	if cmd != nil && cmd.Type == scanCommandType {
		guarded, err := e.guardScanTargets(cmd)
		if err != nil {
			return nil, err
		}
		cmd = guarded
	}

	if cmd == nil || cmd.Type != validateCommandType {
		return e.inner.Execute(ctx, cmd)
	}

	var p validateJobPayload
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		return nil, fmt.Errorf("validate command payload: %w", err)
	}

	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 2*time.Minute {
		timeout = 30 * time.Second
	}

	// The local policy decides before any probe (the poller already
	// admitted the job; this holds when the executor runs on its own too).
	// One policy for the whole job, even if a reload lands meanwhile.
	local := e.local.Load()
	if err := local.CheckTarget(ctx, p.Target.Address); err != nil {
		return nil, err
	}

	start := time.Now()
	var (
		outcome, summary string
		evidence         map[string]any
	)
	kind := p.ExecutorKind
	if kind == "" {
		kind = "safe-check"
	}
	e.logf(ctx, slog.LevelInfo, "Validation started", "executor", kind, "template_id", p.TemplateID)
	if p.ExecutorKind == nucleiExecutorKind {
		// Deeper rung: re-run the finding's own detection template. Reuses the
		// same SSRF-guarded target validation as safe-check.
		var set nucleiTemplateSet
		release := func() {}
		if e.nucleiTemplates != nil {
			set.dir, set.content, release = e.nucleiTemplates(ctx)
		}
		outcome, summary, evidence = runNucleiValidate(ctx, cmd.ID, p.Target.Address, p.TemplateID, p.CVEID, set, timeout,
			local.CapRate(validateRateCeiling()), e.verbose)
		release()
	} else {
		var dial dialFunc
		if local != nil {
			dial = local.DialContext(nil)
		}
		outcome, summary, evidence = runSafeCheck(ctx, p.Target.Address, timeout, dial)
	}

	level := slog.LevelInfo
	if outcome == "error" {
		level = slog.LevelError
	}
	// The summary never carries a URL's query or credentials (the nuclei
	// path redacts it); the evidence stays in the result only.
	e.logf(ctx, level, "Validation finished: "+outcome, "executor", kind, "summary", summary,
		"duration_ms", time.Since(start).Milliseconds())
	if e.verbose {
		fmt.Printf("[validate] kind=%s finding=%s target=%q outcome=%s (%s)\n",
			p.ExecutorKind, p.FindingID, p.Target.Address, outcome, summary)
	}

	// The API's completion hook reads outcome/summary/evidence from the command
	// result's `metadata` (that is where the SDK poller places our Metadata).
	return &core.CommandExecutionResult{
		DurationMs: time.Since(start).Milliseconds(),
		Metadata: map[string]any{
			"outcome":  outcome,
			"summary":  summary,
			"evidence": evidence,
		},
	}, nil
}

// guardScanTargets applies the scanner target guard to a scan command before it
// reaches the SDK executor, and returns the command to run.
//
// Why this lives here rather than in the scanner: a scan is handled by
// core.NewDefaultCommandExecutor from sdk-go, outside the sensor's code.
// Guarding at this boundary defends regardless of which sdk-go version is
// pinned: bumping the dependency would fix today's gap and leave the next
// downgrade silently reopening it.
//
// Targets are checked according to the scanner that receives them (see
// checkScanTarget): network scanners get the SSRF/DNS guard, code scanners get
// workspace confinement for paths. A confined path is written back into the
// payload, so the scanner reads exactly the directory that was checked.
//
// Failing closed is deliberate. The hard-blocked tier (link-local/IMDS,
// loopback, CGNAT, multicast) is not openable by configuration; RFC1918 targets
// are allowed via SENSOR_ALLOW_PRIVATE_TARGETS, the same opt-in the validate path
// and the platform build already use.
func (e *ValidatingCommandExecutor) guardScanTargets(cmd *core.Command) (*core.Command, error) {
	if len(cmd.Payload) == 0 {
		return cmd, nil
	}

	var p scanJobPayload
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		// Not a shape we recognise. Refuse rather than pass an unread payload to
		// a scanner: this guard exists precisely because what reaches the
		// scanner is attacker-influenceable.
		return nil, fmt.Errorf("scan command payload could not be parsed for target validation: %w", err)
	}

	refuse := func(err error) error {
		if e.verbose {
			fmt.Printf("[scan] refused: %v\n", err)
		}
		return fmt.Errorf("scan target refused by guard: %w", err)
	}

	changed := false
	check := func(t string) (string, error) {
		v, err := checkScanTarget(e.workspace, p.scanner(), t)
		if err == nil && v != t {
			changed = true
		}
		return v, err
	}

	target := p.Target
	if target != "" {
		v, err := check(target)
		if err != nil {
			return nil, refuse(err)
		}
		target = v
	}
	targets := make([]string, len(p.Targets))
	for i, t := range p.Targets {
		v, err := check(t)
		if err != nil {
			return nil, refuse(err)
		}
		targets[i] = v
	}
	if !changed {
		return cmd, nil
	}

	// Rewrite only the target fields; every other payload key is kept as sent.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(cmd.Payload, &raw); err != nil {
		return nil, fmt.Errorf("scan command payload could not be parsed for target validation: %w", err)
	}
	if p.Target != "" {
		raw["target"], _ = json.Marshal(target)
	}
	if len(p.Targets) > 0 {
		raw["targets"], _ = json.Marshal(targets)
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("rewrite scan payload: %w", err)
	}
	guarded := *cmd
	guarded.Payload = payload
	return &guarded, nil
}

// RunSafeCheck performs a non-intrusive TCP-reachability probe against address
// and returns (outcome, summary, evidence). address may be a bare host, a
// host:port, or an http/https URL. It never scans blocked space — the SSRF
// guard refuses loopback / IMDS / (by default) RFC1918 targets.
func RunSafeCheck(ctx context.Context, address string, timeout time.Duration) (string, string, map[string]any) {
	return runSafeCheck(ctx, address, timeout, nil)
}

// dialFunc connects to a host:port; nil is a plain net.Dialer.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// runSafeCheck is RunSafeCheck with the connections made by dial (the local
// policy's guarded dialer).
func runSafeCheck(ctx context.Context, address string, timeout time.Duration, dial dialFunc) (string, string, map[string]any) {
	address = strings.TrimSpace(address)
	evidence := map[string]any{"address": address}

	if address == "" {
		return "error", "no target address to validate", evidence
	}
	if err := validateScannerTarget(address); err != nil {
		evidence["refused_reason"] = err.Error()
		return "error", fmt.Sprintf("target refused by safe-check guard: %v", err), evidence
	}

	targets, err := resolveDialTargets(address)
	if err != nil {
		evidence["error"] = err.Error()
		return "error", fmt.Sprintf("could not derive a probe target: %v", err), evidence
	}

	return probeReachability(ctx, targets, timeout, evidence, dial)
}

// RunNucleiValidate re-runs a finding's OWN detection template against address,
// non-destructively, and returns (outcome, summary, evidence) using the same
// vocabulary as safe-check (detected / not_detected / inconclusive / error).
//
// Safety (RFC-011.2 §2): it reuses the safe-check SSRF guard
// (validateScannerTarget) so a validate job can never be turned into an SSRF
// probe of loopback / IMDS / RFC1918 space; delegates the single-template run to
// the sdk-go primitive, which is detection-only (dos/fuzz/intrusive excluded by
// tag, template must have a safe matcher), bounded by timeout, and rate-limited
// per asset; and logs every run under the command id (the audit key).
func RunNucleiValidate(ctx context.Context, commandID, address, templateID, cveID string, timeout time.Duration, verbose bool) (string, string, map[string]any) {
	return RunNucleiValidateIn(ctx, commandID, address, templateID, cveID, "", timeout, verbose)
}

// RunNucleiValidateIn is RunNucleiValidate with the template looked up in
// templatesDir (the managed template set); "" uses nuclei's own directory.
func RunNucleiValidateIn(ctx context.Context, commandID, address, templateID, cveID, templatesDir string, timeout time.Duration, verbose bool) (string, string, map[string]any) {
	return runNucleiValidate(ctx, commandID, address, templateID, cveID, nucleiTemplateSet{dir: templatesDir}, timeout, validateRateCeiling(), verbose)
}

// nucleiTemplateSet is the template set a re-verification runs on: the
// managed directory and its release, or nuclei's own directory (zero).
type nucleiTemplateSet struct {
	dir     string
	content core.ContentInfo
}

// runNucleiValidate is RunNucleiValidateIn with the rate ceiling given
// (the operator's nuclei ceiling, lowered by the local policy).
func runNucleiValidate(ctx context.Context, commandID, address, templateID, cveID string, set nucleiTemplateSet, timeout time.Duration, maxRate int, verbose bool) (string, string, map[string]any) {
	address = strings.TrimSpace(address)
	// The signature is the finding's own template id, or its CVE as a
	// CVE->template candidate for cross-scanner findings.
	signature := strings.TrimSpace(templateID)
	if signature == "" {
		signature = strings.TrimSpace(cveID)
	}
	evidence := map[string]any{"address": address, "signature": signature}
	// Which template release the re-verify ran on, next to the template's
	// own digest (template_digest): the closure evaluator compares them with
	// what the finding was recorded with (api research 18, O6).
	if set.content.Version != "" {
		evidence["templates_version"] = set.content.Version
	}
	if set.content.Digest != "" {
		evidence["templates_digest"] = set.content.Digest
	}

	// Log every re-verify with the command id, whether or not it runs — this is
	// the audit trail the RFC requires for a security-sensitive template run.
	fmt.Printf("[validate:nuclei] command=%s target=%q signature=%q\n", commandID, address, signature)

	if address == "" {
		return "error", "no target address to validate", evidence
	}
	if signature == "" {
		return "inconclusive", "finding carries no nuclei detection signature; re-verify limited to reachability", evidence
	}
	if err := validateScannerTarget(address); err != nil {
		evidence["refused_reason"] = err.Error()
		return "error", fmt.Sprintf("target refused by validate guard: %v", err), evidence
	}

	res, err := nuclei.ValidateSingleTemplate(ctx, nuclei.ValidateOptions{
		Target:           address,
		TemplateID:       signature,
		TimeoutSeconds:   int(timeout / time.Second),
		RateLimit:        nucleiValidateRateLimit,
		MaxRateLimit:     maxRate,
		TemplatesDir:     set.dir,
		TemplatesVersion: set.content.Version,
		Verbose:          verbose,
	})
	if err != nil {
		evidence["error"] = err.Error()
		return "error", fmt.Sprintf("nuclei re-verify could not start: %v", err), evidence
	}

	// Merge the primitive's sanitized evidence (matched-at, matcher, severity,
	// bounded response excerpt) onto our envelope.
	for k, v := range res.Evidence {
		evidence[k] = v
	}
	if len(res.EvidenceItems) > 0 {
		// The run's exchange, raw with sensitive values marked (CTIS 1.6
		// evidence items): the platform masks and keeps it.
		evidence["evidence_items"] = res.EvidenceItems
	}
	return string(res.Outcome), res.Summary, evidence
}

// probeReachability TCP-dials each target and classifies the outcome. It does
// NOT apply the SSRF guard — callers (RunSafeCheck) guard first. Split out so
// the reachability decision can be unit-tested against a local listener.
func probeReachability(ctx context.Context, targets []string, timeout time.Duration, evidence map[string]any, dial dialFunc) (string, string, map[string]any) {
	if evidence == nil {
		evidence = map[string]any{}
	}
	evidence["probed"] = targets

	perDial := timeout / time.Duration(len(targets))
	if perDial <= 0 || perDial > 5*time.Second {
		perDial = 5 * time.Second
	}

	var anyOpen, anyRefused, anyTimeout bool
	results := make([]map[string]any, 0, len(targets))
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	for _, t := range targets {
		dctx, cancel := context.WithTimeout(ctx, perDial)
		conn, derr := dial(dctx, "tcp", t)
		cancel()

		res := map[string]any{"target": t}
		switch {
		case derr == nil:
			anyOpen = true
			res["state"] = "open"
			_ = conn.Close()
		case isTimeout(derr):
			anyTimeout = true
			res["state"] = "timeout"
		default:
			anyRefused = true
			res["state"] = "closed"
			res["error"] = derr.Error()
		}
		results = append(results, res)
	}
	evidence["results"] = results

	switch {
	case anyOpen:
		evidence["reachable"] = true
		return "detected", "target is still reachable (exposure not confirmed fixed)", evidence
	case anyRefused && !anyTimeout:
		evidence["reachable"] = false
		return "not_detected", "target is no longer reachable (connection refused)", evidence
	default:
		evidence["reachable"] = false
		return "inconclusive", "could not confirm reachability (no response before timeout)", evidence
	}
}

// resolveDialTargets turns an address (host, host:port, or URL) into the list
// of host:port endpoints to probe. A bare host is probed on 443 then 80.
func resolveDialTargets(address string) ([]string, error) {
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil {
			return nil, err
		}
		host := u.Hostname()
		if host == "" {
			return nil, fmt.Errorf("URL has no host")
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "http" {
				port = "80"
			} else {
				port = "443"
			}
		}
		return []string{net.JoinHostPort(host, port)}, nil
	}

	if host, port, err := net.SplitHostPort(address); err == nil && host != "" && port != "" {
		return []string{net.JoinHostPort(host, port)}, nil
	}

	// Bare host: probe the two common web ports.
	return []string{net.JoinHostPort(address, "443"), net.JoinHostPort(address, "80")}, nil
}

func isTimeout(err error) bool {
	var nerr net.Error
	if errors.As(err, &nerr) {
		return nerr.Timeout()
	}
	return false
}

// validateRateCeiling is the operator's nuclei rate-limit ceiling
// (SENSOR_NUCLEI_MAX_RATE_LIMIT), which re-verification respects too. A bad
// value already stopped the sensor at start; here it means no extra cap.
func validateRateCeiling() int {
	l, err := nuclei.LimitsFromEnv(os.LookupEnv)
	if err != nil {
		return 0
	}
	return l.MaxRateLimit
}
