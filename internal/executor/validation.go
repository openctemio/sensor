package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
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
}

// ValidatingCommandExecutor wraps an inner command executor and handles
// `validate` commands itself (safe-check), delegating everything else. It
// implements core.CommandExecutor so it can be dropped into the command poller.
type ValidatingCommandExecutor struct {
	inner   core.CommandExecutor
	verbose bool
}

// NewValidatingCommandExecutor wraps inner so validate commands run a safe-check.
func NewValidatingCommandExecutor(inner core.CommandExecutor, verbose bool) *ValidatingCommandExecutor {
	return &ValidatingCommandExecutor{inner: inner, verbose: verbose}
}

// Execute runs the safe-check for validate commands; otherwise delegates.
func (e *ValidatingCommandExecutor) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
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

	start := time.Now()
	outcome, summary, evidence := RunSafeCheck(ctx, p.Target.Address, timeout)

	if e.verbose {
		fmt.Printf("[validate] finding=%s target=%q outcome=%s (%s)\n",
			p.FindingID, p.Target.Address, outcome, summary)
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

// RunSafeCheck performs a non-intrusive TCP-reachability probe against address
// and returns (outcome, summary, evidence). address may be a bare host, a
// host:port, or an http/https URL. It never scans blocked space — the SSRF
// guard refuses loopback / IMDS / (by default) RFC1918 targets.
func RunSafeCheck(ctx context.Context, address string, timeout time.Duration) (string, string, map[string]any) {
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

	return probeReachability(ctx, targets, timeout, evidence)
}

// probeReachability TCP-dials each target and classifies the outcome. It does
// NOT apply the SSRF guard — callers (RunSafeCheck) guard first. Split out so
// the reachability decision can be unit-tested against a local listener.
func probeReachability(ctx context.Context, targets []string, timeout time.Duration, evidence map[string]any) (string, string, map[string]any) {
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
	dialer := &net.Dialer{}

	for _, t := range targets {
		dctx, cancel := context.WithTimeout(ctx, perDial)
		conn, derr := dialer.DialContext(dctx, "tcp", t)
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
