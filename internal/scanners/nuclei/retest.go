package nuclei

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Retest of nuclei findings (the platform's retest command, sdk-go tool
// contract "retest"): each item is a finding with its own template id
// (rule_id) on one of the task's targets. The nuclei-validate tool checks,
// in its sandboxed child, for each target:
//
//  1. reachability: a TCP connect to the target's port (the scheme's, or
//     443 then 80 for a bare host). An unreachable target is reported
//     failed, so every item on it is unverifiable: a host that is down,
//     or a sensor in the wrong network, never reads as "fixed";
//  2. each item's template, with the re-verification's safety flags (one
//     signed template, destructive classes excluded, rate ceiling):
//     detected is still_present, not_detected is fixed, anything else
//     (template not installed or excluded, nuclei error) is unverifiable.
//     An item with a delivered check (tool.RetestItem.TemplatePath, set by
//     sdk-go after it verified the platform's signature and the content)
//     runs exactly that file instead, without nuclei's own signature
//     requirement, after a load check: a file that does not load is
//     unverifiable, never fixed. Its verdict carries the file's digest.
//
// The runtime enforces the rest: items only on admitted targets, no
// records, "fixed" only for a target reported done in a task that
// finished.

// reachTimeout bounds one reachability connect.
const reachTimeout = 5 * time.Second

// Retest runs a retest task of nuclei findings out of process with opts
// (the sensor's template set and rate ceiling; Target and TemplateID are
// taken from each item, never from opts).
func Retest(ctx context.Context, opts ValidateOptions, task tool.Task) (*toolhost.Outcome, error) {
	opts.Target, opts.TemplateID, opts.TemplatePath = "", "", ""
	raw, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("nuclei retest: encode the task: %w", err)
	}
	task.Local = raw
	return toolrun.RunTask(ctx, ValidateTool, task, toolhost.RunOptions{})
}

// retestValidateTool is the retest handler in the tool child.
func retestValidateTool(ctx tool.RetestContext, task tool.Task) error {
	var opts ValidateOptions
	if err := json.Unmarshal(task.Local, &opts); err != nil {
		return tool.Invalid("nuclei retest: the sensor's task configuration is missing or unreadable")
	}
	opts.Headers = toolrun.IdentityHeaders(task, opts.Headers)
	if err := applyTaskWebScope(&opts, task); err != nil {
		return err
	}
	byTarget := map[string][]tool.RetestItem{}
	for _, it := range task.Retest {
		byTarget[it.Target] = append(byTarget[it.Target], it)
	}
	for _, t := range task.Targets {
		items := byTarget[t.Ref]
		if len(items) == 0 {
			ctx.TargetSkipped(t, "no retest item on this target")
			continue
		}
		if err := reachable(ctx, t); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Each item says why it has no conclusion: the platform shows
			// the reason, never a bare "no verdict".
			reason := "the sensor could not connect to the target: " + err.Error()
			code := tool.CodeTargetUnreachable
			terr := tool.Unreachable(err)
			if errors.Is(err, tool.ErrEgressRefused) {
				reason = "the sensor's network confinement refused the target"
				code = tool.CodeEgressRefused
				terr = tool.Refused(reason)
			}
			for _, it := range items {
				ctx.Report(it, tool.VerdictReport{Verdict: tool.Unverifiable, Detail: reason, Code: code})
			}
			ctx.TargetError(t, terr)
			continue
		}
		for _, it := range items {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			o := opts
			o.Target, o.TemplateID, o.TemplatePath, o.Delivered = t.Value, it.RuleID, "", false
			check := "template " + it.RuleID
			if it.TemplatePath != "" {
				// The check the platform delivered for this item, verified
				// and written by sdk-go: exactly that file runs.
				o.TemplateID, o.TemplatePath, o.Delivered = "", it.TemplatePath, true
				check = "the delivered check"
			}
			res, err := validateSingleTemplateDirect(ctx, o)
			switch {
			case err != nil:
				r := tool.VerdictReport{Verdict: tool.Unverifiable, Detail: err.Error()}
				if errors.Is(err, errExcludedClass) {
					r.Code = tool.CodeExcludedByPolicy
				}
				ctx.Report(it, r)
			case res == nil:
				ctx.Verdict(it, tool.Unverifiable, "no outcome")
			default:
				// The verdict carries the run's exchange and the digest of
				// the template that ran: the runtime keeps "fixed" only with
				// the attempt's answered exchange.
				r := tool.VerdictReport{Verdict: tool.Unverifiable, Detail: res.Summary, Code: res.Code,
					Evidence: capVerdictEvidence(res.EvidenceItems), TemplateDigest: res.TemplateDigest, Requests: res.Requests}
				switch res.Outcome {
				case OutcomeDetected:
					r.Verdict = tool.StillPresent
				case OutcomeNotDetected:
					r.Verdict = tool.Fixed
					r.Detail = check + " ran against the reachable target and did not match"
				}
				ctx.Report(it, r)
			}
		}
		ctx.TargetDone(t)
	}
	return nil
}

// reachable connects to the target's port: the explicit or scheme port, or
// 443 then 80 for a bare host.
func reachable(ctx context.Context, t tool.Target) error {
	host := t.Host()
	if host == "" {
		return errors.New("the target has no host")
	}
	ports := []int{t.Port()}
	if ports[0] == 0 {
		ports = []int{443, 80}
	}
	var last error
	for _, p := range ports {
		dctx, cancel := context.WithTimeout(ctx, reachTimeout)
		// tool.Dial goes through the task's forwarder on a sensor that
		// confines the tool's network (a direct connection has no route
		// there, which read as every target being down) and connects
		// directly elsewhere.
		conn, err := tool.Dial(dctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		cancel()
		if err == nil {
			_ = conn.Close()
			return nil
		}
		last = err
	}
	return fmt.Errorf("not reachable: %w", last)
}
