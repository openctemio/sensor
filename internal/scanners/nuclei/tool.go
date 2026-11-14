package nuclei

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/egressenv"
	"github.com/openctemio/sensor/internal/reachobs"
	"github.com/openctemio/sensor/internal/scanners/importparse"
	"github.com/openctemio/sensor/internal/toolrun"
)

// nuclei as a tool of the tool contract (sdk-go pkg/tool). The scanner
// (Scanner, dispatched and wrapped by the managed content as before) runs
// each scan out of process: the sensor re-executes itself as
// "<sensor> __openctem-tool nuclei" in the task sandbox and Tool runs the
// scanner's direct path there, configured exactly as the parent configured
// it (settings, managed templates, limits). The JSON Lines output is
// converted to CTIS in the child with the same parser, and the runtime
// checks and stamps every record. The proxy credentials travel as declared
// credentials, never as configuration; the interaction server's token never
// reaches the child at all (the task's forwarder adds it, oob.go).

// ToolManifest describes the nuclei tool.
var ToolManifest = toolrun.MustManifest(ToolYAML)

// Tool runs nuclei in the tool child. Settings arrive already applied to
// the scanner (the task's local configuration); the config schema is the
// one the platform validates scan settings against.
var Tool = toolrun.Register(tool.New(ToolManifest, runTool))

// nucleiLocal is what the sensor hands its nuclei child: the configured
// scanner (without its secrets) and the parts of the scan options a run
// uses.
type nucleiLocal struct {
	Scanner *Scanner  `json:"scanner"`
	Scan    nucleiRun `json:"scan"`
	// Applied carries which of the scanner's values came from the scan's
	// resolved settings (unexported on Scanner, so not in its JSON): without
	// it the child would re-cap the settings' limits as a command's raw
	// limits and drop a retries setting of 0.
	Applied appliedSettings `json:"applied"`
}

type appliedSettings struct {
	Retries bool `json:"retries,omitempty"`
	Limits  bool `json:"limits,omitempty"`
}

type nucleiRun struct {
	ExtraArgs         []string          `json:"extra_args,omitempty"`
	Env               map[string]string `json:"env,omitempty"`
	CustomTemplateDir string            `json:"custom_template_dir,omitempty"`
	AllowInteractsh   bool              `json:"allow_interactsh,omitempty"`
	RateLimit         int               `json:"rate_limit,omitempty"`
	BulkSize          int               `json:"bulk_size,omitempty"`
	Concurrency       int               `json:"concurrency,omitempty"`
	Verbose           bool              `json:"verbose,omitempty"`
	Exclude           []string          `json:"exclude,omitempty"`
}

func runOf(opts *core.ScanOptions) nucleiRun {
	if opts == nil {
		return nucleiRun{}
	}
	return nucleiRun{ExtraArgs: opts.ExtraArgs, Env: opts.Env, CustomTemplateDir: opts.CustomTemplateDir,
		AllowInteractsh: opts.AllowInteractsh, RateLimit: opts.RateLimit, BulkSize: opts.BulkSize,
		Concurrency: opts.Concurrency, Verbose: opts.Verbose, Exclude: opts.Exclude}
}

func (r nucleiRun) options() *core.ScanOptions {
	return &core.ScanOptions{ExtraArgs: r.ExtraArgs, Env: r.Env, CustomTemplateDir: r.CustomTemplateDir,
		AllowInteractsh: r.AllowInteractsh, RateLimit: r.RateLimit, BulkSize: r.BulkSize,
		Concurrency: r.Concurrency, Verbose: r.Verbose, Exclude: r.Exclude}
}

// outOfProcess runs the configured scanner sc in the tool child.
func (sc *Scanner) outOfProcess(ctx context.Context, targets []string, opts *core.ScanOptions, plan oobPlan) (*core.ScanResult, error) {
	start := time.Now()
	cp := *sc
	// The forwarder's per-host rate stays under nuclei's effective limit;
	// it carries the interaction API and adds the server's token (the
	// child's copy of the scanner holds only the server's name).
	rate, _, _ := cp.EffectiveLimits(opts)
	res, out, err := toolrun.Run(ctx, Tool, targets, nucleiLocal{Scanner: &cp, Scan: runOf(opts),
		Applied: appliedSettings{Retries: cp.retriesSet, Limits: cp.limitsFromSettings}},
		toolhost.RunOptions{TargetRate: float64(rate), OOB: sc.oobServer(plan)})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if res.ScannerVersion == "" {
		res.ScannerVersion = sc.version
	}
	if r := out.Report; r != nil && len(r.Assets) == 0 && len(r.Findings) == 0 && len(r.Dependencies) == 0 {
		// Nothing found: no output, as the direct path. The executor then
		// pushes an empty, command-bound report with the run's coverage.
		res.RawOutput = nil
	}
	res.StartedAt, res.FinishedAt = start.Unix(), time.Now().Unix()
	return res, nil
}

// runTool is nuclei's Run in the tool child.
func runTool(ctx tool.Context, task tool.Task, _ json.RawMessage) error {
	var local nucleiLocal
	if err := json.Unmarshal(task.Local, &local); err != nil || local.Scanner == nil {
		return tool.Invalid("nuclei: the sensor's task configuration is missing or unreadable")
	}
	sc := local.Scanner
	// The job's identification (a program's User-Agent and headers) goes on
	// every request: nuclei's -header applies to all of them.
	sc.Headers = toolrun.IdentityHeaders(task, sc.Headers)
	sc.retriesSet, sc.limitsFromSettings = local.Applied.Retries, local.Applied.Limits
	if task.WebScope != nil {
		// The forwarder enforces the scope; without one nuclei would run
		// unrestricted.
		if !egressenv.Confined() {
			return tool.Refused(ErrWebScopeUnconfined.Error())
		}
		sc.webScoped = true
	}
	opts := local.Scan.options()
	if len(task.Targets) == 1 {
		t := task.Targets[0]
		if err := validateRun(opts); err != nil {
			return tool.Failed(err)
		}
		res, err := sc.execute(ctx, t.Value, "", opts, t.Value)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return tool.Failed(err)
		}
		if err := emitResult(ctx, res, "", ruleSet{}); err != nil {
			return err
		}
		ctx.TargetDone(t)
		return nil
	}
	// A list runs in waves of whole hosts: nuclei reports no host as
	// finished before its whole run ends, so each wave's results are
	// delivered and its hosts released as the wave ends (core.RunWaves).
	byValue := make(map[string]tool.Target, len(task.Targets))
	values := make([]string, 0, len(task.Targets))
	for _, t := range task.Targets {
		if _, dup := byValue[t.Value]; !dup {
			byValue[t.Value] = t
			values = append(values, t.Value)
		}
	}
	n := 0
	rules := ruleSet{}
	err := core.RunWaves(ctx, values, "", TargetWaves, func(wctx context.Context, wave []string) error {
		res, err := sc.scanTargetsDirect(wctx, wave, opts)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return tool.Failed(err)
		}
		n++
		return emitResult(ctx, res, fmt.Sprintf("w%d-", n), rules)
	}, func(v string) { ctx.TargetDone(byValue[v]) })
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// A wave that failed after earlier ones ended: the runtime delivers the
	// settled targets' records and lists the others as unfinished.
	return err
}

// TargetWaves is how many nuclei runs a task over several hosts is cut
// into (core.PlanWaves): each wave's hosts are released for the next tool
// of a pipeline as soon as it ends, at the cost of loading the templates
// once more per wave (measured ~5 s against minutes per host). A wave's
// hosts get no more rate than a one-host task does.
const TargetWaves = 4

// ruleSet maps a template id to the id of the rule a wave of the task
// already emitted for it: a template is described once per report.
type ruleSet map[string]string

// emitResult converts one nuclei run's output to CTIS and emits it, with
// the hosts nuclei's host breaker skipped. idPrefix keeps the report's
// asset and rule ids apart from another wave's: each run's converter
// numbers them from 1, and a finding must stay on its own wave's asset.
// A template an earlier wave already described keeps that wave's rule
// (rules).
func emitResult(ctx tool.Context, res *core.ScanResult, idPrefix string, rules ruleSet) error {
	var report *ctis.Report
	if len(bytes.TrimSpace(res.RawOutput)) > 0 {
		var err error
		report, err = importparse.Nuclei().Parse(ctx, res.RawOutput, &core.ParseOptions{ToolName: "nuclei"})
		if err != nil {
			return tool.Failed(err)
		}
		if res.Error != "" {
			// The run completed with problems (templates that failed):
			// its coverage is partial, as the command executor would say.
			report.Metadata.CoverageType = ctis.CoveragePartial
			ctx.Log().Warn("nuclei run completed with errors", "error", res.Error)
		}
		prefixAssetIDs(report, idPrefix)
		shareRules(report, rules)
		// Matches on a throttling or block answer are kept and held, never
		// dropped (screen.go).
		if n := screenReport(report); n > 0 {
			ctx.Log().Info("nuclei matches held for verification", "findings", n)
		}
	}
	// Callbacks that did not register travel in the report's properties
	// too (toolrun.TakeReportOOB).
	if res.OOB != nil {
		if report == nil {
			report = ctis.NewReport()
		}
		reportOOB(report, res.OOB)
		ctx.Log().Warn("nuclei could not register with the interaction server; the run went on without callbacks")
	}
	// Hosts nuclei's host breaker skipped travel in the report's
	// properties (toolrun.Run reads them back), also when nothing was
	// found.
	if res.HasCoverageGaps() {
		if report == nil {
			report = ctis.NewReport()
		}
		toolrun.SetReportGaps(report, res.CoverageGaps, res.CoverageGapsTotal)
		// The skipped hosts were not reached: the sensor's reach recorder
		// reads them (toolrun takes them off the report).
		reachobs.Attach(report, unresponsiveObs(res.CoverageGaps))
		report.Metadata.CoverageType = ctis.CoveragePartial
		ctx.Log().Warn("nuclei skipped unresponsive hosts", "hosts", res.CoverageGapsTotal)
	}
	if report != nil {
		if err := ctx.Emit().Report(report); err != nil {
			if errors.Is(err, tool.ErrOutputLimit) {
				return err
			}
			ctx.Log().Warn("nuclei: a record was refused", "error", err.Error())
		}
	}
	return nil
}

// prefixAssetIDs prefixes the report's asset and rule ids and the
// findings' references to them.
func prefixAssetIDs(r *ctis.Report, prefix string) {
	if prefix == "" {
		return
	}
	for i := range r.Assets {
		if r.Assets[i].ID != "" {
			r.Assets[i].ID = prefix + r.Assets[i].ID
		}
	}
	for i := range r.Rules {
		r.Rules[i].ID = prefix + r.Rules[i].ID
	}
	for i := range r.Findings {
		if r.Findings[i].AssetRef != "" {
			r.Findings[i].AssetRef = prefix + r.Findings[i].AssetRef
		}
		if r.Findings[i].RuleRef != "" {
			r.Findings[i].RuleRef = prefix + r.Findings[i].RuleRef
		}
	}
}

// shareRules drops the rules of templates an earlier wave already emitted
// and points their findings at that wave's rule; the others are recorded
// in seen.
func shareRules(r *ctis.Report, seen ruleSet) {
	remap := map[string]string{}
	kept := r.Rules[:0]
	for _, rule := range r.Rules {
		if id, ok := seen[rule.RuleID]; ok {
			remap[rule.ID] = id
			continue
		}
		seen[rule.RuleID] = rule.ID
		kept = append(kept, rule)
	}
	r.Rules = kept
	if len(r.Rules) == 0 {
		r.Rules = nil
	}
	for i := range r.Findings {
		if id, ok := remap[r.Findings[i].RuleRef]; ok {
			r.Findings[i].RuleRef = id
		}
	}
}

// ToolContract names nuclei's tool manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return toolrun.Contract(ToolManifest) }
