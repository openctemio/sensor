package nuclei

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
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
// checks and stamps every record. The interactsh token and the proxy
// credentials travel as declared credentials, never as configuration.

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
}

func runOf(opts *core.ScanOptions) nucleiRun {
	if opts == nil {
		return nucleiRun{}
	}
	return nucleiRun{ExtraArgs: opts.ExtraArgs, Env: opts.Env, CustomTemplateDir: opts.CustomTemplateDir,
		AllowInteractsh: opts.AllowInteractsh, RateLimit: opts.RateLimit, BulkSize: opts.BulkSize,
		Concurrency: opts.Concurrency, Verbose: opts.Verbose}
}

func (r nucleiRun) options() *core.ScanOptions {
	return &core.ScanOptions{ExtraArgs: r.ExtraArgs, Env: r.Env, CustomTemplateDir: r.CustomTemplateDir,
		AllowInteractsh: r.AllowInteractsh, RateLimit: r.RateLimit, BulkSize: r.BulkSize,
		Concurrency: r.Concurrency, Verbose: r.Verbose}
}

// outOfProcess runs the configured scanner sc in the tool child.
func (sc *Scanner) outOfProcess(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()
	cp := *sc
	creds := map[string]string{}
	if cp.InteractshToken != "" {
		creds["interactsh_token"], cp.InteractshToken = cp.InteractshToken, ""
	}
	if cp.ProxyAuth != "" {
		creds["proxy_auth"], cp.ProxyAuth = cp.ProxyAuth, ""
	}
	res, out, err := toolrun.Run(ctx, Tool, targets, nucleiLocal{Scanner: &cp, Scan: runOf(opts)}, toolhost.RunOptions{Credentials: creds})
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
		// Nothing found: no output, as the direct path (the executor then
		// pushes no report).
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
	if s, err := ctx.Secret("interactsh_token"); err == nil {
		sc.InteractshToken = s.Reveal()
	}
	if s, err := ctx.Secret("proxy_auth"); err == nil {
		sc.ProxyAuth = s.Reveal()
	}
	opts := local.Scan.options()
	values := make([]string, len(task.Targets))
	for i, t := range task.Targets {
		values[i] = t.Value
	}
	var res *core.ScanResult
	var err error
	if len(values) == 1 {
		if err = validateExtraArgs(opts.ExtraArgs); err == nil {
			res, err = sc.execute(ctx, values[0], "", opts, values[0])
		}
	} else {
		res, err = sc.scanTargetsDirect(ctx, values, opts)
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tool.Failed(err)
	}
	if len(bytes.TrimSpace(res.RawOutput)) > 0 {
		report, err := importparse.Nuclei().Parse(ctx, res.RawOutput, &core.ParseOptions{ToolName: "nuclei"})
		if err != nil {
			return tool.Failed(err)
		}
		if res.Error != "" {
			// The run completed with problems (templates that failed):
			// its coverage is partial, as the command executor would say.
			report.Metadata.CoverageType = "partial"
			ctx.Log().Warn("nuclei run completed with errors", "error", res.Error)
		}
		if err := ctx.Emit().Report(report); err != nil {
			if errors.Is(err, tool.ErrOutputLimit) {
				return err
			}
			ctx.Log().Warn("nuclei: a record was refused", "error", err.Error())
		}
	}
	for _, t := range task.Targets {
		ctx.TargetDone(t)
	}
	return nil
}

// ToolContract names nuclei's tool manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return toolrun.Contract(ToolManifest) }
