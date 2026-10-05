package nuclei

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// The single-template re-verification (ValidateSingleTemplate, the
// validate command's nuclei rung) as a tool of the tool contract (sdk-go
// pkg/tool). Each re-verify runs out of process: the sensor re-executes
// itself as "<sensor> __openctem-tool nuclei-validate" in the task sandbox
// and the direct path runs there, with the same safety flags (-etags,
// signed templates only, one template, one target, rate ceiling). The
// outcome comes back as the task's raw output (toolrun.RunRaw) and is read
// by the sensor exactly as the direct path returns it.
//
// The target is the task's only target, never part of the sensor's local
// configuration, so the runtime admits it against the sensor-local policy
// before the child starts; a refused target never reaches nuclei.

// ValidateToolManifest describes the nuclei re-verification tool.
var ValidateToolManifest = tool.Manifest{
	Name:         "nuclei-validate",
	Version:      "1.0.0",
	Description:  "Re-runs one finding's own nuclei detection template against one target (non-destructive classes only) to confirm the exposure still exists.",
	Class:        tool.TargetScan,
	Tier:         tool.T1,
	Capabilities: []string{"validation", "vulnerability_scanning"},
	Consumes:     []string{"domain", "subdomain", "ip_address", "host", "http_service", "website", "web_application", "api", "service", "open_port"},
	Produces:     []string{"finding:vulnerability"},
	Permissions:  tool.Permissions{Network: tool.NetTargets},
	Resources: tool.Resources{
		// The run is clamped to 120s, plus the template listing (30s).
		Timeout:        tool.Duration(5 * time.Minute),
		MaxOutputBytes: 1 << 20,
	},
}

// ValidateTool runs a re-verification in the tool child.
var ValidateTool = toolrun.Register(tool.New(ValidateToolManifest, runValidateTool))

// validateOutOfProcess runs ValidateSingleTemplate in the tool child.
func validateOutOfProcess(ctx context.Context, opts ValidateOptions) (*ValidateResult, error) {
	target := opts.Target
	local := opts
	local.Target = ""
	res, _, err := toolrun.RunRaw(ctx, ValidateTool, []string{target}, local, toolhost.RunOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	var out ValidateResult
	if err := json.Unmarshal(res.RawOutput, &out); err != nil {
		return nil, fmt.Errorf("nuclei-validate: unreadable outcome: %w", err)
	}
	switch out.Outcome {
	case OutcomeDetected, OutcomeNotDetected, OutcomeInconclusive:
	default:
		// A child that returns an outcome the verdict rule does not know
		// must not change a finding.
		return nil, fmt.Errorf("nuclei-validate: unknown outcome %q", out.Outcome)
	}
	return &out, nil
}

// runValidateTool is the re-verification's Run in the tool child.
func runValidateTool(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var opts ValidateOptions
	if err := json.Unmarshal(task.Local, &opts); err != nil {
		return tool.Invalid("nuclei-validate: the sensor's task configuration is missing or unreadable")
	}
	if len(task.Targets) != 1 {
		return tool.Invalid("nuclei-validate: one target per task")
	}
	// The admitted target, never one from the configuration.
	opts.Target = task.Targets[0].Value
	res, err := validateSingleTemplateDirect(ctx, opts)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tool.Invalid("%s", err.Error())
	}
	if res == nil {
		return tool.Failed(errors.New("nuclei-validate: no outcome"))
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return tool.Failed(err)
	}
	return toolrun.EmitRaw(ctx, task, &core.ScanResult{RawOutput: raw})
}
