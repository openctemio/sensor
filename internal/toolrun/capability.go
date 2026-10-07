package toolrun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// A capability job (the platform sends the capability a workflow node
// runs, its standard params and the grant's tier ceiling) reaches a
// compiled-in tool in two steps:
//
//  1. ApplyJob, in the scanner's scan path: the tool's manifest maps the
//     standard params onto its config keys (tool.Manifest.ApplyParams,
//     which refuses a param the tool does not take or a value it does not
//     support), the result is merged into the scan's settings, which the
//     scanner applies as it applies any setting, and a tool above the tier
//     ceiling is refused;
//  2. Run / RunRaw put the capability and the ceiling on the task (from the
//     context ApplyJob returns), so the runtime checks the tier again and
//     the output against the capability's contract, and stamps the
//     capability in the provenance.

type jobKey struct{}

type job struct {
	capability string
	maxTier    tool.Tier
}

// ApplyJob applies a capability job to a scan of the tool m. It returns
// the context the tool must run with and a copy of the options whose
// Settings carry the mapped params. A scan that is not a capability job is
// returned unchanged.
func ApplyJob(ctx context.Context, m tool.Manifest, schema *core.SettingsSchema, opts *core.ScanOptions) (context.Context, *core.ScanOptions, error) {
	if opts == nil || (opts.Capability == "" && len(opts.Params) == 0 && opts.MaxTier == "") {
		return ctx, opts, nil
	}
	o := *opts
	opts = &o
	maxTier := tool.Tier(opts.MaxTier)
	if maxTier != "" && m.MinimumTier().Exceeds(maxTier) {
		return ctx, nil, fmt.Errorf("%s needs tier %s; the job allows at most %s", m.Name, m.MinimumTier(), maxTier)
	}
	mapped, err := m.ApplyParams(tool.Task{Capability: opts.Capability, Params: opts.Params})
	if err != nil {
		return ctx, nil, err
	}
	if len(mapped.Config) > 0 {
		var values map[string]any
		dec := json.NewDecoder(bytes.NewReader(mapped.Config))
		dec.UseNumber()
		if err := dec.Decode(&values); err != nil {
			return ctx, nil, fmt.Errorf("%s: mapped params: %w", m.Name, err)
		}
		settings, err := mergeScanLayer(schema, opts.Settings, values)
		if err != nil {
			return ctx, nil, fmt.Errorf("%s settings: %w", m.Name, err)
		}
		opts.Settings = settings
	}
	return context.WithValue(ctx, jobKey{}, job{capability: opts.Capability, maxTier: maxTier}), opts, nil
}

// TakesJobs reports whether a tool runs capability jobs: it implements at
// least one capability (core.CapabilityScanner).
func TakesJobs(m tool.Manifest) bool { return len(m.Implements) > 0 }

// mergeScanLayer resolves the scan's settings again with the mapped params
// added to the scan layer. A key the scan's config also set to another
// value is an error: neither silently wins.
func mergeScanLayer(schema *core.SettingsSchema, current *core.ToolSettings, mapped map[string]any) (*core.ToolSettings, error) {
	if schema == nil {
		return nil, fmt.Errorf("the tool has no settings to map params onto")
	}
	layer := map[string]any{}
	if current != nil {
		values := current.Values()
		for _, k := range current.Keys() {
			if current.Source(k) == core.SettingSourceScan {
				layer[k] = values[k]
			}
		}
	}
	for k, v := range mapped {
		if old, ok := layer[k]; ok && !sameValue(old, v) {
			return nil, fmt.Errorf("%s is set by the scan and by a standard param to another value", k)
		}
		layer[k] = v
	}
	return schema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: layer})
}

func sameValue(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// withJob puts the context's capability job on a task.
func withJob(ctx context.Context, task tool.Task) tool.Task {
	if j, ok := ctx.Value(jobKey{}).(job); ok {
		task.Capability, task.MaxTier = j.capability, j.maxTier
	}
	return task
}
