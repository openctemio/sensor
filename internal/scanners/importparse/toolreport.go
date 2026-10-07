package importparse

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/assetctx"
)

// IsToolReport reports whether data is a CTIS report the tool runtime
// assembled for the named tool (the out-of-process path's raw output): it
// is already converted, checked and stamped, so it is read as it is.
func IsToolReport(data []byte, tool string) bool {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return false
	}
	var probe struct {
		Version  string `json:"version"`
		Metadata *struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"metadata"`
		Tool *struct {
			Name string `json:"name"`
		} `json:"tool"`
	}
	if json.Unmarshal(data, &probe) != nil || probe.Version == "" || probe.Metadata == nil || probe.Tool == nil {
		return false
	}
	_, stamped := probe.Metadata.Properties["provenance"]
	return probe.Tool.Name == tool && stamped
}

// readToolReport reads a report the tool runtime assembled, filing findings
// without an asset on the scan target the caller names, and refusing
// findings with no asset at all.
func readToolReport(data []byte, opts *core.ParseOptions, tool string) (*ctis.Report, error) {
	var report ctis.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("read %s report: %w", tool, err)
	}
	if opts != nil && opts.AssetValue != "" {
		targetID := ""
		for i := range report.Findings {
			if report.Findings[i].AssetRef != "" {
				continue
			}
			if targetID == "" {
				t := opts.AssetType
				if t == "" {
					t, _ = assetctx.HostAsset(opts.AssetValue)
				}
				if t == "" {
					t = ctis.AssetTypeDomain
				}
				targetID = fmt.Sprintf("asset-%d", len(report.Assets))
				report.Assets = append(report.Assets, ctis.Asset{ID: targetID, Type: t, Value: opts.AssetValue,
					Name: opts.AssetValue, Properties: ctis.Properties{"source": "parse_options"}})
			}
			report.Findings[i].AssetRef = targetID
		}
	}
	if err := ctis.CheckFindingAssets(&report); err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	return &report, nil
}
