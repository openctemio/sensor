package toolrun

import (
	"bytes"
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
)

// NormalizeForParity returns a report as stable JSON without the runtime's
// provenance, so the direct path's report and the out-of-process path's
// report of the same scan compare byte for byte (tests). Unlike
// testkit.Normalize it keeps metadata.targets: the direct path writes the
// same per-target outcomes the tool host writes for an out-of-process run.
func NormalizeForParity(raw []byte) ([]byte, error) {
	var r ctis.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return NormalizeReport(&r)
}

// NormalizeReport is NormalizeForParity for a decoded report.
func NormalizeReport(r *ctis.Report) ([]byte, error) {
	cp := *r
	if cp.Metadata.Properties != nil {
		props := ctis.Properties{}
		for k, v := range cp.Metadata.Properties {
			if k != "provenance" {
				props[k] = v
			}
		}
		if len(props) == 0 {
			props = nil
		}
		cp.Metadata.Properties = props
	}
	out, err := testkit.Normalize(&cp)
	if err != nil || len(cp.Metadata.Targets) == 0 {
		return out, err
	}
	d := json.NewDecoder(bytes.NewReader(out))
	d.UseNumber()
	var v map[string]any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	md, _ := v["metadata"].(map[string]any)
	if md == nil {
		md = map[string]any{}
		v["metadata"] = md
	}
	md["targets"] = cp.Metadata.Targets
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
