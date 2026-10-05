package toolrun

import (
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
)

// NormalizeForParity returns a report as stable JSON without the runtime's
// provenance, so the direct path's report and the out-of-process path's
// report of the same scan compare byte for byte (tests).
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
	return testkit.Normalize(&cp)
}
