package toolrun

import (
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// TakeReportOOB reads and removes the out-of-band state a tool child put in
// its report's properties (core.MetaOOB). Only a registration failure is
// taken: a child can say its callbacks did not work, never turn them on.
func TakeReportOOB(r *ctis.Report) *core.OOBState {
	if r == nil || r.Properties == nil {
		return nil
	}
	v, ok := r.Properties[core.MetaOOB]
	if !ok {
		return nil
	}
	delete(r.Properties, core.MetaOOB)
	if len(r.Properties) == 0 {
		r.Properties = nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var st core.OOBState
	if json.Unmarshal(raw, &st) != nil || st.Reason != core.OOBReasonRegistration {
		return nil
	}
	return core.OOBOffState(core.OOBReasonRegistration)
}
