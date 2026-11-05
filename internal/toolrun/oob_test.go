package toolrun

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// SECURITY: a tool child can report that its callbacks did not register,
// never that they are on; the property never reaches the platform.
func TestTakeReportOOB(t *testing.T) {
	if TakeReportOOB(nil) != nil || TakeReportOOB(ctis.NewReport()) != nil {
		t.Fatal("state from nothing")
	}
	r := ctis.NewReport()
	r.Properties = map[string]any{core.MetaOOB: map[string]any{"state": "unavailable", "reason": core.OOBReasonRegistration}}
	st := TakeReportOOB(r)
	if st == nil || st.State != core.OOBUnavailable || st.Reason != core.OOBReasonRegistration || st.Detail == "" {
		t.Fatalf("state %+v", st)
	}
	if r.Properties != nil {
		t.Fatalf("property left on the report: %v", r.Properties)
	}
	for _, v := range []any{
		map[string]any{"state": "on"},
		map[string]any{"state": "unavailable", "reason": "no_server"},
		"registration_failed",
	} {
		r := ctis.NewReport()
		r.Properties = map[string]any{core.MetaOOB: v, "other": 1}
		if st := TakeReportOOB(r); st != nil {
			t.Errorf("%v taken as %+v", v, st)
		}
		if _, ok := r.Properties[core.MetaOOB]; ok || r.Properties["other"] != 1 {
			t.Errorf("properties %v", r.Properties)
		}
	}
}
