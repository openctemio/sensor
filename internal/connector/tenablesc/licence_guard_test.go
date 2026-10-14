package tenablesc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The licence guard: a coverage batch launches only when Tenable.sc has the
// licence capacity it needs, checked by the sensor against /rest/status at
// launch time, before anything is created.

func guarded(p map[string]any, newAddrs, headroom int) map[string]any {
	p["licence_guard"] = map[string]any{"new_addresses": newAddrs, "headroom": headroom}
	return p
}

func TestLicenceGuard_RefusesBeforeCreatingAnything(t *testing.T) {
	// Fake status: licensed 2048, active 1530 → 518 free.
	_, sim, e, p := newScanFixture(t, done)
	pl := guarded(scanPayload(), 18, 501) // 18 + 501 = 519 > 518
	_, err := e.Execute(context.Background(), scanCmd(t, pl))
	if !errors.Is(err, ErrLicenceCapacity) || !strings.HasPrefix(err.Error(), "tenable.sc scan on") ||
		!strings.Contains(err.Error(), LicenceCapacityCode) || !strings.Contains(err.Error(), "free 518") {
		t.Fatalf("err %v", err)
	}
	if len(sim.created) != 0 || len(sim.launches) != 0 || len(p.reports) != 0 {
		t.Fatalf("created %d launched %v reports %d: nothing may be created", len(sim.created), sim.launches, len(p.reports))
	}
}

func TestLicenceGuard_AllowsWithinCapacity(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, done)
	if _, err := e.Execute(context.Background(), scanCmd(t, guarded(scanPayload(), 18, 500))); err != nil {
		t.Fatal(err)
	}
	if len(sim.created) != 1 {
		t.Fatalf("created %d", len(sim.created))
	}
}

func TestLicenceGuard_NewAddressesBoundedByTheBatch(t *testing.T) {
	// The batch covers 18 addresses: a guard asking for more counts 18.
	_, sim, e, _ := newScanFixture(t, done)
	if _, err := e.Execute(context.Background(), scanCmd(t, guarded(scanPayload(), 100000, 500))); err != nil {
		t.Fatal(err)
	}
	if len(sim.created) != 1 {
		t.Fatal("not launched")
	}
}

func TestLicenceGuard_NegativeRefused(t *testing.T) {
	_, _, e, _ := newScanFixture(t, done)
	if _, err := e.Execute(context.Background(), scanCmd(t, guarded(scanPayload(), -1, 0))); !errors.Is(err, ErrRefused) {
		t.Fatalf("err %v", err)
	}
}

func TestLicenceGuard_ResumedScanIsNotGuarded(t *testing.T) {
	// The scan was launched before a restart: its capacity was checked then.
	_, sim, e, _ := newScanFixture(t, done)
	sim.results = []map[string]any{{"id": "777", "name": "openctem-cmd-scan-1", "status": "Running", "repository": map[string]any{"id": "5"}}}
	sim.defs = []map[string]any{{"id": "42", "name": "openctem-cmd-scan-1"}}
	if _, err := e.Execute(context.Background(), scanCmd(t, guarded(scanPayload(), 18, 100000))); err != nil {
		t.Fatal(err)
	}
}

func TestLicenceGuard_AgainstTheMock(t *testing.T) {
	// Licence 4: the first batch (4 addresses, 2 of them licensed after the
	// import) fits; the second needs 4 with 2 free and is refused by the
	// guard before anything is created.
	mock, e, _ := newMockEstate(t, 4)
	res, err := e.Execute(context.Background(), scanCmd(t, guarded(mockPayload("1", "10.30.0.0/30"), 4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(res.Metadata["active_ips_before"]) != "0" || fmt.Sprint(res.Metadata["active_ips"]) != "2" || mock.ActiveIPs() != 2 {
		t.Fatalf("licence metadata %v", res.Metadata)
	}
	cmd := scanCmd(t, guarded(mockPayload("2", "10.30.1.0/30"), 4, 0))
	cmd.ID = "cmd-scan-2"
	if _, err := e.Execute(context.Background(), cmd); !errors.Is(err, ErrLicenceCapacity) {
		t.Fatalf("err %v, want the guard", err)
	}
}
