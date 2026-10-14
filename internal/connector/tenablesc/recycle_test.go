package tenablesc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sensor/internal/connector/tenablesc/scmock"
)

// Licence rotation by recycling the rotation repository: only the one
// repository the owner named is deleted and recreated, with the
// administrator keys, and only when the batch asks for it.

const (
	testAdminAccess = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testAdminSecret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func recycleEstate(t *testing.T, licensed int, name string) (*scmock.Server, *ScanExecutor) {
	t.Helper()
	mock, e, _ := newMockEstateWith(t, licensed, func(o *scmock.Options) {
		o.AdminAccessKey, o.AdminSecretKey = testAdminAccess, testAdminSecret
		o.Repositories = []scmock.Named{{ID: 5, Name: "openctem-rotation"}, {ID: 7, Name: "Other team"}}
	}, func(in *Instance) {
		in.Allow.Operations[OperationRecycle] = true
		in.Allow.ScanRepositories = []int{5, 7}
		in.Recycle = &Recycle{RepositoryName: name, AdminAccessKey: Secret{testAdminAccess}, AdminSecretKey: Secret{testAdminSecret}}
	})
	return mock, e
}

func rotationPayload(id string, recycle bool, targets ...string) map[string]any {
	p := mockPayload(id, targets...)
	p["repository_id"] = 0
	p["rotation_repository"] = true
	p["recycle_repository"] = recycle
	p["licence_guard"] = map[string]any{"new_addresses": 4, "headroom": 0}
	return p
}

func run(t *testing.T, e *ScanExecutor, id string, p map[string]any) (map[string]any, error) {
	t.Helper()
	cmd := scanCmd(t, p)
	cmd.ID = id
	res, err := e.Execute(context.Background(), cmd)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

func TestRecycle_FreesTheLicenceForTheNextBatch(t *testing.T) {
	mock, e := recycleEstate(t, 5, "openctem-rotation")
	// Another team's data in repository 7 (one licensed host) is never touched.
	other := mockPayload("0", "10.30.1.1")
	other["repository_id"] = 7
	if _, err := run(t, e, "cmd-other", other); err != nil {
		t.Fatal(err)
	}
	md, err := run(t, e, "cmd-b1", rotationPayload("1", false, "10.30.0.0/30"))
	if err != nil {
		t.Fatal(err)
	}
	if md["repository_id"] != 5 || mock.ActiveIPs() != 3 {
		t.Fatalf("batch 1: repository %v active %d", md["repository_id"], mock.ActiveIPs())
	}
	// Batch 2 needs 4 with 2 free: without recycling the guard refuses.
	if _, err := run(t, e, "cmd-b2a", rotationPayload("2", false, "10.30.1.0/30")); !errors.Is(err, ErrLicenceCapacity) {
		t.Fatalf("without recycle: %v", err)
	}
	// With recycling the rotation repository is emptied first.
	md, err = run(t, e, "cmd-b2", rotationPayload("2", true, "10.30.0.0/30"))
	if err != nil {
		t.Fatal(err)
	}
	if md["recycled_repository_id"] != "5" || md["repository_id"] == 5 || md["rotation_repository"] != true {
		t.Fatalf("batch 2 metadata %v", md)
	}
	// Repository 7's host still counts; the rotation repository holds batch 2 only.
	if mock.ActiveIPs() != 3 {
		t.Fatalf("active %d, want 1 (other team) + 2 (batch 2)", mock.ActiveIPs())
	}
}

func TestRecycle_Refusals(t *testing.T) {
	t.Run("rotation without a recycle block", func(t *testing.T) {
		_, e, _ := newMockEstate(t, 10)
		if _, err := run(t, e, "c", rotationPayload("1", true, "10.30.0.1")); !errors.Is(err, ErrRefused) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("recycle without rotation", func(t *testing.T) {
		_, e := recycleEstate(t, 10, "openctem-rotation")
		p := mockPayload("1", "10.30.0.1")
		p["recycle_repository"] = true
		if _, err := run(t, e, "c", p); !errors.Is(err, ErrRefused) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("named repository missing: nothing deleted", func(t *testing.T) {
		_, e := recycleEstate(t, 10, "openctem-missing")
		if _, err := run(t, e, "c0", rotationPayload("0", false, "10.30.0.1")); err == nil {
			t.Fatal("scanned into a repository that does not exist")
		}
		if _, err := run(t, e, "c1", rotationPayload("1", true, "10.30.0.1")); err == nil || !strings.Contains(err.Error(), "no repository is named") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("user keys cannot recycle", func(t *testing.T) {
		_, e := recycleEstate(t, 10, "openctem-rotation")
		e.Config.Instances[0].Recycle.AdminAccessKey = Secret{testAccessKey}
		e.Config.Instances[0].Recycle.AdminSecretKey = Secret{testSecretKey}
		if _, err := run(t, e, "c", rotationPayload("1", true, "10.30.0.1")); !errors.Is(err, ErrForbidden) {
			t.Fatalf("err %v, want the 403 of a non-administrator", err)
		}
	})
}

func TestRecycleConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ak, sk := write("a", testAdminAccess), write("s", testAdminSecret)
	scanAllow := Allow{Operations: map[string]bool{OperationScan: true, OperationRecycle: true}}
	for name, tc := range map[string]struct {
		fr    *fileRecycle
		allow Allow
		ok    bool
	}{
		"valid":                {&fileRecycle{RepositoryName: "openctem-rotation", AdminAccessKeyFile: ak, AdminSecretKeyFile: sk}, scanAllow, true},
		"no block, no op":      {nil, Allow{Operations: map[string]bool{OperationScan: true}}, true},
		"op without block":     {nil, scanAllow, false},
		"block without op":     {&fileRecycle{RepositoryName: "openctem-rotation", AdminAccessKeyFile: ak, AdminSecretKeyFile: sk}, Allow{Operations: map[string]bool{OperationScan: true}}, false},
		"recycle without scan": {&fileRecycle{RepositoryName: "openctem-rotation", AdminAccessKeyFile: ak, AdminSecretKeyFile: sk}, Allow{Operations: map[string]bool{OperationRecycle: true}}, false},
		"name without prefix":  {&fileRecycle{RepositoryName: "Datacenter", AdminAccessKeyFile: ak, AdminSecretKeyFile: sk}, scanAllow, false},
		"prefix only":          {&fileRecycle{RepositoryName: "openctem-", AdminAccessKeyFile: ak, AdminSecretKeyFile: sk}, scanAllow, false},
		"no key files":         {&fileRecycle{RepositoryName: "openctem-rotation"}, scanAllow, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildRecycle(tc.fr, tc.allow)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, ok want %v", err, tc.ok)
			}
		})
	}
	// The administrator keys never appear in an error.
	_, err := buildRecycle(&fileRecycle{RepositoryName: "x"}, scanAllow)
	if err != nil && strings.Contains(fmt.Sprint(err), testAdminSecret) {
		t.Fatal("key in error")
	}
}
