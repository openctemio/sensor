package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
)

type pairCall struct {
	called bool
	opts   identity.PairOptions
}

func fakePairDeps(env map[string]string, c *pairCall) pairDeps {
	return pairDeps{
		getenv: func(k string) string { return env[k] },
		pair: func(_ context.Context, o identity.PairOptions) (*identity.Identity, error) {
			c.called, c.opts = true, o
			return &identity.Identity{SensorID: "s-1"}, nil
		},
	}
}

func runPair(t *testing.T, env map[string]string, args ...string) (int, string, *pairCall) {
	t.Helper()
	var out, errw bytes.Buffer
	c := &pairCall{}
	code := runPairCommand(args, &out, &errw, fakePairDeps(env, c))
	return code, out.String() + errw.String(), c
}

func paired(t *testing.T, dir string) *identity.Identity {
	t.Helper()
	st := identity.NewStore(dir)
	sg, err := st.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	id := &identity.Identity{SensorID: "11111111-2222-3333-4444-555555555555", Name: "dmz-01", KeyID: sg.KeyID(), PairedAt: time.Now()}
	if err := st.Save(id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPairCommandForwardAndReverse(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"API_URL": "https://platform.example", "SENSOR_STATE_DIR": dir, "SENSOR_PLATFORM_KEY": "SHA256:abc"}
	code, out, c := runPair(t, env)
	if code != 0 || !c.called || c.opts.Code != "" || c.opts.PlatformKeyPin != "SHA256:abc" || c.opts.Retry || c.opts.NewKey {
		t.Fatalf("forward: code %d %+v\n%s", code, c.opts, out)
	}
	if c.opts.Store.Dir() != filepath.Join(dir, identity.DirName) || c.opts.Host.Product != binName {
		t.Fatalf("store %s host %+v", c.opts.Store.Dir(), c.opts.Host)
	}
	code, _, c = runPair(t, env, "K7QM-4ZTD")
	if code != 0 || c.opts.Code != "K7QM-4ZTD" {
		t.Fatalf("reverse: code %d %+v", code, c.opts)
	}
}

func TestPairCommandRefusals(t *testing.T) {
	dir := t.TempDir()
	if code, out, c := runPair(t, map[string]string{"SENSOR_STATE_DIR": dir}); code != 2 || c.called || !strings.Contains(out, "API_URL") {
		t.Fatalf("no URL: %d %s", code, out)
	}
	env := map[string]string{"API_URL": "https://platform.example", "SENSOR_STATE_DIR": dir}
	if code, out, c := runPair(t, env, "-repair"); code != 2 || c.called {
		t.Fatalf("repair without identity: %d %s", code, out)
	}
	if code, out, c := runPair(t, env, "a", "b"); code != 2 || c.called {
		t.Fatalf("two codes: %d %s", code, out)
	}
	t.Cleanup(func() { httpsec.SetAPIPinnedCA(nil) })
	bad := map[string]string{"API_URL": "https://platform.example", "SENSOR_STATE_DIR": dir, "SENSOR_CA_FINGERPRINT": "zz"}
	if code, out, c := runPair(t, bad); code != 2 || c.called || !strings.Contains(out, "SENSOR_CA_FINGERPRINT") {
		t.Fatalf("bad CA pin: %d %s", code, out)
	}
	ipPin := map[string]string{"API_URL": "https://10.0.0.5:8443", "SENSOR_STATE_DIR": dir,
		"SENSOR_CA_FINGERPRINT": strings.Repeat("ab", 32)}
	if code, out, c := runPair(t, ipPin); code != 2 || c.called || !strings.Contains(out, "IP address") {
		t.Fatalf("IP URL with a pin: %d %s", code, out)
	}
}

func TestPairCommandAlreadyPairedAndRepair(t *testing.T) {
	dir := t.TempDir()
	id := paired(t, dir)
	env := map[string]string{"API_URL": "https://platform.example", "SENSOR_STATE_DIR": dir}
	code, out, c := runPair(t, env)
	if code != 1 || c.called || !strings.Contains(out, "already paired") || !strings.Contains(out, "pair -repair") {
		t.Fatalf("already paired: %d %s", code, out)
	}
	code, out, c = runPair(t, env, "-repair")
	if code != 0 || !c.called || c.opts.RepairSensorID != id.SensorID || !c.opts.NewKey {
		t.Fatalf("repair: %d %+v %s", code, c.opts, out)
	}
}

// RFC-052 D-7: an identity others can read stops the command with the fix.
func TestPairCommandRefusesLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	paired(t, dir)
	key := filepath.Join(dir, identity.DirName, identity.KeyFile)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, c := runPair(t, map[string]string{"API_URL": "https://platform.example", "SENSOR_STATE_DIR": dir}, "-repair")
	if code != 1 || c.called || !strings.Contains(out, "chmod 0600 "+key) {
		t.Fatalf("loose key: %d %s", code, out)
	}
}
