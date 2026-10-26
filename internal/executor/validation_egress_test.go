package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	"github.com/openctemio/sensor/internal/toolrun"
)

// fakePool is the job's pool: it records every address it is asked to dial
// and answers with err, or with a connection that is open.
type fakePool struct {
	dials []string
	err   error
}

func (f *fakePool) Dial(_ context.Context, _, addr string) (net.Conn, error) {
	f.dials = append(f.dials, addr)
	if f.err != nil {
		return nil, f.err
	}
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func pooledValidate(t *testing.T, kind, addr string) *core.Command {
	t.Helper()
	p := validateJobPayload{FindingID: "f-1", ExecutorKind: kind, TimeoutSeconds: 2, TemplateID: "t-1",
		Egress: &upstream.Config{Mode: upstream.ModePool, PoolID: "pool-1", AppliesTo: upstream.AppliesAll,
			Endpoints: []upstream.Endpoint{{ID: "e1", Scheme: upstream.SchemeHTTP, Host: "10.0.0.5", Port: 3128, Weight: 1}}}}
	p.Target.Address = addr
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: "cmd-1", Type: "validate", Payload: payload}
}

func executorWithPool(f *fakePool, prepared *int) *ValidatingCommandExecutor {
	e := NewValidatingCommandExecutor(&stubExecutor{}, false)
	e.prepare = func(_ context.Context, id string, cfg *upstream.Config) (core.EgressDialer, error) {
		*prepared++
		if cfg.PoolID != "pool-1" || id != "cmd-1" {
			return nil, errors.New("wrong pool or command")
		}
		return f, nil
	}
	return e
}

// A pooled validate job's probe leaves through the pool, at the address the
// policy checked, and a connection through it is the verdict.
func TestValidateSafeCheckProbesThroughThePool(t *testing.T) {
	f := &fakePool{}
	var prepared int
	res, err := executorWithPool(f, &prepared).Execute(context.Background(), pooledValidate(t, "safe-check", "192.0.2.1:8443"))
	if err != nil {
		t.Fatal(err)
	}
	if prepared != 1 || len(f.dials) != 1 || f.dials[0] != "192.0.2.1:8443" {
		t.Fatalf("prepared %d dials %v", prepared, f.dials)
	}
	// Only the pool could have answered (nothing listens there).
	if res.Metadata["outcome"] != "detected" {
		t.Fatalf("outcome %v", res.Metadata["outcome"])
	}
}

// SECURITY: a pool that cannot carry the probe is no answer about the
// target: never "fixed" (not_detected), never a direct retry.
func TestValidateThroughAPoolNeverReadsAProxyFailureAsFixed(t *testing.T) {
	for name, perr := range map[string]error{
		"proxy down":                     &egress.UpstreamError{Class: egress.ClassProxyDown, Final: true, Err: errors.New("down")},
		"proxy auth":                     &egress.UpstreamError{Class: egress.ClassProxyAuth, Final: true, Err: errors.New("auth")},
		"refused by the proxy's ruleset": &egress.UpstreamError{Class: egress.ClassTargetRefused, Final: true, Err: errors.New("403")},
		"no route (a proxy cannot tell)": &egress.UpstreamError{Class: egress.ClassTargetUnreachable, TargetClass: reach.NoRoute, Final: true, Err: errors.New("502")},
	} {
		f := &fakePool{err: perr}
		var prepared int
		res, err := executorWithPool(f, &prepared).Execute(context.Background(), pooledValidate(t, "safe-check", "192.0.2.1:8443"))
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Metadata["outcome"]; got != "inconclusive" {
			t.Errorf("%s: outcome %v, want inconclusive", name, got)
		}
		if len(f.dials) != 1 {
			t.Errorf("%s: dials %v", name, f.dials)
		}
	}
	// The proxy says the port is closed: that is an answer about the target.
	f := &fakePool{err: &egress.UpstreamError{Class: egress.ClassTargetUnreachable, TargetClass: reach.PortClosed, Final: true, Err: errors.New("refused")}}
	var prepared int
	res, err := executorWithPool(f, &prepared).Execute(context.Background(), pooledValidate(t, "safe-check", "192.0.2.1:8443"))
	if err != nil || res.Metadata["outcome"] != "not_detected" {
		t.Fatalf("closed port through the proxy: %v %v", res, err)
	}
}

// SECURITY: a pooled job that cannot get its pool (the sensor's veto, an
// empty pool, no credentials) fails before any probe; a sensor with no way
// to prepare one refuses the job. Neither probes from the sensor's address.
func TestValidateWithAnUnusablePoolFailsClosed(t *testing.T) {
	f := &fakePool{}
	e := NewValidatingCommandExecutor(&stubExecutor{}, false)
	e.prepare = func(context.Context, string, *upstream.Config) (core.EgressDialer, error) {
		return nil, errors.New("proxy pool pool-1 has no usable endpoint; the job does not run direct")
	}
	if _, err := e.Execute(context.Background(), pooledValidate(t, "safe-check", "192.0.2.1:8443")); err == nil {
		t.Fatal("an unusable pool must fail the job")
	}
	if len(f.dials) != 0 {
		t.Fatal("probed")
	}

	e = NewValidatingCommandExecutor(&stubExecutor{}, false)
	_, err := e.Execute(context.Background(), pooledValidate(t, "safe-check", "192.0.2.1:8443"))
	if r := core.RefusalOf(err); r == nil || r.Rule != core.RefusalEgressUnavailable {
		t.Fatalf("no way to prepare a pool: %v", err)
	}
}

// The local policy decides before the pool is prepared: a denied target
// costs no credential fetch.
func TestValidatePreparesThePoolOnlyForAnAdmittedTarget(t *testing.T) {
	f := &fakePool{}
	var prepared int
	_, err := executorWithPool(f, &prepared).Execute(context.Background(), pooledValidate(t, "safe-check", "169.254.169.254"))
	if err == nil || prepared != 0 || len(f.dials) != 0 {
		t.Fatalf("err %v prepared %d dials %v", err, prepared, f.dials)
	}
}

// The nuclei re-verification runs through the tool host's forwarder; where
// tools run in this process it would go direct, so a pooled one is refused.
func TestValidateNucleiThroughAPoolNeedsOutOfProcessTools(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "in-process")
	f := &fakePool{}
	var prepared int
	_, err := executorWithPool(f, &prepared).Execute(context.Background(), pooledValidate(t, nucleiExecutorKind, "192.0.2.1:8443"))
	if r := core.RefusalOf(err); r == nil || r.Rule != core.RefusalEgressUnavailable {
		t.Fatalf("err %v", err)
	}
	if len(f.dials) != 0 {
		t.Fatal("probed")
	}
}
