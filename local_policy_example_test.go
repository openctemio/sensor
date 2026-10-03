package main

import (
	"context"
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// The template shipped for the install dialog is a valid policy (with the
// private-range switch on, as its comments say) and keeps the risky switches
// off.
func TestLocalPolicyExample(t *testing.T) {
	data, err := os.ReadFile("docs/sensor-policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	lp, err := core.ParseLocalPolicy(data, core.LocalPolicyOptions{
		LookupEnv: func(k string) (string, bool) { return "1", k == core.EnvSensorAllowPrivateTargets },
	})
	if err != nil {
		t.Fatalf("the example policy does not load: %v", err)
	}
	if lp.AllowsCustomTemplates() || lp.AllowsInteractsh() {
		t.Fatal("the example must keep custom templates and interactsh off")
	}
	r := lp.Report()
	if r.State != core.LocalPolicyStateEnforced || r.Summary.TargetsAllow != 4 || !r.Summary.AllowPrivate || r.Summary.MaxRPS == 0 {
		t.Fatalf("summary %+v", r.Summary)
	}
	if err := lp.CheckTarget(context.Background(), "10.20.5.1"); err == nil {
		t.Fatal("the example's denied range is allowed")
	}
	// Without the switch the policy only narrows: it loads with a warning
	// and private targets stay refused.
	off, err := core.ParseLocalPolicy(data, core.LocalPolicyOptions{LookupEnv: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Warnings()) == 0 || off.CheckTarget(context.Background(), "10.20.1.1") == nil {
		t.Fatal("private range without SENSOR_ALLOW_PRIVATE_TARGETS must stay refused, with a warning")
	}
}
