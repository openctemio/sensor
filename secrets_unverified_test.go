package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/contract/secretref"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sensor/internal/reachprobe"
)

// A job whose proxy pool needs credentials, on a sensor that verified no
// job signature (no job signer pinned: the sensor bound its own key over a
// plain-http platform URL, or the hello could not be read), is refused
// before it starts with rule secrets_unverified and the fix, not later with
// "the job's signed secret list names none" for the pool: the secret list
// was there, the sensor only may not use it from an unverified job.
func TestUnverifiedJobNeedingPoolCredentialsIsRefusedSecretsUnverified(t *testing.T) {
	httpsec.AllowLoopback = true
	t.Cleanup(func() { httpsec.AllowLoopback = false })
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetManifest(true)
	t.Cleanup(f.Close)

	set := secretref.Set{V: secretref.Version, Local: secretref.LocalAllow, Refs: []secretref.Ref{{
		ID: "p1", Kind: secretref.KindEgressProxy, Class: secretref.ClassOf(secretref.KindEgressProxy),
		Ref: "pool-a", Audience: []string{secretref.AudiencePool}, Consumer: secretref.ConsumerForwarder,
		Required: true, Local: secretref.LocalNever,
	}}}
	if err := set.Validate(); err != nil {
		t.Fatalf("test secret list: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"scanner": reachprobe.Name, "targets": []string{"198.51.100.7"},
		secretref.PayloadField: set,
	})
	if err != nil {
		t.Fatal(err)
	}
	const id = "0192a3b4-0000-7000-8000-0000000000b1"
	f.QueueCommandPayload(id, "scan", payload) // unsigned: nothing verifies it
	d := &refusingDial{}
	stop := startProbeSensor(t, conformance.SensorEndpoint{URL: f.URL(), APIKey: f.APIKey}, d)
	t.Cleanup(stop)

	deadline := time.Now().Add(30 * time.Second)
	var state, detail string
	for time.Now().Before(deadline) {
		if state, detail = f.CommandState(id); state != "" && state != "pending" && state != "claimed" && state != "running" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if state == "completed" {
		t.Fatalf("an unverified job that requires pool credentials ran: %s", f.CommandResult(id))
	}
	all := detail + " " + string(f.CommandResult(id))
	if !strings.Contains(all, core.RefusalRuleSecretsUnverified) {
		t.Fatalf("command ended %q (%s), want refused with %s", state, all, core.RefusalRuleSecretsUnverified)
	}
	if strings.Contains(all, "names none") {
		t.Fatalf("the refusal blames the secret list instead of the unverified job: %s", all)
	}
	if !strings.Contains(all, "SENSOR_JOB_SIGNING_ROOT") {
		t.Errorf("the refusal does not name the fix: %s", all)
	}
	if len(d.addrs()) != 0 {
		t.Fatalf("the refused job dialed %v", d.addrs())
	}
}
