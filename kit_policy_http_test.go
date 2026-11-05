package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
)

// The daemon's tool admission policy is kitPolicy, not *core.LocalPolicy:
// the tool host reads http.allow_insecure_tls, http.user_agent,
// http.headers and rate.max_rps by type assertion on it, so the adapter
// must pass each of them on, or the owner's settings are silently ignored.
// Each value may only narrow what the job asks for (owner rule: local
// policy follows the platform, narrow-only); unset keeps the behaviour of
// a sensor without a policy.
func TestKitPolicyPassesHTTPAndRateSettings(t *testing.T) {
	const v1 = "apiVersion: openctem.io/sensor-policy/v1\n"
	type rateCase struct{ requested, want int }
	for _, tc := range []struct {
		name         string
		doc          string // "" no policy file
		wantUA       string
		wantInsecure bool
		wantHeaders  []core.LocalHTTPHeader
		rates        []rateCase
	}{
		{
			name: "no policy keeps every value as the job asks", wantInsecure: true,
			rates: []rateCase{{0, 0}, {50, 50}, {5000, 5000}},
		},
		{
			name: "policy without http or rate keeps every value", doc: v1 + "tools:\n  allow: [nuclei]\n", wantInsecure: true,
			rates: []rateCase{{0, 0}, {50, 50}},
		},
		{
			name: "allow_insecure_tls false forbids skipping verification", doc: v1 + "http:\n  allow_insecure_tls: false\n",
			wantInsecure: false, rates: []rateCase{{50, 50}},
		},
		{
			// true is the default: it adds nothing the job did not allow
			// (the tool host checks the organization's refusal apart).
			name: "allow_insecure_tls true is the same as unset", doc: v1 + "http:\n  allow_insecure_tls: true\n",
			wantInsecure: true, rates: []rateCase{{50, 50}},
		},
		{
			name:   "user agent and headers reach the tool host",
			doc:    v1 + "http:\n  user_agent: dc1-scan\n  headers:\n    - {name: X-Netops, value: dc1}\n",
			wantUA: "dc1-scan", wantInsecure: true,
			wantHeaders: []core.LocalHTTPHeader{{Name: "X-Netops", Value: "dc1"}},
			rates:       []rateCase{{50, 50}},
		},
		{
			// A job asking above the maximum is lowered, one below it is
			// kept (never raised), one asking nothing runs at the maximum.
			name: "max_rps only lowers", doc: v1 + "rate:\n  max_rps: 20\n", wantInsecure: true,
			rates: []rateCase{{500, 20}, {21, 20}, {20, 20}, {5, 5}, {1, 1}, {0, 20}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lp *core.LocalPolicy
			if tc.doc != "" {
				lp = loadPolicy(t, tc.doc)
			}
			var pol toolhost.Policy = kitPolicy{current: func() *core.LocalPolicy { return lp }}

			hp, ok := pol.(toolhost.HTTPPolicy)
			if !ok {
				t.Fatal("kitPolicy is not a toolhost.HTTPPolicy: http.user_agent and http.allow_insecure_tls are ignored")
			}
			ua, insecure := hp.HTTPPolicy()
			if ua != tc.wantUA || insecure != tc.wantInsecure {
				t.Errorf("HTTPPolicy() = %q, %v; want %q, %v", ua, insecure, tc.wantUA, tc.wantInsecure)
			}

			hh, ok := pol.(toolhost.HTTPHeaderPolicy)
			if !ok {
				t.Fatal("kitPolicy is not a toolhost.HTTPHeaderPolicy: http.headers are ignored")
			}
			got := hh.HTTPHeaders()
			if len(got) != len(tc.wantHeaders) {
				t.Fatalf("HTTPHeaders() = %+v, want %+v", got, tc.wantHeaders)
			}
			for i := range got {
				if got[i] != tc.wantHeaders[i] {
					t.Errorf("HTTPHeaders()[%d] = %+v, want %+v", i, got[i], tc.wantHeaders[i])
				}
			}

			rp, ok := pol.(toolhost.RatePolicy)
			if !ok {
				t.Fatal("kitPolicy is not a toolhost.RatePolicy: rate.max_rps is ignored")
			}
			for _, r := range tc.rates {
				if g := rp.CapRate(r.requested); g != r.want {
					t.Errorf("CapRate(%d) = %d, want %d", r.requested, g, r.want)
				}
				if r.requested > 0 && rp.CapRate(r.requested) > r.requested {
					t.Errorf("CapRate(%d) raised the job's rate", r.requested)
				}
			}
		})
	}
}

// SECURITY: the owner's headers can never carry credentials or steer the
// connection: a policy naming one is refused when it loads, so nothing
// reaches the adapter.
func TestKitPolicyHeadersRefuseCredentialAndConnectionNames(t *testing.T) {
	for _, name := range []string{"Authorization", "cookie", "Proxy-Authorization", "Host", "Connection", "Transfer-Encoding"} {
		doc := "apiVersion: openctem.io/sensor-policy/v1\nhttp:\n  headers:\n    - {name: " + name + ", value: x}\n"
		if _, err := core.ParseLocalPolicy([]byte(doc), core.LocalPolicyOptions{LookupEnv: func(string) (string, bool) { return "", false }}); err == nil {
			t.Errorf("a local policy setting %s loaded", name)
		}
	}
}

// A SIGHUP reload is seen at the next task: the adapter reads the policy in
// force, not the one it was built with.
func TestKitPolicyHTTPFollowsReload(t *testing.T) {
	current := loadPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\n")
	var pol toolhost.Policy = kitPolicy{current: func() *core.LocalPolicy { return current }}
	hp, okHTTP := pol.(toolhost.HTTPPolicy)
	rp, okRate := pol.(toolhost.RatePolicy)
	if !okHTTP || !okRate {
		t.Fatal("kitPolicy does not pass http or rate settings to the tool host")
	}
	if _, insecure := hp.HTTPPolicy(); !insecure || rp.CapRate(100) != 100 {
		t.Fatal("an empty policy narrowed the job")
	}
	current = loadPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nhttp:\n  allow_insecure_tls: false\nrate:\n  max_rps: 10\n")
	if _, insecure := hp.HTTPPolicy(); insecure {
		t.Error("the reloaded allow_insecure_tls: false is not applied")
	}
	if got := rp.CapRate(100); got != 10 {
		t.Errorf("the reloaded max_rps is not applied: CapRate(100) = %d", got)
	}
}
