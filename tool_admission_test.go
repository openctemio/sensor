package main

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
)

var _ toolhost.Policy = kitPolicy{}

func loadPolicy(t *testing.T, doc string) *core.LocalPolicy {
	t.Helper()
	lp, err := core.ParseLocalPolicy([]byte(doc), core.LocalPolicyOptions{LookupEnv: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatal(err)
	}
	return lp
}

// The admission policy of the ported tools is the local policy in force at
// each task, and tools.allow may name a tool by the name it is configured
// under ("trivy-fs" runs trivy), as the kit's inventory accepts.
func TestKitPolicyAdmitsByConfiguredName(t *testing.T) {
	lp := loadPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntools:\n  allow: [trivy-fs, httpx]\ntargets:\n  deny: [203.0.113.0/24]\n")
	current := lp
	p := kitPolicy{current: func() *core.LocalPolicy { return current }, aliases: map[string][]string{"trivy": {"trivy-fs"}}}
	if !p.AllowsTool("trivy") || !p.AllowsTool("httpx") {
		t.Fatal("a listed tool or configured name is refused")
	}
	if p.AllowsTool("nuclei") || p.AllowsTool("semgrep") {
		t.Fatal("an unlisted tool is allowed")
	}
	if err := p.CheckTarget(context.Background(), "203.0.113.7"); err == nil {
		t.Fatal("a denied target is admitted")
	}
	// A reload replaces the policy: the next check uses the new one.
	current = loadPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nkill_switch: true\n")
	if !p.KillSwitchEngaged() {
		t.Fatal("the reloaded policy is not the one asked")
	}
	if !p.AllowsTool("nuclei") {
		t.Fatal("the reloaded policy has no tools.allow")
	}
}

// The nuclei re-verification runs nuclei: tools.allow admits it exactly
// when it admits nuclei (by name or by the name nuclei is configured
// under), and refuses it when nuclei is not allowed.
func TestKitPolicyAdmitsReverifyWithNuclei(t *testing.T) {
	for _, tc := range []struct {
		allow   string
		aliases map[string][]string
		want    bool
	}{
		{"[nuclei]", nil, true},
		{"[nuclei-dast]", map[string][]string{"nuclei": {"nuclei-dast"}}, true},
		{"[nuclei-validate]", nil, true},
		{"[httpx]", map[string][]string{"nuclei": {"nuclei-dast"}}, false},
	} {
		lp := loadPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntools:\n  allow: "+tc.allow+"\n")
		p := kitPolicy{current: func() *core.LocalPolicy { return lp }, aliases: withReverifyAliases(tc.aliases)}
		if got := p.AllowsTool(nuclei.ValidateToolManifest.Name); got != tc.want {
			t.Errorf("allow %s: nuclei-validate admitted = %v, want %v", tc.allow, got, tc.want)
		}
	}
}
