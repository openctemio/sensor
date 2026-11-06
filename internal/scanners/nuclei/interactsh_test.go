package nuclei

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/egressenv"
)

func withServer(s *Scanner, token string) *Scanner {
	s.OOB = OOBConfig{Host: "oob.example.test", Token: token}
	return s
}

// SECURITY (privacy): nuclei never runs out-of-band callbacks without the
// operator's own server: with no server it would use the public oast.*
// servers. Every combination without one gives -ni.
func TestBuildArgsOOBNeedsTheOperatorsServer(t *testing.T) {
	t.Setenv(egressenv.EnvProxy, "")
	ask := &core.ScanOptions{AllowInteractsh: true}
	cases := []struct {
		name    string
		scanner func() *Scanner
		opts    *core.ScanOptions
		wantOn  bool
	}{
		{name: "default scanner, nil opts", scanner: NewScanner, opts: nil},
		{name: "default scanner, empty opts", scanner: NewScanner, opts: &core.ScanOptions{}},
		{name: "DAST preset stays off", scanner: NewDAST, opts: &core.ScanOptions{}},
		{name: "the job asks, no server: off (never the public servers)", scanner: NewScanner, opts: ask},
		{name: "a server, the job does not ask", scanner: func() *Scanner { return withServer(NewScanner(), "") }, opts: &core.ScanOptions{}},
		{name: "a server and the job asks", scanner: func() *Scanner { return withServer(NewScanner(), "") }, opts: ask, wantOn: true},
		{name: "NoInteractsh beats everything", scanner: func() *Scanner {
			s := withServer(NewScanner(), "")
			s.NoInteractsh = true
			return s
		}, opts: ask},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.scanner()
			args := s.buildArgs("https://example.com", tc.opts)
			if got := s.InteractshEnabled(tc.opts); got != tc.wantOn {
				t.Errorf("InteractshEnabled = %v, want %v", got, tc.wantOn)
			}
			if slices.Contains(args, "-ni") == tc.wantOn {
				t.Errorf("-ni present=%v with callbacks on=%v: %v", slices.Contains(args, "-ni"), tc.wantOn, args)
			}
			if slices.Contains(args, "-iserver") != tc.wantOn {
				t.Errorf("-iserver present=%v, want %v: %v", slices.Contains(args, "-iserver"), tc.wantOn, args)
			}
			if slices.Contains(args, "-itoken") || slices.Contains(args, "-pi") {
				t.Errorf("token or -pi on an unconfined run: %v", args)
			}
			if tc.wantOn && argAfter(args, "-iserver") != "https://oob.example.test" {
				t.Errorf("unconfined server %q", argAfter(args, "-iserver"))
			}
		})
	}
	// The multi-target (list) path builds the same way.
	if args := NewScanner().buildArgsFor("", "/tmp/targets.txt", ask, passOwn); !slices.Contains(args, "-ni") {
		t.Errorf("list scan without -ni: %v", args)
	}
}

// A confined run talks plain HTTP to the server through its forwarder
// (-pi), which adds the token; the timing flags that keep late hits are
// always set.
func TestBuildArgsOOBConfined(t *testing.T) {
	t.Setenv(egressenv.EnvProxy, "http://127.0.0.1:1080")
	s := withServer(NewScanner(), "")
	args := s.buildArgs("https://example.com", &core.ScanOptions{AllowInteractsh: true})
	if argAfter(args, "-iserver") != "http://oob.example.test" || !slices.Contains(args, "-pi") || slices.Contains(args, "-ni") {
		t.Fatalf("confined args %v", args)
	}
	for flag, want := range map[string]string{
		"-interactions-eviction": "900", "-interactions-cooldown-period": "60",
		"-interactions-cache-size": "50000", "-interactions-poll-duration": "5",
	} {
		if got := argAfter(args, flag); got != want {
			t.Errorf("%s = %q, want %s", flag, got, want)
		}
	}
}

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// What a scan does with the callbacks its job asked for, and the reason
// when it runs without them (it never fails for it).
func TestPlanOOB(t *testing.T) {
	ask := &core.ScanOptions{AllowInteractsh: true}
	cases := []struct {
		name       string
		scanner    *Scanner
		opts       *core.ScanOptions
		confined   bool
		wantOn     bool
		wantReason string
		wantNil    bool
	}{
		{name: "not asked", scanner: withServer(NewScanner(), "t"), opts: &core.ScanOptions{}, wantNil: true},
		{name: "nil opts", scanner: withServer(NewScanner(), "t"), opts: nil, wantNil: true},
		{name: "policy turned them off", scanner: withServer(NewScanner(), ""), opts: &core.ScanOptions{OOBOffReason: core.OOBReasonLocalPolicy}, wantReason: core.OOBReasonLocalPolicy},
		{name: "no server", scanner: NewScanner(), opts: ask, wantReason: core.OOBReasonNoServer},
		{name: "operator turned them off", scanner: func() *Scanner { s := withServer(NewScanner(), ""); s.NoInteractsh = true; return s }(), opts: ask, wantReason: core.OOBReasonDisabled},
		{name: "token on an unconfined sensor", scanner: withServer(NewScanner(), "t"), opts: ask, wantReason: core.OOBReasonUnconfined},
		{name: "token on a confined sensor", scanner: withServer(NewScanner(), "t"), opts: ask, confined: true, wantOn: true},
		{name: "no token, unconfined", scanner: withServer(NewScanner(), ""), opts: ask, wantOn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.scanner.planOOB(tc.opts, tc.confined)
			if tc.wantNil {
				if p.on || p.state != nil {
					t.Fatalf("plan %+v", p)
				}
				return
			}
			if p.on != tc.wantOn || p.state == nil {
				t.Fatalf("plan %+v", p)
			}
			if tc.wantOn {
				if p.state.State != core.OOBOn || tc.scanner.oobServer(p) == nil {
					t.Fatalf("on: %+v", p.state)
				}
			} else if p.state.State != core.OOBUnavailable || p.state.Reason != tc.wantReason || p.state.Detail == "" || tc.scanner.oobServer(p) != nil {
				t.Fatalf("off: %+v", p.state)
			}
			got := withOOB(tc.opts, p)
			if got.AllowInteractsh != p.on {
				t.Fatalf("opts not set to the plan: %+v", got)
			}
			if tc.opts.AllowInteractsh && !p.on && !tc.opts.AllowInteractsh {
				t.Fatal("the caller's options were modified")
			}
		})
	}
	// The forwarder's server carries the operator's settings.
	s := withServer(NewScanner(), "tok")
	s.OOB.AllowPrivate = true
	srv := s.oobServer(oobPlan{on: true})
	if srv.Host != "oob.example.test" || srv.Authorization != "tok" || !srv.PrivateOK {
		t.Fatalf("server %+v", srv)
	}
}

func TestFinishOOB(t *testing.T) {
	on := oobPlan{on: true, state: &core.OOBState{State: core.OOBOn}}
	res := &core.ScanResult{OOB: core.OOBOffState(core.OOBReasonRegistration)}
	finishOOB(res, on)
	if res.OOB.State != core.OOBUnavailable || res.OOB.Reason != core.OOBReasonRegistration {
		t.Fatalf("registration failure lost: %+v", res.OOB)
	}
	res = &core.ScanResult{}
	finishOOB(res, on)
	if res.OOB == nil || res.OOB.State != core.OOBOn {
		t.Fatalf("on: %+v", res.OOB)
	}
	// A run that was not asked for callbacks reports none, whatever it says.
	res = &core.ScanResult{OOB: core.OOBOffState(core.OOBReasonRegistration)}
	finishOOB(res, oobPlan{})
	if res.OOB != nil {
		t.Fatalf("not asked: %+v", res.OOB)
	}
	finishOOB(nil, on)
	if !registrationFailed("[ERR] Could not create interactsh client: could not register to servers") || registrationFailed("[INF] Using Interactsh Server: oob.example.test") {
		t.Fatal("registration failure detection")
	}
}

func TestOOBFromEnv(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	c, err := OOBFromEnv(env(nil))
	if err != nil || c.Configured() {
		t.Fatalf("unset: %+v %v", c, err)
	}
	c, err = OOBFromEnv(env(map[string]string{EnvOOBServer: "https://OOB.Example.Test/", EnvOOBToken: " tok ", EnvOOBAllowPrivate: "true", EnvOOBCAFile: ca}))
	if err != nil || c.Host != "oob.example.test" || c.Token != "tok" || !c.AllowPrivate || c.RootCAs == nil {
		t.Fatalf("full: %+v %v", c, err)
	}
	if c, err = OOBFromEnv(env(map[string]string{EnvOOBServer: "oob.example.test"})); err != nil || c.Host != "oob.example.test" {
		t.Fatalf("bare name: %+v %v", c, err)
	}
	for name, m := range map[string]map[string]string{
		"cleartext":           {EnvOOBServer: "http://oob.example.test"},
		"port":                {EnvOOBServer: "https://oob.example.test:8443"},
		"path":                {EnvOOBServer: "https://oob.example.test/x"},
		"query":               {EnvOOBServer: "https://oob.example.test?x=1"},
		"user info":           {EnvOOBServer: "https://u:p@oob.example.test"},
		"address":             {EnvOOBServer: "https://203.0.113.5"},
		"single label":        {EnvOOBServer: "localhost"},
		"bad name":            {EnvOOBServer: "oob_bad.example.test"},
		"several servers":     {EnvOOBServer: "a.example.test,b.example.test"},
		"token without one":   {EnvOOBToken: "tok"},
		"private without one": {EnvOOBAllowPrivate: "true"},
		"bad bool":            {EnvOOBServer: "oob.example.test", EnvOOBAllowPrivate: "maybe"},
		"missing CA":          {EnvOOBServer: "oob.example.test", EnvOOBCAFile: filepath.Join(t.TempDir(), "none.pem")},
		"token line break":    {EnvOOBServer: "oob.example.test", EnvOOBToken: "a\nb"},
	} {
		if _, err := OOBFromEnv(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The token and the CA never travel to the tool child.
	c = OOBConfig{Host: "oob.example.test", Token: "tok-secret", AllowPrivate: true}
	s := NewScanner()
	s.OOB = c
	b, err := json.Marshal(nucleiLocal{Scanner: s})
	raw := string(b)
	if err != nil || strings.Contains(raw, "tok-secret") || !strings.Contains(raw, "oob.example.test") {
		t.Fatalf("child configuration %s %v", raw, err)
	}
}
