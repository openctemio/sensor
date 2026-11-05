package nuclei

// Out-of-band (OOB) callbacks. A template that needs one (tag "oast") makes
// its target call back to an interaction server, which shows a blind effect
// (SSRF, XXE, a JNDI lookup). nuclei, left alone, uses public interaction
// servers (oast.*), which would see every target name and request that
// calls back. The sensor never does that:
//
//   - callbacks run only when the job asks for them (allow_interactsh), the
//     local policy does not turn them off, and the sensor's operator
//     configured an interaction server (SENSOR_OOB_SERVER); every other run
//     passes -ni;
//   - in a confined task nuclei talks plain HTTP to http://<server> through
//     the task's forwarder (-pi), which carries only the interaction API to
//     that one server over verified TLS and adds the token itself
//     (sdk-go egress.OOBServer): the token is never in nuclei's arguments,
//     environment or task configuration;
//   - a sensor that does not confine the tool's network reaches the server
//     directly (https), and only when the server needs no token: a token
//     would otherwise sit on nuclei's command line;
//   - a scan that cannot use callbacks runs without them and its result says
//     why (core.OOBState, result metadata "oob"); it never fails for it.

import (
	"crypto/x509"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sensor/internal/egressenv"
)

// Environment variables of the operator's interaction server.
const (
	// EnvOOBServer is the server: https://<name> or <name>. The name is
	// also the zone of the callback payloads, so it takes no port or path.
	EnvOOBServer = "SENSOR_OOB_SERVER"
	// EnvOOBToken is the server's token (sent by the task's forwarder).
	EnvOOBToken = "SENSOR_OOB_TOKEN"
	// EnvOOBAllowPrivate lets the server resolve to private addresses (a
	// server inside the operator's network).
	EnvOOBAllowPrivate = "SENSOR_OOB_ALLOW_PRIVATE"
	// EnvOOBCAFile is a PEM file of the roots that verify the server
	// (default: the system roots).
	EnvOOBCAFile = "SENSOR_OOB_CA_FILE"
)

// Callback timing nuclei runs with when callbacks are on. nuclei's own
// defaults drop real hits: a callback more than 60 s after its request is
// evicted, one more than 5 s after the last request is lost at exit, and a
// 5000-entry cache evicts requests of a large run before their callbacks
// arrive.
const (
	OOBEvictionSeconds = 900
	OOBCooldownSeconds = 60
	OOBCacheSize       = 50000
	OOBPollSeconds     = 5
)

// OOBConfig is the operator's interaction server. Only Host travels to the
// tool child; the token, the private-address switch and the roots stay in
// the sensor process (the task's forwarder uses them).
type OOBConfig struct {
	Host         string         `json:"host,omitempty"`
	Token        string         `json:"-"`
	AllowPrivate bool           `json:"-"`
	RootCAs      *x509.CertPool `json:"-"`
}

// Configured reports whether the operator configured a server.
func (c OOBConfig) Configured() bool { return c.Host != "" }

// OOBFromEnv reads the operator's interaction server. An invalid value is an
// error: the sensor must not start with another server than the one its
// operator meant, or with callbacks that silently never work.
func OOBFromEnv(lookup func(string) (string, bool)) (OOBConfig, error) {
	get := func(k string) string {
		v, _ := lookup(k)
		return strings.TrimSpace(v)
	}
	var c OOBConfig
	raw := get(EnvOOBServer)
	if raw == "" {
		for _, k := range []string{EnvOOBToken, EnvOOBAllowPrivate, EnvOOBCAFile} {
			if get(k) != "" {
				return OOBConfig{}, fmt.Errorf("%s is set without %s", k, EnvOOBServer)
			}
		}
		return c, nil
	}
	host, err := parseOOBServer(raw)
	if err != nil {
		return OOBConfig{}, fmt.Errorf("%s: %w", EnvOOBServer, err)
	}
	c.Host = host
	c.Token = get(EnvOOBToken)
	if strings.ContainsAny(c.Token, "\r\n") {
		return OOBConfig{}, fmt.Errorf("%s contains a line break", EnvOOBToken)
	}
	if v := get(EnvOOBAllowPrivate); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return OOBConfig{}, fmt.Errorf("%s: %q is not true or false", EnvOOBAllowPrivate, v)
		}
		c.AllowPrivate = b
	}
	if f := get(EnvOOBCAFile); f != "" {
		pem, err := os.ReadFile(f) //nolint:gosec // the operator's own CA file
		if err != nil {
			return OOBConfig{}, fmt.Errorf("%s: %w", EnvOOBCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return OOBConfig{}, fmt.Errorf("%s: no PEM certificate in %s", EnvOOBCAFile, f)
		}
		c.RootCAs = pool
	}
	return c, nil
}

// parseOOBServer returns the host name of an interaction server value.
func parseOOBServer(raw string) (string, error) {
	v := raw
	if !strings.Contains(v, "://") {
		v = "https://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("%q is not a server name or https URL", raw)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("%q: only https (the token and the polled interactions must not travel in clear)", raw)
	case u.User != nil, u.Port() != "", strings.Trim(u.Path, "/") != "", u.RawQuery != "", u.Fragment != "":
		return "", fmt.Errorf("%q: give the server's name only (it is also the callback zone: no port, path or query)", raw)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if _, err := netip.ParseAddr(host); err == nil {
		return "", fmt.Errorf("%q: an address cannot be a callback zone; give the server's DNS name", raw)
	}
	if !validZone(host) {
		return "", fmt.Errorf("%q is not a valid DNS name", raw)
	}
	return host, nil
}

// validZone reports whether h is a DNS name of at least two labels.
func validZone(h string) bool {
	labels := strings.Split(h, ".")
	if len(h) > 253 || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// oobPlan is what a scan does with the callbacks its job asked for.
type oobPlan struct {
	// on: the run uses them.
	on bool
	// state is reported with the result (nil: the job did not ask).
	state *core.OOBState
}

// planOOB decides a scan's callbacks. confined says the run goes through a
// task forwarder (out of process, network confined).
func (s *Scanner) planOOB(opts *core.ScanOptions, confined bool) oobPlan {
	if opts == nil || (!opts.AllowInteractsh && opts.OOBOffReason == "") {
		return oobPlan{}
	}
	off := func(reason string) oobPlan { return oobPlan{state: core.OOBOffState(reason)} }
	switch {
	case opts.OOBOffReason != "":
		return off(opts.OOBOffReason)
	case s.NoInteractsh:
		return off(core.OOBReasonDisabled)
	case !s.OOB.Configured():
		return off(core.OOBReasonNoServer)
	case !confined && s.OOB.Token != "":
		return off(core.OOBReasonUnconfined)
	}
	return oobPlan{on: true, state: &core.OOBState{State: core.OOBOn}}
}

// withOOB returns opts with callbacks set to the plan (a copy when it
// changes them).
func withOOB(opts *core.ScanOptions, p oobPlan) *core.ScanOptions {
	if opts == nil || opts.AllowInteractsh == p.on {
		return opts
	}
	cp := *opts
	cp.AllowInteractsh = p.on
	return &cp
}

// oobServer is the task forwarder's interaction server for a planned run
// (nil: none).
func (s *Scanner) oobServer(p oobPlan) *egress.OOBServer {
	if !p.on {
		return nil
	}
	return &egress.OOBServer{Host: s.OOB.Host, Authorization: s.OOB.Token, PrivateOK: s.OOB.AllowPrivate, RootCAs: s.OOB.RootCAs}
}

// finishOOB sets the result's out-of-band state from the plan and what the
// run saw (a registration failure reported by the run).
func finishOOB(res *core.ScanResult, p oobPlan) {
	if res == nil {
		return
	}
	ran := res.OOB
	res.OOB = p.state
	if p.on && ran != nil && ran.Reason == core.OOBReasonRegistration {
		res.OOB = core.OOBOffState(core.OOBReasonRegistration)
	}
}

// oobArgs are a run's interactsh flags: -ni unless callbacks are on.
func (s *Scanner) oobArgs(opts *core.ScanOptions) []string {
	if !s.InteractshEnabled(opts) {
		return []string{"-ni"}
	}
	timing := []string{
		"-interactions-eviction", strconv.Itoa(OOBEvictionSeconds),
		"-interactions-cooldown-period", strconv.Itoa(OOBCooldownSeconds),
		"-interactions-cache-size", strconv.Itoa(OOBCacheSize),
		"-interactions-poll-duration", strconv.Itoa(OOBPollSeconds),
	}
	if egressenv.Confined() {
		// Through the forwarder, which opens the TLS connection and adds
		// the token: nuclei sends its interaction requests to its proxy
		// only with -pi.
		return append([]string{"-iserver", "http://" + s.OOB.Host, "-pi"}, timing...)
	}
	return append([]string{"-iserver", "https://" + s.OOB.Host}, timing...)
}

// registrationFailed reports whether a run's stderr says nuclei could not
// register with its interaction server (it then runs on without callbacks).
func registrationFailed(stderr string) bool {
	return strings.Contains(stderr, "Could not create interactsh client")
}

// reportOOB puts a run's registration failure in the child's report
// (toolrun.Run reads it back as ScanResult.OOB, toolrun.TakeReportOOB).
func reportOOB(r *ctis.Report, st *core.OOBState) {
	if r == nil || st == nil {
		return
	}
	if r.Properties == nil {
		r.Properties = map[string]any{}
	}
	r.Properties[core.MetaOOB] = map[string]any{"state": st.State, "reason": st.Reason}
}
