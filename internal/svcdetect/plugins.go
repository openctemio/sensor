package svcdetect

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	// The audited plugins, and only those. Never import nerva's pkg/scan
	// (it imports every plugin) or any other plugin package: importing a
	// package registers its plugins, and the allow-list test fails on a
	// plugin it does not know.
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/ftp"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/imap"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/memcached"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/mongodb"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/mssql"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/mysql"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/pop3"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/rdp"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/redis"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/rsync"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/smtp"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/telnet"
	_ "github.com/praetorian-inc/nerva/pkg/plugins/services/vnc"
)

// The audit of nerva v1.84.0 (source read, research 441 §1.3 in the openctem
// repository). A plugin is allowed only when its Run, with Misconfigs and
// Deep false:
//   - uses only the connection it is given (no net.Dial, no TLS or HTTP
//     client of its own, no use of Target.DialTCP);
//   - sends no credential, user name, bind, login or authentication message
//     and no command that changes state;
//   - sends no HTTP (HTTP goes through our own probe, with the job's
//     identification).
//
//	plugin (type/name)  sends (Misconfigs false)                        why it is safe
//	TCP/ftp             nothing (reads the greeting)                    read only
//	TCP/smtp            EHLO example.com                                greeting; the relay test (MAIL/RCPT) is Misconfigs only
//	TCPTLS/smtps        EHLO example.com over TLS                       same, over our TLS handshake
//	TCP/pop3            one unknown command line                        provokes -ERR; no USER/PASS
//	TCPTLS/pop3s        the same over TLS                               same
//	TCP/imap            "<tag> CAPABILITY"                              pre-auth capability listing; no LOGIN
//	TCPTLS/imaps        the same over TLS                               same
//	TCP/telnet          nothing (reads the option negotiation)          read only; no login prompt answered
//	TCP/MySQL           nothing (reads the server greeting)             the anonymous login is Misconfigs only
//	TCP/mssql           TDS PRELOGIN (version, encryption options)      pre-login, no LOGIN7 (blank sa login is Misconfigs only)
//	TCP/mongodb         hello / isMaster / buildInfo                    unauthenticated handshake commands; listDatabases is Misconfigs only
//	TCP/redis           PING, then INFO SERVER only when PING needs no  read-only commands; never AUTH
//	                    password
//	TCPTLS/redis        the same over TLS                               same
//	TCP/memcached       "version", then "stats" if needed               read-only commands
//	TCP/VNC             nothing (reads the RFB version)                 read only; no security type chosen
//	TCP/rsync           an "@RSYNCD:" greeting line                     protocol greeting; no module listed or opened
//	TCP/rdp             X.224 Connection Request                        connection negotiation only
//
// Excluded (never imported): ssh (password and keyboard-interactive login,
// own socket), clickhouse (Hello as default with an empty password), smpp
// (bind test/test), ldap (bind with a random DN and password), snmp
// (community "public"), postgresql (startup message as user postgres: a
// login on a trust-auth server), kerberos (AS-REQ, own socket), amqp
// (guest/guest, own socket), smb, nrpe, http and every fingerprinter (own
// sockets and clients), the oracle*, weblogic, webcenter, peoplesoft,
// glassfish, sonarqube, qdrant, milvus and librechat product plugins (own
// HTTP clients, login pages), every UDP and SCTP plugin (no UDP route through
// the task's forwarder), and the rest not yet audited (industrial and
// telecom protocols are never probed at tier 1).
//
// Registered by an allowed package but never run:
//	TCPTLS/rdp  CredSSP with an NTLM NEGOTIATE message: an authentication
//	            protocol exchange, so not run.
//
// A nerva upgrade changes the digests pinned in plugins_test.go and fails
// until the changed files are audited again.

// pluginKey names a nerva plugin.
type pluginKey struct {
	Proto plugins.Protocol
	Name  string
}

func (k pluginKey) String() string { return k.Proto.String() + "/" + k.Name }

// allowedPlugin is one audited plugin.
type allowedPlugin struct {
	key pluginKey
	// talksFirst: the plugin starts by reading what the server sends
	// first, so it is tried only on a server that did.
	talksFirst bool
	// anonymous, when set, reads from the plugin's metadata whether the
	// handshake itself proved access without credentials.
	anonymous func(meta map[string]any) bool
}

// allowList is the audit's result (see the table above).
var allowList = []allowedPlugin{
	{key: pluginKey{plugins.TCP, "ftp"}, talksFirst: true},
	{key: pluginKey{plugins.TCP, "smtp"}, talksFirst: true},
	{key: pluginKey{plugins.TCPTLS, "smtps"}, talksFirst: true},
	{key: pluginKey{plugins.TCP, "pop3"}, talksFirst: true},
	{key: pluginKey{plugins.TCPTLS, "pop3s"}, talksFirst: true},
	{key: pluginKey{plugins.TCP, "imap"}, talksFirst: true},
	{key: pluginKey{plugins.TCPTLS, "imaps"}, talksFirst: true},
	{key: pluginKey{plugins.TCP, "telnet"}, talksFirst: true},
	{key: pluginKey{plugins.TCP, "MySQL"}, talksFirst: true},
	{key: pluginKey{plugins.TCP, "VNC"}, talksFirst: true},
	{key: pluginKey{plugins.TCP, "rsync"}, talksFirst: true},
	{key: pluginKey{plugins.TCP, "mssql"}},
	{key: pluginKey{plugins.TCP, "mongodb"}},
	// Redis answered PING with PONG, not NOAUTH: commands run without a
	// password (no AUTH was sent).
	{key: pluginKey{plugins.TCP, "redis"}, anonymous: redisAnonymous},
	{key: pluginKey{plugins.TCPTLS, "redis"}, anonymous: redisAnonymous},
	{key: pluginKey{plugins.TCP, "memcached"}},
	{key: pluginKey{plugins.TCP, "rdp"}},
}

// registeredUnused are plugins an allowed package registers that the tool
// never runs.
var registeredUnused = []pluginKey{{plugins.TCPTLS, "rdp"}}

func redisAnonymous(meta map[string]any) bool {
	v, ok := meta["auth_required"].(bool)
	return ok && !v
}

// errNoDial is what a plugin gets when it asks for a connection of its own.
var errNoDial = errors.New("svcdetect: plugins get no connections of their own")

// nervaProbes are the allowed plugins as probes, built once from nerva's
// registry. A listed plugin missing from the registry is a programming
// error (the allow-list test catches it first).
var nervaProbes = buildNervaProbes()

func buildNervaProbes() []*probe {
	var out []*probe
	for _, a := range allowList {
		var found plugins.Plugin
		for _, p := range plugins.Plugins[a.key.Proto] {
			if p.Name() == a.key.Name {
				found = p
				break
			}
		}
		if found == nil {
			panic("svcdetect: allowed plugin " + a.key.String() + " is not registered")
		}
		out = append(out, nervaProbe(found, a))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].priority < out[j].priority })
	return out
}

// nervaProbe adapts an allowed plugin.
func nervaProbe(p plugins.Plugin, a allowedPlugin) *probe {
	return &probe{
		name:       strings.ToLower(p.Name()),
		tls:        a.key.Proto == plugins.TCPTLS,
		talksFirst: a.talksFirst,
		priority:   p.Priority(),
		portHint:   func(port uint16) bool { return p.PortPriority(port) },
		run: func(c net.Conn, timeout time.Duration, t *target) (res *result, err error) {
			defer func() {
				// A plugin that panics on a malformed answer is a non-match.
				if r := recover(); r != nil {
					res, err = nil, fmt.Errorf("svcdetect: probe %s failed on the answer", a.key)
				}
			}()
			nt := plugins.Target{
				Address: netip.AddrPortFrom(t.addrOrZero(), t.port),
				Host:    t.name(),
				// Never true: the misconfiguration and deep probes log in,
				// relay mail or list data.
				Misconfigs: false,
				Deep:       false,
				DialTCP:    func(string, time.Duration) (net.Conn, error) { return nil, errNoDial },
			}
			svc, err := p.Run(c, timeout, nt)
			if err != nil || svc == nil {
				return nil, err
			}
			return fromNerva(svc, a), nil
		},
	}
}

// fromNerva maps a plugin's service to a result. Security findings are
// never taken (Misconfigs is off, and the tool reports no findings).
func fromNerva(svc *plugins.Service, a allowedPlugin) *result {
	r := &result{protocol: strings.ToLower(a.key.Name), version: cleanText(svc.Version, maxVersion)}
	var meta map[string]any
	if len(svc.Raw) > 0 && len(svc.Raw) <= maxConnRead {
		_ = json.Unmarshal(svc.Raw, &meta)
	}
	if cpes, ok := meta["cpes"].([]any); ok {
		for _, c := range cpes {
			if s, ok := c.(string); ok {
				if cpe, product := usableCPE(s); product != "" {
					r.cpe, r.product = cpe, product
					break
				}
			}
		}
	}
	if b, ok := meta["banner"].(string); ok {
		r.banner = cleanText(b, MaxBanner)
	}
	r.details = detailsFrom(meta, "banner", "cpes", "confidence")
	if a.anonymous != nil && meta != nil {
		r.anonymous = a.anonymous(meta)
	}
	return r
}
