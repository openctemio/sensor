package nuclei

// The job's web scope (sdk-go pkg/webscope) on a nuclei scan. nuclei's
// templates request arbitrary paths, so no flag keeps it inside a scope;
// the task's forwarder does. On a sandbox that confines the network, the
// forwarder is nuclei's only way out and checks every request (TLS
// terminated with its per-task authority, which nuclei does not verify;
// redirects checked as new requests) against the scope, refusing the rest.
// So nuclei takes a web-scoped job only when it runs out of process in
// such a sandbox, and refuses it otherwise (fail closed).
//
// A web-scoped run also:
//   - always uses the forwarder's relay as its proxy, never another one;
//   - runs no template whose protocol the forwarder cannot read as HTTP
//     (they would be refused) or whose result would describe the
//     forwarder instead of the target (ssl: the certificate it sees is the
//     forwarder's);
//   - runs no headless browser.

import (
	"errors"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/egressenv"
	"github.com/openctemio/sensor/internal/toolrun"
)

// webScopeExcludedTypes are the template protocols a web-scoped run
// leaves out (nuclei -exclude-type).
const webScopeExcludedTypes = "ssl,tcp,javascript,websocket,headless,code,whois,file"

// ErrWebScopeUnconfined is the error of a web-scoped job on a sensor
// whose tools do not run confined to the task's forwarder.
var ErrWebScopeUnconfined = errors.New("nuclei keeps to a web scope only in a tool sandbox that confines its network, " +
	"and this sensor's does not (SENSOR_SANDBOX_NETWORK; the container needs the seccomp profile in docker/seccomp); the job has a web scope")

// webScopeEnforced reports whether this sensor runs nuclei confined to
// the task's forwarder (a variable for tests).
var webScopeEnforced = func() bool {
	return toolrun.OutOfProcess() && executor.Current().Status().NetworkEnforced
}

// checkWebScope refuses a web-scoped job this sensor cannot enforce.
func checkWebScope(opts *core.ScanOptions) error {
	if opts != nil && opts.WebScope != nil && !webScopeEnforced() {
		return ErrWebScopeUnconfined
	}
	return nil
}

// webScopeArgs are the flags of a web-scoped run (none otherwise).
func (s *Scanner) webScopeArgs() []string {
	if !s.webScoped {
		return nil
	}
	return []string{"-ept", webScopeExcludedTypes}
}

// proxyArg is the proxy a run uses: the forwarder's relay for a
// web-scoped run, else the operator's proxy or the relay.
func (s *Scanner) proxyArg() string {
	if s.webScoped {
		return egressenv.Proxy()
	}
	if s.Proxy != "" {
		return s.Proxy
	}
	return egressenv.Proxy()
}

// applyTaskWebScope sets opts.WebScoped from the task (the tool child's
// view, never the configuration's) and refuses a web-scoped task that does
// not run confined to its forwarder: without it nuclei would run
// unrestricted.
func applyTaskWebScope(opts *ValidateOptions, task tool.Task) error {
	opts.WebScoped = task.WebScope != nil
	if opts.WebScoped && !egressenv.Confined() {
		return tool.Refused(ErrWebScopeUnconfined.Error())
	}
	return nil
}

// WebScopeEnforced reports whether this sensor can run a web-scoped nuclei
// job (out of process, confined to the task's forwarder).
func WebScopeEnforced() bool { return webScopeEnforced() }
