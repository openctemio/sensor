package main

// Outbound-only invariant (api RFC-040 §11.1, docs/rfcs/RFC-040-platform-
// sensor-mutual-distrust.md in openctemio/openctem): a sensor never accepts
// inbound connections; all control flows over the connection the sensor
// opens to the platform. These tests fail the build when the sensor binary
// gains a way to listen on the network.

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type listPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Standard   bool
	Module     *struct{ Path string }
}

// sensorPackages lists the packages linked into the sensor binary.
func sensorPackages(t *testing.T) []listPackage {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-json", ".")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []listPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listPackage
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode go list: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// Packages whose mere import serves something over HTTP.
var forbiddenImports = []string{
	"net/http/pprof",
	"github.com/prometheus/client_golang/prometheus/promhttp",
}

func TestOutboundOnly_NoServingPackagesLinked(t *testing.T) {
	for _, p := range sensorPackages(t) {
		for _, f := range forbiddenImports {
			if p.ImportPath == f {
				t.Errorf("the sensor binary links %s, which serves over HTTP; sensors are outbound-only", f)
			}
		}
	}
}

// listenFuncs are the package functions that open a listener.
var listenFuncs = map[string]map[string]bool{
	"net":                    {"Listen": true, "ListenPacket": true, "ListenTCP": true, "ListenUDP": true, "ListenIP": true, "ListenMulticastUDP": true, "ListenUnix": true, "ListenUnixgram": true},
	"crypto/tls":             {"Listen": true, "NewListener": true},
	"net/http":               {"ListenAndServe": true, "ListenAndServeTLS": true, "Serve": true, "ServeTLS": true},
	"google.golang.org/grpc": {"NewServer": true},
}

// listenMethods are server methods that listen (http.Server and others).
var listenMethods = map[string]bool{"ListenAndServe": true, "ListenAndServeTLS": true}

// allowedListeners are the listener call sites the sensor may contain, by
// "<import path>.<enclosing function>", each with why it reaches no network.
var allowedListeners = map[string]string{
	// Per-task relays bind 127.0.0.1 inside the task's own network
	// namespace: reachable only by the tool in that namespace.
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor.setupNetwork": "loopback inside a private network namespace",
	// The egress forwarder listens on a Unix socket in the task directory.
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost.(*Host).startEgress": "Unix socket in the task directory",
	// The webhook collector of the SDK can listen, but the sensor never
	// creates one (TestOutboundOnly_NoWebhookCollector): Start is unreachable.
	"github.com/openctemio/sdk-go/pkg/core.(*WebhookCollector).Start": "never constructed by the sensor",
}

// TestOutboundOnly_NoWebhookCollector keeps the webhook collector, the one
// SDK component that listens on the network, out of the sensor.
func TestOutboundOnly_NoWebhookCollector(t *testing.T) {
	for _, p := range sensorPackages(t) {
		if p.Module == nil || p.Module.Path != "github.com/openctemio/sensor" {
			continue
		}
		for _, name := range p.GoFiles {
			src, err := os.ReadFile(filepath.Join(p.Dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(src, []byte("NewWebhookCollector")) {
				t.Errorf("%s creates a webhook collector, which listens for inbound connections; sensors are outbound-only",
					filepath.Join(p.ImportPath, name))
			}
		}
	}
}

// TestOutboundOnly_NoNetworkListeners walks the source of every
// openctemio package linked into the sensor and fails on a call that opens
// a listener, outside the reviewed allow list.
func TestOutboundOnly_NoNetworkListeners(t *testing.T) {
	var found []string
	for _, p := range sensorPackages(t) {
		if p.Standard || p.Module == nil || !strings.HasPrefix(p.Module.Path, "github.com/openctemio/") {
			continue
		}
		for _, name := range p.GoFiles {
			for _, site := range listenerSites(t, filepath.Join(p.Dir, name), p.ImportPath) {
				if _, ok := allowedListeners[site]; !ok {
					found = append(found, site+" ("+filepath.Join(p.ImportPath, name)+")")
				}
			}
		}
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("listener call outside the allow list: %s; sensors are outbound-only (api RFC-040 §11.1)", f)
	}
}

// listenerSites returns "<pkg>.<enclosing func>" for each listener call in
// the file.
func listenerSites(t *testing.T, path, pkg string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	aliases := map[string]string{}
	for _, imp := range f.Imports {
		ip, _ := strconv.Unquote(imp.Path.Value)
		if _, watched := listenFuncs[ip]; !watched {
			continue
		}
		name := filepath.Base(ip)
		if ip == "google.golang.org/grpc" {
			name = "grpc"
		}
		if imp.Name != nil {
			name = imp.Name.Name
		}
		aliases[name] = ip
	}
	var sites []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		encl := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			encl = "(" + recvString(fn.Recv.List[0].Type) + ")." + encl
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				if ip, imported := aliases[id.Name]; imported && listenFuncs[ip][sel.Sel.Name] {
					sites = append(sites, pkg+"."+encl)
					return true
				}
			}
			if listenMethods[sel.Sel.Name] {
				sites = append(sites, pkg+"."+encl)
			}
			return true
		})
	}
	return sites
}

func recvString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return "*" + recvString(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr:
		return recvString(v.X)
	default:
		return "?"
	}
}
