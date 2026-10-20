package nuclei

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// fakeForwarder answers every HTTP CONNECT with status and records the
// destinations asked for.
func fakeForwarder(t *testing.T, status int) (addr string, asked chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	asked = make(chan string, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				asked <- req.Host
				_, _ = c.Write([]byte("HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status) + "\r\n\r\n"))
			}()
		}
	}()
	return l.Addr().String(), asked
}

// On a sensor that confines the tool's network the reachability check goes
// through the task's forwarder: a target with no direct route (here a
// documentation address) is reachable when the forwarder connects it, and a
// forwarder refusal is reported as such, never as the target being down.
func TestReachableUsesTheForwarderWhenConfined(t *testing.T) {
	target := tool.Target{Ref: "t1", Value: "http://198.51.100.7:8080"}

	addr, asked := fakeForwarder(t, 200)
	t.Setenv(tool.EnvEgressProxy, "http://"+addr)
	if err := reachable(context.Background(), target); err != nil {
		t.Fatalf("reachable through the forwarder: %v", err)
	}
	if got := <-asked; got != "198.51.100.7:8080" {
		t.Fatalf("the forwarder was asked for %q", got)
	}

	addr, _ = fakeForwarder(t, 403)
	t.Setenv(tool.EnvEgressProxy, "http://"+addr)
	err := reachable(context.Background(), target)
	if !errors.Is(err, tool.ErrEgressRefused) {
		t.Fatalf("a refused target = %v, want egress refused", err)
	}
}
