// Package tlstest has TLS test servers for the sensor's probe tests: a
// host that completes the handshake and resets the request, one that
// answers, and a closed port.
package tlstest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// Server modes.
const (
	Reset  = iota // handshake, then reset on the request
	Answer        // handshake, then an HTTP answer
)

// Cert is a self-signed certificate for cn, valid in [from, to).
func Cert(t testing.TB, cn string, from, to time.Time) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}, NotBefore: from, NotAfter: to}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// Serve listens on localhost in mode and returns "localhost:<port>".
func Serve(t testing.TB, mode int, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck // test server
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				tc := tls.Server(c, cfg)
				if tc.Handshake() != nil {
					return
				}
				if _, err := bufio.NewReader(tc).ReadString('\n'); err != nil {
					return
				}
				if mode == Reset {
					_ = c.(*net.TCPConn).SetLinger(0)
					return
				}
				_, _ = io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}(c)
		}
	}()
	return "localhost:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

// ClosedPort returns "127.0.0.1:<port>" where nothing listens.
func ClosedPort(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// Direct dials directly.
var Direct = (&net.Dialer{Timeout: 2 * time.Second}).DialContext

// Offline never connects and says nothing about the host.
func Offline(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("offline test dialer")
}
