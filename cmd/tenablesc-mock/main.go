// Command tenablesc-mock serves the Tenable.sc API mock
// (internal/connector/tenablesc/scmock) over HTTPS for scratch end-to-end runs
// of the connector: a sensor with a connector config pointing at it can sync
// and run scans without a real Tenable.sc. It is a test tool, never shipped in
// the sensor image.
//
//	tenablesc-mock -listen 172.18.0.5:8443 -host sc.mock.test -estate estate.json -ca-out /shared/sc-ca.pem
//
// The estate file is scmock.Options as JSON. The API keys come from the
// environment (SCMOCK_ACCESS_KEY, SCMOCK_SECRET_KEY). The certificate is
// self-signed for -host and the listen address, written to -ca-out for the
// connector's ca_file.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/openctemio/sensor/internal/connector/tenablesc/scmock"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "address to listen on")
	host := flag.String("host", "sc.mock.test", "DNS name in the certificate")
	estate := flag.String("estate", "", "scmock.Options as JSON (hosts, repositories, policies, zones, licensed IPs)")
	caOut := flag.String("ca-out", "", "write the certificate (PEM) here for the connector's ca_file")
	flag.Parse()

	var o scmock.Options
	if *estate != "" {
		b, err := os.ReadFile(*estate)
		if err != nil {
			log.Fatalf("estate: %v", err)
		}
		if err := json.Unmarshal(b, &o); err != nil {
			log.Fatalf("estate: %v", err)
		}
	}
	o.AccessKey, o.SecretKey = os.Getenv("SCMOCK_ACCESS_KEY"), os.Getenv("SCMOCK_SECRET_KEY")
	if o.AccessKey == "" || o.SecretKey == "" {
		log.Fatal("SCMOCK_ACCESS_KEY and SCMOCK_SECRET_KEY are required")
	}

	cert, certPEM, err := selfSigned(*host, *listen)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	if *caOut != "" {
		if err := os.WriteFile(*caOut, certPEM, 0o644); err != nil { //nolint:gosec // a public certificate
			log.Fatalf("ca-out: %v", err)
		}
	}
	m := scmock.New(o)
	m.Log = func(s string) { log.Print(s) }
	srv := &http.Server{
		Addr: *listen, Handler: m.Handler(), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	log.Printf("tenablesc-mock on https://%s (%d hosts, licence %d)", *listen, len(o.Hosts), o.LicensedIPs)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func selfSigned(host, listen string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	if h, _, err := net.SplitHostPort(listen); err == nil {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("key pair: %w", err)
	}
	return cert, certPEM, nil
}
