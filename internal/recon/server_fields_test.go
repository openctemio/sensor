package recon

import (
	"slices"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// The scan's rate limit reaches every recon tool's options (the tools turn
// it into -rl / -rate). It used to be dropped: every run went at the tool's
// default rate whatever the command or the sensor policy said.
func TestScanTargets_RateLimitReachesTheTool(t *testing.T) {
	for _, tool := range Tools {
		f := &optsRecon{fakeRecon: fakeRecon{name: tool, typ: core.ReconTypeDNS}}
		s := NewScanner(f)
		s.Options.Resolvers = []string{"192.0.2.53"}
		if _, err := s.ScanTargets(t.Context(), []string{"a.example.com", "b.example.com"}, &core.ScanOptions{RateLimit: 7}); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		for _, o := range f.opts {
			if o.RateLimit != 7 {
				t.Errorf("%s: rate limit %d, want 7", tool, o.RateLimit)
			}
		}
		// No limit asked: the tool keeps its own.
		f = &optsRecon{fakeRecon: fakeRecon{name: tool, typ: core.ReconTypeDNS}}
		s = NewScanner(f)
		s.Options.Resolvers = []string{"192.0.2.53"}
		if _, err := s.ScanTargets(t.Context(), []string{"a.example.com"}, &core.ScanOptions{}); err != nil || f.opts[0].RateLimit != 0 {
			t.Errorf("%s: rate limit %d without a request, want 0 (tool default) err %v", tool, f.opts[0].RateLimit, err)
		}
	}
}

// What httpx learned about the server reaches the CTIS report: a
// certificate asset linked from the service, and the favicon, JARM and CDN.
func TestScanTargets_ProbeKeepsServerFields(t *testing.T) {
	const fp = "85ca6ab068e9bcce88b6c4aa3c47f7d17228134a457f870d3800e6223a0df07a"
	f := &fakeRecon{name: "httpx", typ: core.ReconTypeHTTPProbe, results: map[string]*core.ReconResult{
		"example.com": {LiveHosts: []core.LiveHost{{
			URL: "https://example.com", Host: "example.com", Scheme: "https", Port: 443, StatusCode: 200,
			CDN: "cloudflare", CDNType: "waf", FaviconMMH3: "-1840324437",
			JARM: "27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
			ASN:  &core.ASN{Number: "AS13335", Org: "CLOUDFLARENET", Country: "US"},
			TLS: &core.TLSLeaf{
				SubjectCN: "example.com", SANs: []string{"example.com", "*.example.com"}, IssuerCN: "Cloudflare TLS Issuing ECC CA 3",
				NotBefore: time.Date(2026, 9, 26, 22, 49, 11, 0, time.UTC), NotAfter: time.Date(2026, 12, 25, 22, 56, 35, 0, time.UTC),
				FingerprintSHA256: fp, Wildcard: true,
			},
		}}},
	}}
	res, err := NewScanner(f).Scan(t.Context(), "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	r := parse(t, res.RawOutput)
	var svc, cert *ctis.Asset
	for i := range r.Assets {
		switch r.Assets[i].Type {
		case ctis.AssetTypeHTTPService:
			svc = &r.Assets[i]
		case ctis.AssetTypeCertificate:
			cert = &r.Assets[i]
		}
	}
	if svc == nil || cert == nil {
		t.Fatalf("want an http_service and a certificate: %s", res.RawOutput)
	}
	if cert.Value != fp || cert.Technical == nil || cert.Technical.Certificate == nil || cert.Technical.Certificate.NotAfter == nil {
		t.Fatalf("certificate = %+v", cert)
	}
	if !slices.Contains(svc.RelatedAssets, cert.ID) {
		t.Errorf("service does not link its certificate: %v", svc.RelatedAssets)
	}
	for k, want := range map[string]any{"favicon_mmh3": "-1840324437", "cdn_type": "waf", "hosted_by": "cloudflare", "asn": "AS13335"} {
		if svc.Properties[k] != want {
			t.Errorf("service %s = %v, want %v", k, svc.Properties[k], want)
		}
	}
}
