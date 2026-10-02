package content

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// A content tool (trivy's DB download, a template update) follows the
// content proxy, even when scanners are set to direct (api RFC-034).
func TestRun_FollowsContentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://corp-proxy:3128")
	s, err := httpsec.ParseProxySetting("http://content-proxy:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	httpsec.SetContentProxy(s)
	core.SetScannerProxyMode(core.ScannerProxyDirect)
	t.Cleanup(func() {
		httpsec.SetContentProxy(httpsec.ProxySetting{})
		core.SetScannerProxyMode(core.ScannerProxyInherit)
	})

	out, err := run(context.Background(), "env", nil, nil, nil)
	if err != nil {
		t.Skipf("env not available: %v", err)
	}
	if !strings.Contains(string(out), "HTTPS_PROXY=http://content-proxy:8080") || strings.Contains(string(out), "corp-proxy") {
		t.Fatalf("content tool environment:\n%s", out)
	}
}

func TestUpstreamHostsCoverDefaults(t *testing.T) {
	for _, u := range []string{DefaultNucleiLatestURL, DefaultNucleiArchiveURL, DefaultSemgrepRegistry} {
		found := false
		for _, h := range upstreamHosts {
			if strings.Contains(u, "://"+h+"/") || strings.HasSuffix(u, "://"+h) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: host not in upstreamHosts", u)
		}
	}
}
