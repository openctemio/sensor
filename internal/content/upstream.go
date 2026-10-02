package content

import "github.com/openctemio/sdk-go/pkg/httpsec"

// upstreamHosts are the content hosts this package hard-codes (the default
// nuclei-templates and semgrep sources, and the hosts GitHub redirects
// archive and release downloads to). On a network whose only way out is an
// egress proxy, the host often cannot resolve public names; registering them
// lets the proxy resolve them (api RFC-034 G2). Any other name that does not
// resolve locally is still refused, so a configured or platform-supplied URL
// never skips the address check.
var upstreamHosts = []string{
	"api.github.com",
	"github.com",
	"codeload.github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
	"semgrep.dev",
}

func init() { httpsec.TrustUpstreamHosts(upstreamHosts...) }
