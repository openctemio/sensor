package lookup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// ErrTargetHost is the error of a request that would reach one of the
// task's own targets: a passive lookup never does.
var ErrTargetHost = errors.New("refused: the host is one of the task's targets")

// ErrNotHTTPS is the error of a request over plain HTTP: registry data that
// lands in an inventory must not be open to tampering on the way.
var ErrNotHTTPS = errors.New("refused: only https sources are used")

// Client fetches public registry data for a task. Every request:
//   - is https;
//   - never goes to a host that is one of the task's targets or under one
//     (a passive step sends nothing to the target hosts, whatever a
//     registry answer links to);
//   - goes through the task's egress forwarder when the sandbox confines
//     the network (public addresses only), else through the SSRF-guarded
//     client (no private, loopback, link-local or metadata address);
//   - re-checks the above on every redirect.
type Client struct {
	http    *http.Client
	names   []string
	addrs   []netip.Prefix
	ua      string
	maxBody int64
}

// NewClient returns the client of a task of the tool named in m, refusing
// the task's targets.
func NewClient(m tool.Manifest, targets []tool.Target, timeout time.Duration) *Client {
	c := &Client{ua: "openctem-sensor-" + m.Name + "/" + m.Version, maxBody: 4 << 20}
	for _, t := range targets {
		v := strings.TrimSpace(t.Value)
		if p, err := netip.ParsePrefix(v); err == nil {
			c.addrs = append(c.addrs, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(v); err == nil {
			c.addrs = append(c.addrs, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		if h := normHost(t.Host()); h != "" {
			c.names = append(c.names, h)
		}
	}
	hc := HTTPClient(timeout)
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := c.allowed(req.URL); err != nil {
			return err
		}
		return httpsec.SafeCheckRedirect(req, via)
	}
	c.http = hc
	return c
}

// HTTPClient is the transport: the SSRF-guarded client, through the task's
// forwarder when there is one. Replaced only by tests (a loopback TLS
// server); NewClient adds its redirect checks either way.
var HTTPClient = func(timeout time.Duration) *http.Client {
	hc := httpsec.SafeHTTPClient(timeout)
	if p := tool.EgressProxy(); p != nil {
		if tr, ok := hc.Transport.(*http.Transport); ok {
			tr = tr.Clone()
			tr.Proxy = http.ProxyURL(p)
			// The forwarder is on loopback: dial it directly; it applies
			// the public-only rule to every destination.
			tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
			hc.Transport = tr
		}
	}
	return hc
}

func normHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]")), ".")
}

// allowed checks one URL against the rules above.
func (c *Client) allowed(u *url.URL) error {
	if u == nil || u.Scheme != "https" {
		return ErrNotHTTPS
	}
	h := normHost(u.Hostname())
	if h == "" {
		return fmt.Errorf("refused: no host in %q", u.Redacted())
	}
	if a, err := netip.ParseAddr(h); err == nil {
		for _, p := range c.addrs {
			if p.Contains(a.Unmap()) {
				return ErrTargetHost
			}
		}
		return nil
	}
	for _, n := range c.names {
		if h == n || strings.HasSuffix(h, "."+n) {
			return ErrTargetHost
		}
	}
	return nil
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Code       int
	RetryAfter time.Duration
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Code) }

// Get fetches rawURL with the Accept header and returns at most the
// client's body limit (a larger body is an error).
func (c *Client) Get(ctx context.Context, rawURL, accept string) ([]byte, error) {
	resp, err := c.open(ctx, rawURL, accept)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > c.maxBody {
		return nil, fmt.Errorf("%s: answer larger than %d bytes", hostOf(rawURL), c.maxBody)
	}
	return b, nil
}

// Open fetches rawURL and returns the open response body (a download the
// caller streams and bounds itself).
func (c *Client) Open(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	resp, err := c.open(ctx, rawURL, "")
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (c *Client) open(ctx context.Context, rawURL, accept string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := c.allowed(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = resp.Body.Close()
		se := &StatusError{Code: resp.StatusCode}
		if s := resp.Header.Get("Retry-After"); s != "" {
			var secs int
			if _, err := fmt.Sscanf(s, "%d", &secs); err == nil && secs > 0 {
				se.RetryAfter = time.Duration(secs) * time.Second
			}
		}
		return nil, se
	}
	return resp, nil
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return "source"
}
