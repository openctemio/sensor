package tenablesc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"golang.org/x/time/rate"
)

// Errors a caller can tell apart. None of them carries a credential.
var (
	ErrCredentialsRejected = errors.New("tenable.sc rejected the API keys (401)")
	ErrForbidden           = errors.New("tenable.sc refused the request for this user (403)")
	ErrResponseTooLarge    = errors.New("tenable.sc response is larger than limits.max_response_bytes")
	ErrRedirectRefused     = errors.New("tenable.sc answered with a redirect; redirects are refused (the API keys would follow it)")
	ErrUnsupportedVersion  = errors.New("tenable.sc is older than 5.13, which API key authorization needs")
	ErrBlockedAddress      = errors.New("tenable.sc address is loopback, link-local, metadata, multicast or unspecified")
	ErrTooManyRecords      = errors.New("tenable.sc query has more records than limits.max_records")
)

// APIError is an error envelope (error_code != 0).
type APIError struct {
	Status int
	Code   int64
	Msg    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("tenable.sc error %d (http %d): %s", e.Code, e.Status, e.Msg)
}

// Retry and timeout settings.
const (
	maxAttempts        = 5
	maxRetryAfter      = 60 * time.Second
	baseBackoff        = time.Second
	maxBackoff         = 30 * time.Second
	analysisTimeout    = 120 * time.Second
	defaultReqTimeout  = 30 * time.Second
	maxErrorMsgBytes   = 512
	minVersionMajor    = 5
	minVersionMinor    = 13
	errorBodyReadLimit = 64 << 10
)

// Client talks to one Tenable.sc instance. Paths are constants of this file;
// nothing the platform sends ends up in a URL, header or query.
type Client struct {
	base      *url.URL
	hc        *http.Client
	apiKey    string // the x-apikey header value
	limiter   *rate.Limiter
	maxBody   int64
	sleep     func(ctx context.Context, d time.Duration) error
	jitter    func(d time.Duration) time.Duration
	attempts  int
	reqTimout time.Duration
}

// clientOptions are test seams, unexported on purpose: production code has
// no way to relax the address guard or replace the trust store.
type clientOptions struct {
	blocked func(net.IP) bool
	sleep   func(ctx context.Context, d time.Duration) error
	resolve func(ctx context.Context, host string) ([]net.IPAddr, error)
}

// NewClient builds the client for inst.
func NewClient(inst *Instance) (*Client, error) { return newClient(inst, clientOptions{}) }

func newClient(inst *Instance, o clientOptions) (*Client, error) {
	if inst == nil || inst.URL == nil {
		return nil, errors.New("tenable.sc: no instance")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(inst.CAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(inst.CAPEM) {
			return nil, fmt.Errorf("tenable.sc %s: ca_file holds no usable certificate", inst.Name)
		}
		tlsCfg.RootCAs = pool
	}
	if len(inst.Pins) > 0 {
		pins := inst.Pins
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
				for _, p := range pins {
					if subtle.ConstantTimeCompare(sum[:], p) == 1 {
						return nil
					}
				}
			}
			return errors.New("tenable.sc certificate matches no pin_spki_sha256")
		}
	}
	blocked := o.blocked
	if blocked == nil {
		// Private ranges are allowed (the appliance is internal); loopback,
		// link-local, metadata, CGNAT, multicast and unspecified are not.
		blocked = func(ip net.IP) bool { return httpsec.IsIPBlockedWith(ip, true, false) }
	}
	resolve := o.resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupIPAddr
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolve(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("tenable.sc: %s did not resolve", host)
			}
			for _, ip := range ips {
				if blocked(ip.IP) {
					return nil, fmt.Errorf("%w: %s", ErrBlockedAddress, ip.IP)
				}
			}
			// Dial the address just checked (no DNS rebinding); TLS still
			// verifies the certificate against the configured host name.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: analysisTimeout,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConnsPerHost:   2,
		ForceAttemptHTTP2:     true,
	}
	sleep := o.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	rps := inst.Limits.RequestsPerSecond
	if rps <= 0 {
		rps = defaultRPS
	}
	maxBody := inst.Limits.MaxResponseBytes
	if maxBody <= 0 {
		maxBody = defaultMaxResponseBytes
	}
	return &Client{
		base: inst.URL,
		hc: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrRedirectRefused
			},
		},
		apiKey:    "accesskey=" + inst.AccessKey.Value() + "; secretkey=" + inst.SecretKey.Value() + ";",
		limiter:   rate.NewLimiter(rate.Limit(rps), 1),
		maxBody:   maxBody,
		sleep:     sleep,
		jitter:    func(d time.Duration) time.Duration { return time.Duration(rand.Int64N(int64(d) + 1)) }, //nolint:gosec // backoff jitter, not security
		attempts:  maxAttempts,
		reqTimout: defaultReqTimeout,
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type envelope struct {
	Type      string          `json:"type"`
	Response  json.RawMessage `json:"response"`
	ErrorCode flexInt         `json:"error_code"`
	ErrorMsg  string          `json:"error_msg"`
}

// do sends one API request and decodes the response into out.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, timeout time.Duration, out any) error {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = b
	}
	u := *c.base
	u.Path = c.base.Path + "/rest" + path
	u.RawQuery = query.Encode()
	target := u.String()

	var lastErr error
	for attempt := 0; attempt < c.attempts; attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, c.backoff(attempt, lastErr)); err != nil {
				return err
			}
		}
		if err := c.limiter.Wait(ctx); err != nil {
			return err
		}
		retry, err := c.once(ctx, method, target, payload, timeout, out)
		if err == nil {
			return nil
		}
		if !retry || ctx.Err() != nil {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("tenable.sc: giving up after %d attempts: %w", c.attempts, lastErr)
}

// retryableStatus carries a Retry-After hint.
type retryableStatus struct {
	status     int
	retryAfter time.Duration
}

func (e *retryableStatus) Error() string {
	return fmt.Sprintf("tenable.sc answered http %d", e.status)
}

func (c *Client) backoff(attempt int, last error) time.Duration {
	var rs *retryableStatus
	if errors.As(last, &rs) && rs.retryAfter > 0 {
		return min(rs.retryAfter, maxRetryAfter)
	}
	d := baseBackoff << (attempt - 1)
	if d > maxBackoff || d <= 0 {
		d = maxBackoff
	}
	return c.jitter(d)
}

func (c *Client) once(ctx context.Context, method, target string, payload []byte, timeout time.Duration, out any) (retry bool, err error) {
	if timeout <= 0 {
		timeout = c.reqTimout
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(rctx, method, target, rd)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, ErrRedirectRefused):
			return false, ErrRedirectRefused
		case errors.Is(err, ErrBlockedAddress):
			return false, err
		case ctx.Err() != nil:
			return false, ctx.Err()
		}
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) || strings.Contains(err.Error(), "certificate") {
			return false, fmt.Errorf("tenable.sc TLS verification failed: %w", err)
		}
		return true, fmt.Errorf("tenable.sc request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, errorBodyReadLimit))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return false, ErrRedirectRefused
	case resp.StatusCode == http.StatusUnauthorized:
		return false, ErrCredentialsRejected
	case resp.StatusCode == http.StatusForbidden:
		if msg := c.errorMessage(resp.Body); msg != "" {
			return false, fmt.Errorf("%w: %s", ErrForbidden, msg)
		}
		return false, ErrForbidden
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusGatewayTimeout:
		return true, &retryableStatus{status: resp.StatusCode, retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return false, &APIError{Status: resp.StatusCode, Code: -1, Msg: c.errorMessage(resp.Body)}
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return true, fmt.Errorf("tenable.sc read: %w", err)
	}
	if int64(len(data)) > c.maxBody {
		return false, ErrResponseTooLarge
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return false, fmt.Errorf("tenable.sc returned malformed JSON: %w", err)
	}
	if env.ErrorCode != 0 {
		return false, &APIError{Status: resp.StatusCode, Code: int64(env.ErrorCode), Msg: capMsg(env.ErrorMsg)}
	}
	if out != nil {
		if len(env.Response) == 0 || bytes.Equal(bytes.TrimSpace(env.Response), []byte("null")) {
			return false, errors.New("tenable.sc returned an envelope without a response")
		}
		if err := json.Unmarshal(env.Response, out); err != nil {
			return false, fmt.Errorf("tenable.sc returned an unexpected response: %w", err)
		}
	}
	return false, nil
}

func (c *Client) errorMessage(r io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(r, errorBodyReadLimit))
	var env envelope
	if json.Unmarshal(data, &env) == nil && env.ErrorMsg != "" {
		return capMsg(env.ErrorMsg)
	}
	return ""
}

func capMsg(s string) string { return sanitizeText(s, maxErrorMsgBytes) }

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return min(time.Duration(n)*time.Second, maxRetryAfter)
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return min(d, maxRetryAfter)
		}
	}
	return 0
}

// SystemInfo is what the connector reads from /rest/system.
type SystemInfo struct {
	Version string
}

// System reads the version and refuses versions without API key support.
func (c *Client) System(ctx context.Context) (SystemInfo, error) {
	var r struct {
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/system", url.Values{"fields": {"version"}}, nil, 0, &r); err != nil {
		return SystemInfo{}, err
	}
	v := sanitizeText(r.Version, 64)
	if !versionAtLeast(v, minVersionMajor, minVersionMinor) {
		return SystemInfo{Version: v}, fmt.Errorf("%w (reported %q)", ErrUnsupportedVersion, v)
	}
	return SystemInfo{Version: v}, nil
}

func versionAtLeast(v string, major, minor int) bool {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}

// License is what /rest/status says about the IP license.
type License struct {
	Status      string
	LicensedIPs int64
	ActiveIPs   int64
}

// Status reads the license counters.
func (c *Client) Status(ctx context.Context) (License, error) {
	var r struct {
		LicenseStatus string  `json:"licenseStatus"`
		LicensedIPs   flexInt `json:"licensedIPs"`
		ActiveIPs     flexInt `json:"activeIPs"`
	}
	q := url.Values{"fields": {"licenseStatus,licensedIPs,activeIPs"}}
	if err := c.do(ctx, http.MethodGet, "/status", q, nil, 0, &r); err != nil {
		return License{}, err
	}
	l := License{Status: sanitizeText(r.LicenseStatus, 32)}
	if r.LicensedIPs > 0 {
		l.LicensedIPs = int64(r.LicensedIPs)
	}
	if r.ActiveIPs > 0 {
		l.ActiveIPs = int64(r.ActiveIPs)
	}
	return l, nil
}

// Page is one analysis page.
type Page struct {
	Total   int
	Results []json.RawMessage
}

// Analysis reads results [offset, offset+limit) of a vulnerability query.
func (c *Client) Analysis(ctx context.Context, q Query, offset, limit int) (Page, error) {
	if limit <= 0 {
		return Page{}, errors.New("tenable.sc: page size must be positive")
	}
	type wireQuery struct {
		Type        string   `json:"type"`
		Tool        string   `json:"tool"`
		SourceType  string   `json:"sourceType"`
		StartOffset int      `json:"startOffset"`
		EndOffset   int      `json:"endOffset"`
		Filters     []Filter `json:"filters"`
	}
	body := struct {
		Type       string    `json:"type"`
		SourceType string    `json:"sourceType"`
		ScanID     string    `json:"scanID,omitempty"`
		View       string    `json:"view,omitempty"`
		Query      wireQuery `json:"query"`
		SortField  string    `json:"sortField,omitempty"`
		SortDir    string    `json:"sortDir,omitempty"`
	}{
		Type:       "vuln",
		SourceType: q.SourceType,
		ScanID:     q.ScanID,
		View:       q.View,
		Query: wireQuery{
			Type: "vuln", Tool: q.Tool, SourceType: q.SourceType,
			StartOffset: offset, EndOffset: offset + limit, Filters: q.Filters,
		},
		SortField: q.SortField,
		SortDir:   q.SortDir,
	}
	if body.Query.Filters == nil {
		body.Query.Filters = []Filter{}
	}
	var p analysisPage
	if err := c.do(ctx, http.MethodPost, "/analysis", nil, body, analysisTimeout, &p); err != nil {
		return Page{}, err
	}
	if len(p.Results) > limit {
		return Page{}, fmt.Errorf("tenable.sc returned %d results for a page of %d", len(p.Results), limit)
	}
	total := int(p.TotalRecords)
	if total < 0 {
		total = 0
	}
	return Page{Total: total, Results: p.Results}, nil
}

// Plugin reads one plugin's metadata.
func (c *Client) Plugin(ctx context.Context, id string) (*plugin, error) {
	if _, err := strconv.ParseUint(id, 10, 32); err != nil {
		return nil, fmt.Errorf("tenable.sc: %q is not a plugin id", truncate(id, 16))
	}
	var p plugin
	if err := c.do(ctx, http.MethodGet, "/plugin/"+id, url.Values{"fields": {pluginFields}}, nil, 0, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ScanSpec is the one scan the connector creates for a connector_scan
// command. Every field comes from checked, typed values.
type ScanSpec struct {
	Name         string
	PolicyID     int
	RepositoryID int
	ZoneID       int // 0: not sent
	Targets      []string
	MaxScanTime  int // seconds
}

// CreateScan creates an on-demand scan definition and returns its id.
func (c *Client) CreateScan(ctx context.Context, s ScanSpec) (string, error) {
	body := map[string]any{
		"name":          s.Name,
		"description":   "Created by OpenCTEM for one scan run; deleted when the run ends",
		"type":          "policy",
		"policy":        map[string]string{"id": strconv.Itoa(s.PolicyID)},
		"repository":    map[string]string{"id": strconv.Itoa(s.RepositoryID)},
		"ipList":        strings.Join(s.Targets, ","),
		"schedule":      map[string]string{"type": "template"},
		"maxScanTime":   strconv.Itoa(s.MaxScanTime),
		"timeoutAction": "import",
		"dhcpTracking":  "false",
		"emailOnLaunch": "false",
		"emailOnFinish": "false",
	}
	if s.ZoneID > 0 {
		body["zone"] = map[string]string{"id": strconv.Itoa(s.ZoneID)}
	}
	var r struct {
		ID flexString `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/scan", nil, body, 0, &r); err != nil {
		return "", err
	}
	id := numericID(string(r.ID))
	if id == "" {
		return "", errors.New("tenable.sc created a scan without a usable id")
	}
	return id, nil
}

// LaunchScan launches the scan definition id and returns the scan result id.
func (c *Client) LaunchScan(ctx context.Context, id string) (string, error) {
	if numericID(id) == "" {
		return "", errors.New("tenable.sc: not a scan id")
	}
	var r struct {
		ScanResult struct {
			ID flexString `json:"id"`
		} `json:"scanResult"`
	}
	if err := c.do(ctx, http.MethodPost, "/scan/"+id+"/launch", nil, map[string]any{}, 0, &r); err != nil {
		return "", err
	}
	rid := numericID(string(r.ScanResult.ID))
	if rid == "" {
		return "", errors.New("tenable.sc launched a scan without a usable result id")
	}
	return rid, nil
}

// ScanResultState is the progress of one scan result.
type ScanResultState struct {
	Status          string
	ImportStatus    string
	Running         bool
	TotalChecks     int64
	CompletedChecks int64
}

// ScanResult reads the state of scan result id.
func (c *Client) ScanResult(ctx context.Context, id string) (ScanResultState, error) {
	if numericID(id) == "" {
		return ScanResultState{}, errors.New("tenable.sc: not a scan result id")
	}
	var r struct {
		Status          string   `json:"status"`
		ImportStatus    string   `json:"importStatus"`
		Running         flexBool `json:"running"`
		TotalChecks     flexInt  `json:"totalChecks"`
		CompletedChecks flexInt  `json:"completedChecks"`
	}
	q := url.Values{"fields": {"id,status,importStatus,running,totalChecks,completedChecks"}}
	if err := c.do(ctx, http.MethodGet, "/scanResult/"+id, q, nil, 0, &r); err != nil {
		return ScanResultState{}, err
	}
	return ScanResultState{
		Status:          sanitizeText(r.Status, 32),
		ImportStatus:    sanitizeText(r.ImportStatus, 32),
		Running:         bool(r.Running),
		TotalChecks:     int64(r.TotalChecks),
		CompletedChecks: int64(r.CompletedChecks),
	}, nil
}

// StopScanResult stops scan result id.
func (c *Client) StopScanResult(ctx context.Context, id string) error {
	if numericID(id) == "" {
		return errors.New("tenable.sc: not a scan result id")
	}
	return c.do(ctx, http.MethodPost, "/scanResult/"+id+"/stop", nil, map[string]any{}, 0, nil)
}

// DeleteScan deletes the scan definition id (its results stay).
func (c *Client) DeleteScan(ctx context.Context, id string) error {
	if numericID(id) == "" {
		return errors.New("tenable.sc: not a scan id")
	}
	return c.do(ctx, http.MethodDelete, "/scan/"+id, nil, nil, 0, nil)
}

// CatalogItem is a Tenable object the platform may pick by id.
type CatalogItem struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Repositories lists the repositories this user sees.
func (c *Client) Repositories(ctx context.Context) ([]CatalogItem, error) {
	var r []idName
	if err := c.do(ctx, http.MethodGet, "/repository", url.Values{"fields": {"id,name"}}, nil, 0, &r); err != nil {
		return nil, err
	}
	return catalog(r), nil
}

// Zones lists the scan zones this user sees.
func (c *Client) Zones(ctx context.Context) ([]CatalogItem, error) {
	var r []idName
	if err := c.do(ctx, http.MethodGet, "/zone", url.Values{"fields": {"id,name"}}, nil, 0, &r); err != nil {
		return nil, err
	}
	return catalog(r), nil
}

// Policies lists the scan policies this user may use or manage.
func (c *Client) Policies(ctx context.Context) ([]CatalogItem, error) {
	var r struct {
		Usable     []idName `json:"usable"`
		Manageable []idName `json:"manageable"`
	}
	if err := c.do(ctx, http.MethodGet, "/policy", url.Values{"fields": {"id,name"}}, nil, 0, &r); err != nil {
		return nil, err
	}
	return catalog(append(r.Usable, r.Manageable...)), nil
}

type idName struct {
	ID   flexString `json:"id"`
	Name string     `json:"name"`
}

const maxCatalogItems = 1000

func catalog(in []idName) []CatalogItem {
	seen := map[int]bool{}
	out := make([]CatalogItem, 0, len(in))
	for _, it := range in {
		id, err := strconv.Atoi(numericID(string(it.ID)))
		if err != nil || id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, CatalogItem{ID: id, Name: sanitizeText(it.Name, 128)})
		if len(out) >= maxCatalogItems {
			break
		}
	}
	return out
}

// numericID returns s when it is a positive decimal id, else "".
func numericID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 18 {
		return ""
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return ""
		}
	}
	if strings.TrimLeft(s, "0") == "" {
		return ""
	}
	return s
}
