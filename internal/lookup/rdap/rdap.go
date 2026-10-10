// Package rdap is the rdap lookup tool: the registration data of a root
// domain (registrar, registrant organization, name servers, registration
// and expiry dates, status) from the RDAP service of its registry
// (RFC 9082, RFC 9083), found through the IANA bootstrap registry
// (RFC 9224, https://data.iana.org/rdap/dns.json). Optionally the
// registrar's RDAP service the registry answer links to.
//
// Sources and terms: the IANA bootstrap file is public registry data,
// published for automated use; each registry and registrar RDAP service
// answers public queries under its own terms of use, which allow low-volume
// lookups of individual domains (bulk harvesting is what they forbid). The
// tool asks one question per domain per server, at most one request per
// second per server, honours Retry-After once, caches only the bootstrap
// file (24 h) and never caches per-domain answers between tasks.
//
// Personal data: only the registrant organization and country are kept;
// names, e-mail addresses, phone numbers and street addresses are dropped,
// as are redaction placeholders ("REDACTED FOR PRIVACY").
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/openctemio/sensor/internal/lookup"
)

// bootstrap is the IANA RDAP bootstrap file for DNS (a var for tests).
var bootstrap = lookup.Cached{
	Name:     "iana-rdap-dns.json",
	URL:      "https://data.iana.org/rdap/dns.json",
	MaxAge:   24 * time.Hour,
	MaxStale: 30 * 24 * time.Hour,
	MaxBytes: 4 << 20,
}

// mediaType is the RDAP media type (RFC 7480 §4.2).
const mediaType = "application/rdap+json, application/json;q=0.5"

// Bootstrap maps TLDs to RDAP base URLs (RFC 9224 §4).
type Bootstrap struct {
	services map[string][]string
}

// ParseBootstrap reads a bootstrap file. Only https base URLs are kept.
func ParseBootstrap(b []byte) (*Bootstrap, error) {
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("RDAP bootstrap: %w", err)
	}
	out := &Bootstrap{services: map[string][]string{}}
	for _, svc := range doc.Services {
		if len(svc) != 2 {
			continue
		}
		var urls []string
		for _, u := range svc[1] {
			if strings.HasPrefix(strings.ToLower(u), "https://") {
				if !strings.HasSuffix(u, "/") {
					u += "/"
				}
				urls = append(urls, u)
			}
		}
		for _, tld := range svc[0] {
			tld = strings.ToLower(strings.Trim(tld, "."))
			if tld != "" {
				out.services[tld] = append(out.services[tld], urls...)
			}
		}
	}
	if len(out.services) == 0 {
		return nil, errors.New("RDAP bootstrap: no services")
	}
	return out, nil
}

// ErrNoService: the domain's TLD has no https RDAP service in the
// bootstrap.
var ErrNoService = errors.New("no https RDAP service for this top-level domain")

// ServerFor is the RDAP base URL for a domain: the longest matching label
// suffix (bootstrap entries are single labels today; longer ones win).
func (b *Bootstrap) ServerFor(domain string) (string, error) {
	labels := strings.Split(domain, ".")
	for i := range labels {
		if urls := b.services[strings.Join(labels[i:], ".")]; len(urls) > 0 {
			return urls[0], nil
		}
	}
	return "", ErrNoService
}

// NormalizeDomain is the ASCII (A-label) lower-case form of a domain name
// target, or an error for anything that is not one (an address, a URL, a
// single label).
func NormalizeDomain(v string) (string, error) {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if v == "" || strings.ContainsAny(v, "/:@ ") {
		return "", fmt.Errorf("%q is not a domain name", v)
	}
	a, err := idna.Lookup.ToASCII(v)
	if err != nil || !strings.Contains(a, ".") || len(a) > 253 {
		return "", fmt.Errorf("%q is not a domain name", v)
	}
	return a, nil
}

// Registration is what a lookup found.
type Registration struct {
	Domain            string
	Server            string
	Handle            string
	Registrar         string
	RegistrarIANAID   string
	RegistrantOrg     string
	RegistrantCountry string
	Nameservers       []string
	Status            []string
	RegisteredAt      *time.Time
	ExpiresAt         *time.Time
	UpdatedAt         *time.Time
	// RegistrarURL is the registrar RDAP link of a registry answer.
	RegistrarURL string
}

// rdapDomain is the subset of an RDAP domain object (RFC 9083 §5.3) used.
type rdapDomain struct {
	ObjectClassName string       `json:"objectClassName"`
	LDHName         string       `json:"ldhName"`
	Handle          string       `json:"handle"`
	Status          []string     `json:"status"`
	Events          []rdapEvent  `json:"events"`
	Nameservers     []rdapNS     `json:"nameservers"`
	Entities        []rdapEntity `json:"entities"`
	Links           []rdapLink   `json:"links"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
	Type string `json:"type"`
}

type rdapEntity struct {
	Roles     []string        `json:"roles"`
	VCard     json.RawMessage `json:"vcardArray"`
	PublicIDs []rdapPublicID  `json:"publicIds"`
}

type rdapPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// Limits of what one answer may contribute.
const (
	maxNameservers = 32
	maxStatus      = 32
	maxText        = 256
)

// Parse reads an RDAP domain answer for domain. An answer for another
// domain, or that is not a domain object, is an error.
func Parse(domain, server string, b []byte) (*Registration, error) {
	var d rdapDomain
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("RDAP answer: %w", err)
	}
	if d.ObjectClassName != "domain" {
		return nil, fmt.Errorf("RDAP answer: object class %q, want domain", clip(d.ObjectClassName))
	}
	if got, err := NormalizeDomain(d.LDHName); err != nil || got != domain {
		return nil, fmt.Errorf("RDAP answer is for %q, not %s", clip(d.LDHName), domain)
	}
	r := &Registration{Domain: domain, Server: server, Handle: clip(d.Handle)}
	for _, s := range d.Status {
		if s = clip(strings.ToLower(strings.TrimSpace(s))); s != "" && len(r.Status) < maxStatus && !slices.Contains(r.Status, s) {
			r.Status = append(r.Status, s)
		}
	}
	for _, ns := range d.Nameservers {
		if n, err := NormalizeDomain(ns.LDHName); err == nil && len(r.Nameservers) < maxNameservers && !slices.Contains(r.Nameservers, n) {
			r.Nameservers = append(r.Nameservers, n)
		}
	}
	for _, e := range d.Events {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(e.Date))
		if err != nil {
			continue
		}
		t = t.UTC()
		switch strings.ToLower(e.Action) {
		case "registration":
			r.RegisteredAt = &t
		case "expiration":
			r.ExpiresAt = &t
		case "last changed":
			r.UpdatedAt = &t
		}
	}
	for _, e := range d.Entities {
		switch {
		case slices.Contains(e.Roles, "registrar"):
			if n := vcardText(e.VCard, "fn"); n != "" {
				r.Registrar = n
			} else if o := vcardText(e.VCard, "org"); o != "" {
				r.Registrar = o
			}
			for _, id := range e.PublicIDs {
				if strings.EqualFold(id.Type, "IANA Registrar ID") {
					r.RegistrarIANAID = clip(id.Identifier)
				}
			}
		case slices.Contains(e.Roles, "registrant"):
			if o := vcardText(e.VCard, "org"); o != "" {
				r.RegistrantOrg = o
			}
			if cc := vcardCountry(e.VCard); cc != "" {
				r.RegistrantCountry = cc
			}
		}
	}
	for _, l := range d.Links {
		if strings.EqualFold(l.Rel, "related") && strings.Contains(strings.ToLower(l.Type), "rdap+json") &&
			strings.HasPrefix(strings.ToLower(l.Href), "https://") {
			r.RegistrarURL = l.Href
			break
		}
	}
	return r, nil
}

// Merge fills what the registry answer lacks from the registrar's answer
// (the registrant, a registrar name); registry data wins otherwise.
func (r *Registration) Merge(o *Registration) {
	if o == nil {
		return
	}
	if r.RegistrantOrg == "" {
		r.RegistrantOrg = o.RegistrantOrg
	}
	if r.RegistrantCountry == "" {
		r.RegistrantCountry = o.RegistrantCountry
	}
	if r.Registrar == "" {
		r.Registrar = o.Registrar
	}
	if len(r.Nameservers) == 0 {
		r.Nameservers = o.Nameservers
	}
}

// vcardText is the first text value of a jCard property (RFC 7095), or ""
// for a missing, redacted or non-text value.
func vcardText(raw json.RawMessage, prop string) string {
	for _, p := range vcardProps(raw) {
		if len(p) < 4 || !strings.EqualFold(str(p[0]), prop) {
			continue
		}
		v := str(p[3])
		if v == "" {
			if list, ok := p[3].([]any); ok && len(list) > 0 {
				v = str(list[0])
			}
		}
		if v = clip(strings.TrimSpace(v)); v != "" && !redacted(v) {
			return v
		}
	}
	return ""
}

// vcardCountry is the cc parameter of the first adr property.
func vcardCountry(raw json.RawMessage) string {
	for _, p := range vcardProps(raw) {
		if len(p) < 2 || !strings.EqualFold(str(p[0]), "adr") {
			continue
		}
		if params, ok := p[1].(map[string]any); ok {
			if cc := strings.ToUpper(strings.TrimSpace(str(params["cc"]))); len(cc) == 2 {
				return cc
			}
		}
	}
	return ""
}

func vcardProps(raw json.RawMessage) [][]any {
	if len(raw) == 0 {
		return nil
	}
	var arr []any
	if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
		return nil
	}
	list, _ := arr[1].([]any)
	out := make([][]any, 0, len(list))
	for _, p := range list {
		if pp, ok := p.([]any); ok {
			out = append(out, pp)
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// redacted reports a redaction placeholder instead of a value.
func redacted(v string) bool {
	l := strings.ToLower(v)
	for _, w := range []string{"redacted", "privacy", "not disclosed", "data protected", "withheld"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// clip bounds a text value from an answer.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxText {
		s = s[:maxText]
	}
	return s
}

// Looker looks domains up for one task.
type Looker struct {
	Client          *lookup.Client
	Bootstrap       *Bootstrap
	FollowRegistrar bool
	// Interval is the minimum time between two requests to one server.
	Interval time.Duration

	mu   sync.Mutex
	last map[string]time.Time
}

// ErrNotFound: the registry has no such domain.
var ErrNotFound = errors.New("the registry has no registration for this domain")

// Lookup asks the registry (and the registrar, when asked to and linked).
func (l *Looker) Lookup(ctx context.Context, domain string) (*Registration, error) {
	base, err := l.Bootstrap.ServerFor(domain)
	if err != nil {
		return nil, err
	}
	reg, err := l.ask(ctx, domain, base+"domain/"+url.PathEscape(domain), base)
	if err != nil {
		return nil, err
	}
	if l.FollowRegistrar && reg.RegistrarURL != "" {
		if more, err := l.ask(ctx, domain, reg.RegistrarURL, reg.RegistrarURL); err == nil {
			reg.Merge(more)
		}
	}
	return reg, nil
}

func (l *Looker) ask(ctx context.Context, domain, u, server string) (*Registration, error) {
	for attempt := 0; ; attempt++ {
		if err := l.wait(ctx, u); err != nil {
			return nil, err
		}
		b, err := l.Client.Get(ctx, u, mediaType)
		var se *lookup.StatusError
		switch {
		case err == nil:
			return Parse(domain, server, b)
		case errors.As(err, &se) && se.Code == 404:
			return nil, ErrNotFound
		case errors.As(err, &se) && se.Code == 429 && attempt == 0 && se.RetryAfter > 0 && se.RetryAfter <= time.Minute:
			if err := sleep(ctx, se.RetryAfter); err != nil {
				return nil, err
			}
			continue
		default:
			return nil, err
		}
	}
}

// wait keeps Interval between two requests to one host.
func (l *Looker) wait(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	l.mu.Lock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	next := l.last[u.Host].Add(l.Interval)
	t := time.Now()
	if next.Before(t) {
		next = t
	}
	l.last[u.Host] = next
	l.mu.Unlock()
	return sleep(ctx, time.Until(next))
}

var sleep = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// LoadBootstrap fetches (or reuses) the bootstrap file in dir.
func LoadBootstrap(ctx context.Context, c *lookup.Client, dir string) (*Bootstrap, bool, error) {
	path, stale, err := c.Fetch(ctx, dir, bootstrap)
	if path == "" {
		return nil, false, err
	}
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		return nil, false, rerr
	}
	bs, perr := ParseBootstrap(b)
	if perr != nil {
		return nil, false, perr
	}
	return bs, stale, err
}
