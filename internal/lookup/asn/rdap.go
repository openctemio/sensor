package asn

// The RDAP fallback: when the routing dataset can neither be downloaded nor
// read and there is no cached copy, each address is asked of the regional
// registry that holds it (RFC 9082, RFC 9083), found through the IANA RDAP
// bootstrap files for addresses (ipv4.json, ipv6.json; RFC 9224). The
// answer names the holder and the registered range, and an origin system
// when the registry publishes one; the report has the same shape as the
// dataset's, with system 0 when unknown (the platform keys such a network by
// its holder name).
//
// The requests go to the registries' servers, never to the targets (the
// lookup client refuses target hosts), only over https, through the task's
// egress route. Concurrency and the number of addresses per task are bounded.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sensor/internal/lookup"
)

const (
	// rdapConcurrency bounds the parallel registry requests.
	rdapConcurrency = 4
	// maxRDAPAddrs bounds the addresses one task looks up this way.
	maxRDAPAddrs = 500
	rdapMedia    = "application/rdap+json, application/json;q=0.5"
)

// ipBootstrapFile is one IANA bootstrap file for addresses.
func ipBootstrapFile(local lookup.Local, name string) lookup.Cached {
	return lookup.Cached{
		Name:     "iana-rdap-" + name,
		URL:      local.BootstrapURL(name),
		MaxAge:   24 * time.Hour,
		AnyAge:   true,
		MaxBytes: 4 << 20,
		Validate: func(p string) error {
			b, err := os.ReadFile(p) // #nosec G304 -- the sensor's own temporary download
			if err != nil {
				return err
			}
			_, err = parseIPBootstrap(b)
			return err
		},
		Attempts: 2,
		Bound:    20 * time.Second,
	}
}

type ipService struct {
	prefixes []netip.Prefix
	base     string
}

type ipBootstrap struct{ services []ipService }

// parseIPBootstrap reads a bootstrap file. Only https base URLs are kept.
func parseIPBootstrap(b []byte) (*ipBootstrap, error) {
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("RDAP bootstrap: %w", err)
	}
	out := &ipBootstrap{}
	for _, svc := range doc.Services {
		if len(svc) != 2 {
			continue
		}
		var base string
		for _, u := range svc[1] {
			if lookup.HTTPSURL(u) == nil {
				base = u
				break
			}
		}
		if base == "" {
			continue
		}
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		s := ipService{base: base}
		for _, p := range svc[0] {
			if pf, err := netip.ParsePrefix(p); err == nil {
				s.prefixes = append(s.prefixes, pf.Masked())
			}
		}
		if len(s.prefixes) > 0 {
			out.services = append(out.services, s)
		}
	}
	if len(out.services) == 0 {
		return nil, errors.New("RDAP bootstrap: no services")
	}
	return out, nil
}

// baseFor is the RDAP base URL of the registry whose most specific listed
// prefix contains a ("" when none does).
func (b *ipBootstrap) baseFor(a netip.Addr) string {
	best, base := -1, ""
	for _, s := range b.services {
		for _, p := range s.prefixes {
			if p.Contains(a) && p.Bits() > best {
				best, base = p.Bits(), s.base
			}
		}
	}
	return base
}

func loadIPBootstraps(ctx context.Context, c *lookup.Client, dir string, local lookup.Local) (v4, v6 *ipBootstrap, err error) {
	load := func(name string) (*ipBootstrap, error) {
		f := ipBootstrapFile(local, name)
		path, _, ferr := c.Fetch(ctx, dir, f)
		if path == "" {
			return nil, fmt.Errorf("IANA bootstrap %s %s", hostOf(f.URL), lookup.Describe(ferr))
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- the sensor's own cache
		if rerr != nil {
			return nil, rerr
		}
		return parseIPBootstrap(b)
	}
	if v4, err = load("ipv4.json"); err != nil {
		return nil, nil, err
	}
	if v6, err = load("ipv6.json"); err != nil {
		return nil, nil, err
	}
	return v4, v6, nil
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return "source"
}

type rdapEntity struct {
	Roles    []string     `json:"roles"`
	VCard    []any        `json:"vcardArray"`
	Entities []rdapEntity `json:"entities"`
	Handle   string       `json:"handle"`
}

type rdapIP struct {
	Name         string          `json:"name"`
	Country      string          `json:"country"`
	StartAddress string          `json:"startAddress"`
	EndAddress   string          `json:"endAddress"`
	Cidrs        []rdapCIDR      `json:"cidr0_cidrs"`
	OriginAS     json.RawMessage `json:"arin_originas0_originautnums"`
	Entities     []rdapEntity    `json:"entities"`
}

type rdapCIDR struct {
	V4 string `json:"v4prefix"`
	V6 string `json:"v6prefix"`
	N  int    `json:"length"`
}

// entityName is the formatted name (vCard fn) of the registrant, else of
// any entity, searching nested entities to a small depth.
func entityName(es []rdapEntity, depth int) string {
	pick := func(wantRole string) string {
		for _, e := range es {
			if wantRole != "" && !hasRole(e.Roles, wantRole) {
				continue
			}
			if fn := vcardFN(e.VCard); fn != "" {
				return fn
			}
			if depth < 3 {
				if fn := entityName(e.Entities, depth+1); fn != "" {
					return fn
				}
			}
		}
		return ""
	}
	if fn := pick("registrant"); fn != "" {
		return fn
	}
	return pick("")
}

func hasRole(roles []string, r string) bool {
	for _, x := range roles {
		if strings.EqualFold(x, r) {
			return true
		}
	}
	return false
}

// vcardFN is the fn property of a jCard (RFC 7095).
func vcardFN(v []any) string {
	if len(v) != 2 {
		return ""
	}
	props, ok := v[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		arr, ok := p.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		if name, _ := arr[0].(string); strings.EqualFold(name, "fn") {
			if s, ok := arr[3].(string); ok {
				if s = clip(s); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// entryFromRDAP turns a registry answer for addr into a dataset-shaped
// entry. An answer whose range does not contain addr is refused.
func entryFromRDAP(addr netip.Addr, b []byte) (Entry, error) {
	var r rdapIP
	if err := json.Unmarshal(b, &r); err != nil {
		return Entry{}, fmt.Errorf("answer is not RDAP: %w", err)
	}
	start, err1 := netip.ParseAddr(r.StartAddress)
	end, err2 := netip.ParseAddr(r.EndAddress)
	if err1 != nil || err2 != nil {
		start, end = netip.Addr{}, netip.Addr{}
		for _, c := range r.Cidrs {
			raw := c.V4
			if raw == "" {
				raw = c.V6
			}
			if p, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", raw, c.N)); err == nil && p.Masked().Contains(addr) {
				p = p.Masked()
				start, end = p.Addr(), lastAddr(p)
				break
			}
		}
	}
	if !start.IsValid() || !end.IsValid() {
		return Entry{}, errors.New("answer has no address range")
	}
	e := Entry{Start: start.Unmap(), End: end.Unmap()}
	if !e.Contains(addr) || end.Less(start) {
		return Entry{}, errors.New("answer does not cover the address")
	}
	e.Org = entityName(r.Entities, 0)
	if e.Org == "" {
		e.Org = clip(r.Name)
	}
	if cc := strings.ToUpper(strings.TrimSpace(r.Country)); len(cc) == 2 && cc != "ZZ" {
		e.Country = cc
	}
	var asns []int
	if len(r.OriginAS) > 0 && json.Unmarshal(r.OriginAS, &asns) == nil {
		for _, a := range asns {
			if a > 0 && a <= 4294967295 {
				e.ASN = a
				break
			}
		}
	}
	return e, nil
}

// rdapResult is the outcome for one address.
type rdapResult struct {
	entry Entry
	found bool   // a registry holds the address
	err   error  // the source failed
	src   string // "host status" of the failure
}

// lookupRDAP asks the registries about addrs (at most maxRDAPAddrs, the rest
// get a limit error), maxRDAPConcurrency at a time.
func lookupRDAP(ctx context.Context, c *lookup.Client, v4, v6 *ipBootstrap, addrs []netip.Addr) map[netip.Addr]rdapResult {
	out := make(map[netip.Addr]rdapResult, len(addrs))
	var mu sync.Mutex
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range rdapConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				res := lookupOne(ctx, c, v4, v6, a)
				mu.Lock()
				out[a] = res
				mu.Unlock()
			}
		}()
	}
	for i, a := range addrs {
		if i >= maxRDAPAddrs {
			out[a] = rdapResult{err: errors.New("limit"), src: fmt.Sprintf("limit of %d addresses per task", maxRDAPAddrs)}
			continue
		}
		jobs <- a
	}
	close(jobs)
	wg.Wait()
	return out
}

func lookupOne(ctx context.Context, c *lookup.Client, v4, v6 *ipBootstrap, a netip.Addr) rdapResult {
	if err := ctx.Err(); err != nil {
		return rdapResult{err: err, src: "canceled"}
	}
	bs := v6
	if a.Is4() {
		bs = v4
	}
	base := bs.baseFor(a)
	if base == "" {
		// No registry is listed for the address: a finished lookup.
		return rdapResult{}
	}
	body, err := c.Get(ctx, base+"ip/"+a.String(), rdapMedia)
	if err != nil {
		var se *lookup.StatusError
		if errors.As(err, &se) && se.Code == 404 {
			return rdapResult{}
		}
		return rdapResult{err: err, src: hostOf(base) + " " + lookup.Describe(err)}
	}
	e, err := entryFromRDAP(a, body)
	if err != nil {
		return rdapResult{err: err, src: hostOf(base) + " " + err.Error()}
	}
	return rdapResult{entry: e, found: true}
}

// sources lists the distinct failures, sorted and bounded.
func sources(res map[netip.Addr]rdapResult) string {
	set := map[string]bool{}
	for _, r := range res {
		if r.err != nil {
			set[r.src] = true
		}
	}
	list := make([]string, 0, len(set))
	for s := range set {
		list = append(list, s)
	}
	sort.Strings(list)
	if len(list) > 4 {
		list = append(list[:4], "...")
	}
	return strings.Join(list, ", ")
}
