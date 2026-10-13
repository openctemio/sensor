package naabu

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// maxExcludeHosts bounds the hosts handed to -exclude-hosts (the SDK
// refuses a job with more exclusions).
const maxExcludeHosts = 4096

// WithExcludeHosts returns a copy of the scanner that never probes the
// job's excluded addresses (naabu -exclude-hosts). The SDK already cut the
// job's ranges around them address by address; this keeps naabu from
// reaching them too, should a target still cover one. Each entry is an
// address, a CIDR prefix or a "first-last" range (written as prefixes); an
// entry that is none of these refuses the job rather than being dropped.
func (s *Scanner) WithExcludeHosts(hosts []string) (core.ReconScanner, error) {
	if len(hosts) == 0 {
		return s, nil
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ps, err := excludePrefixes(strings.TrimSpace(h))
		if err != nil {
			return nil, fmt.Errorf("naabu: excluded host %q: %w", h, err)
		}
		out = append(out, ps...)
	}
	if len(out) > maxExcludeHosts {
		return nil, fmt.Errorf("naabu: %d excluded hosts, at most %d", len(out), maxExcludeHosts)
	}
	c := *s
	c.ExcludeHosts = out
	return &c, nil
}

// excludePrefixes writes one exclusion as naabu reads it: an address or a
// CIDR prefix.
func excludePrefixes(s string) ([]string, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return []string{p.Masked().String()}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return []string{a.Unmap().WithZone("").String()}, nil
	}
	first, last, ok := strings.Cut(s, "-")
	if !ok {
		return nil, fmt.Errorf("not an address, a prefix or a range")
	}
	a, err1 := netip.ParseAddr(strings.TrimSpace(first))
	b, err2 := netip.ParseAddr(strings.TrimSpace(last))
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("not an address range")
	}
	a, b = a.Unmap().WithZone(""), b.Unmap().WithZone("")
	if a.Is4() != b.Is4() || b.Less(a) {
		return nil, fmt.Errorf("not an address range")
	}
	var out []string
	for {
		bits := a.BitLen()
		for bits > 0 {
			p := netip.PrefixFrom(a, bits-1)
			if p.Masked().Addr() != a || lastAddr(p).Compare(b) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(a, bits)
		out = append(out, p.String())
		if len(out) > maxExcludeHosts {
			return nil, fmt.Errorf("the range splits into too many prefixes")
		}
		l := lastAddr(p)
		if l.Compare(b) >= 0 {
			return out, nil
		}
		a = l.Next()
	}
}

// lastAddr is the last address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	host := len(b)*8 - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
