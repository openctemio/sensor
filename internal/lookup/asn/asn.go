// Package asn is the asn lookup tool: the origin autonomous system, its
// holder and country, and the announced range of an address or network,
// and optionally the other ranges the same system announces.
//
// Source and licence: the IPtoASN dataset (https://iptoasn.com/), built
// hourly from public BGP tables and released into the public domain under
// the Open Data Commons PDDL 1.0: any use, commercial included, with no
// attribution required. It is one file (ip2asn-combined.tsv.gz, about
// 9 MB) downloaded through the sensor's egress proxy at most once a day and
// kept in the sensor's lookup cache; every lookup is then local, so the
// tool sends no per-target query anywhere (the dataset host never learns
// which addresses a tenant looked up) and nothing to the targets.
package asn

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sensor/internal/lookup"
)

// dataset is the IPtoASN combined (IPv4 + IPv6) file (a var for tests).
var dataset = lookup.Cached{
	Name:     "ip2asn-combined.tsv.gz",
	URL:      "https://iptoasn.com/data/ip2asn-combined.tsv.gz",
	MaxAge:   24 * time.Hour,
	MaxStale: 7 * 24 * time.Hour,
	MaxBytes: 64 << 20,
}

// Entry is one dataset row: a routed range and its origin system.
type Entry struct {
	Start, End netip.Addr
	ASN        int
	Country    string
	Org        string
}

// maxLine bounds a dataset line; longer lines are skipped.
const maxLine = 4096

// Scan calls fn for every routed row of the gzip'd dataset at path (rows
// of AS 0, "not routed", and malformed rows are skipped). fn returns false
// to stop.
func Scan(ctx context.Context, path string, fn func(Entry) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("dataset: %w", err)
	}
	defer func() { _ = zr.Close() }()
	return scanReader(ctx, zr, fn)
}

func scanReader(ctx context.Context, r io.Reader, fn func(Entry) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	n := 0
	for sc.Scan() {
		if n++; n%65536 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		e, ok := parseLine(sc.Text())
		if !ok {
			continue
		}
		if !fn(e) {
			return nil
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return fmt.Errorf("dataset: %w", err)
	}
	return nil
}

func parseLine(line string) (Entry, bool) {
	parts := strings.SplitN(line, "\t", 5)
	if len(parts) != 5 {
		return Entry{}, false
	}
	start, err1 := netip.ParseAddr(parts[0])
	end, err2 := netip.ParseAddr(parts[1])
	asn, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || asn <= 0 || asn > 4294967295 ||
		start.Is4() != end.Is4() || end.Less(start) {
		return Entry{}, false
	}
	cc := strings.ToUpper(strings.TrimSpace(parts[3]))
	if len(cc) != 2 || cc == "ZZ" {
		cc = ""
	}
	return Entry{Start: start.Unmap(), End: end.Unmap(), ASN: asn, Country: cc, Org: clip(parts[4])}, true
}

func clip(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s))
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// Contains reports whether a is in the entry's range.
func (e Entry) Contains(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() == e.Start.Is4() && !a.Less(e.Start) && !e.End.Less(a)
}

// Prefixes are the CIDR blocks that exactly cover the entry's range, at
// most max (0: no bound).
func (e Entry) Prefixes(max int) []netip.Prefix {
	return RangePrefixes(e.Start, e.End, max)
}

// RangePrefixes is the smallest list of prefixes covering start..end, in
// order, cut at max (0: no bound).
func RangePrefixes(start, end netip.Addr, max int) []netip.Prefix {
	var out []netip.Prefix
	if start.Is4() != end.Is4() || end.Less(start) {
		return nil
	}
	bits := start.BitLen()
	for {
		l := bits
		for l > 0 {
			p := netip.PrefixFrom(start, l-1).Masked()
			if p.Addr() != start || end.Less(lastAddr(p)) {
				break
			}
			l--
		}
		p := netip.PrefixFrom(start, l)
		out = append(out, p)
		last := lastAddr(p)
		if (max > 0 && len(out) >= max) || !last.Less(end) {
			return out
		}
		start = last.Next()
		if !start.IsValid() {
			return out
		}
	}
}

// lastAddr is the last address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().As16()
	host := 128 - p.Bits()
	if p.Addr().Is4() {
		host = 32 - p.Bits()
	}
	for i := 15; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(0xff >> (8 - n))
		host -= n
	}
	a := netip.AddrFrom16(b)
	if p.Addr().Is4() {
		return a.Unmap()
	}
	return a
}

// Lookup finds the entry holding each address (in one pass over the
// dataset).
func Lookup(ctx context.Context, path string, addrs []netip.Addr) (map[netip.Addr]Entry, error) {
	sorted := slices.Clone(addrs)
	slices.SortFunc(sorted, func(a, b netip.Addr) int { return a.Compare(b) })
	sorted = slices.Compact(sorted)
	out := make(map[netip.Addr]Entry, len(sorted))
	err := Scan(ctx, path, func(e Entry) bool {
		i, _ := slices.BinarySearchFunc(sorted, e.Start, func(a, t netip.Addr) int { return a.Compare(t) })
		for ; i < len(sorted) && e.Contains(sorted[i]); i++ {
			if _, ok := out[sorted[i]]; !ok {
				out[sorted[i]] = e
			}
		}
		return len(out) < len(sorted)
	})
	return out, err
}

// Announced collects, per autonomous system, the prefixes of its ranges,
// at most max prefixes per system (in one pass over the dataset).
func Announced(ctx context.Context, path string, asns []int, max int) (map[int][]netip.Prefix, error) {
	want := map[int]bool{}
	for _, a := range asns {
		want[a] = true
	}
	out := map[int][]netip.Prefix{}
	err := Scan(ctx, path, func(e Entry) bool {
		if !want[e.ASN] {
			return true
		}
		room := max - len(out[e.ASN])
		if room <= 0 {
			return true
		}
		out[e.ASN] = append(out[e.ASN], e.Prefixes(room)...)
		return true
	})
	return out, err
}
