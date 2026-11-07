package asn

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/lookup"
	"github.com/openctemio/sensor/internal/toolrun"
)

// ToolYAML is the tool's descriptor (OpenCTEM Tool Contract v1): the one
// place its contract is written.
//
//go:embed tool.yaml
var ToolYAML []byte

// Manifest describes the asn tool.
var Manifest = toolrun.MustManifest(ToolYAML)

// Tool runs asn in the tool child.
var Tool = toolrun.Register(tool.New(Manifest, run))

var settingsSchema = core.MustParseSettingsSchema(string(Manifest.Config))

// Config is the tool's configuration (tool.yaml config).
type Config struct {
	IncludeAnnounced bool `json:"include_announced,omitempty"`
	MaxRanges        int  `json:"max_ranges,omitempty"`
}

// Defaults and bounds.
const (
	defaultMaxRanges = 100
	maxMaxRanges     = 5000
	// maxOwnPrefixes bounds the prefixes of a target's own range listed
	// on it.
	maxOwnPrefixes = 16
)

// NewScanner is the asn scanner the command executor dispatches.
func NewScanner() *lookup.Scanner {
	return lookup.New(lookup.Spec{Tool: Tool, Schema: settingsSchema, Config: configFrom})
}

func configFrom(ts *core.ToolSettings) (json.RawMessage, error) {
	var c Config
	if v, ok := ts.Bool("include_announced"); ok {
		c.IncludeAnnounced = v
	}
	if v, ok := ts.Int("max_ranges"); ok {
		if v < 1 || v > maxMaxRanges {
			return nil, fmt.Errorf("max_ranges %d outside 1..%d", v, maxMaxRanges)
		}
		c.MaxRanges = int(v)
	}
	return json.Marshal(c)
}

// runRDAP is the run when the routing dataset is unavailable and no usable
// copy exists: each address is asked of its registry (rdap.go). Addresses a
// registry answered are reported and done; an address no source could answer
// is an error of the transient class whose detail starts with
// "source_unavailable:" and names the sources and their statuses.
func runRDAP(ctx tool.Context, client *lookup.Client, local lookup.Local, dir string, targets []target, addrs []netip.Addr, dsHost string, dsErr error) error {
	detail := "routing dataset " + dsHost + " " + lookup.Describe(dsErr)
	unavailable := func(rdap string) error {
		return tool.Retry(errors.New("source_unavailable: " + detail + "; rdap: " + rdap))
	}
	if local.ASNRDAPFallbackOff {
		ctx.Log().Warn("asn: the routing dataset is unavailable and the RDAP fallback is off", "error", detail)
		return unavailable("fallback off (" + lookup.EnvASNRDAPFallback + "=off)")
	}
	v4, v6, err := loadIPBootstraps(ctx, client, dir, local)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ctx.Log().Warn("asn: the routing dataset is unavailable and so is the RDAP bootstrap", "error", detail)
		return unavailable(err.Error())
	}
	ctx.Log().Warn("asn: the routing dataset is unavailable; asking the registries (RDAP)", "error", detail)
	uniq := slices.Clone(addrs)
	slices.SortFunc(uniq, func(a, b netip.Addr) int { return a.Compare(b) })
	uniq = slices.Compact(uniq)
	res := lookupRDAP(ctx, client, v4, v6, uniq)
	if err := ctx.Err(); err != nil {
		return err
	}
	srcs := sources(res)
	done, failed := 0, 0
	for _, tg := range targets {
		r := res[tg.addr]
		switch {
		case r.err != nil:
			failed++
			ctx.TargetError(tg.t, tool.Retry(errors.New("source_unavailable: "+detail+"; rdap: "+srcs)))
			continue
		case !r.found:
			ctx.Log().Info("asn: no registry holds the address", "target", tg.t.Value)
		default:
			if err := emitReport(ctx, TargetReport(tg, r.entry)); err != nil {
				return err
			}
		}
		done++
		ctx.TargetDone(tg.t)
	}
	if done == 0 && failed > 0 {
		return unavailable(srcs)
	}
	return nil
}

// target is one task target as an address or a network.
type target struct {
	t      tool.Target
	addr   netip.Addr
	prefix netip.Prefix // valid for a network target
}

func parseTarget(t tool.Target) (target, error) {
	v := strings.TrimSpace(t.Value)
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return target{}, fmt.Errorf("%q is not a network", v)
		}
		p = p.Masked()
		return target{t: t, addr: p.Addr().Unmap(), prefix: p}, nil
	}
	a, err := netip.ParseAddr(strings.Trim(v, "[]"))
	if err != nil {
		return target{}, fmt.Errorf("%q is not an address", v)
	}
	return target{t: t, addr: a.Unmap()}, nil
}

// run is the tool's Run in the child.
func run(ctx tool.Context, task tool.Task, _ json.RawMessage) error {
	local, err := lookup.ReadLocal(task)
	if err != nil {
		return err
	}
	var cfg Config
	if len(local.Config) > 0 {
		if err := json.Unmarshal(local.Config, &cfg); err != nil {
			return tool.Invalid("asn: the configuration is unreadable")
		}
	}
	if cfg.MaxRanges <= 0 || cfg.MaxRanges > maxMaxRanges {
		cfg.MaxRanges = defaultMaxRanges
	}
	var targets []target
	var addrs []netip.Addr
	for _, t := range task.Targets {
		tg, err := parseTarget(t)
		if err != nil {
			ctx.TargetSkipped(t, err.Error())
			continue
		}
		if !tg.addr.IsGlobalUnicast() || tg.addr.IsPrivate() {
			ctx.TargetSkipped(t, "not a public address: no routing data")
			continue
		}
		targets = append(targets, tg)
		addrs = append(addrs, tg.addr)
	}
	if len(targets) == 0 {
		return nil
	}
	dir := local.CacheDir
	if dir == "" {
		dir = ctx.Workdir()
	}
	client := lookup.NewClient(Manifest, task.Targets, 5*time.Minute)
	ds := dataset
	if local.ASNDatasetURL != "" {
		ds.URL = local.ASNDatasetURL
	}
	path, stale, err := client.Fetch(ctx, dir, ds)
	var found map[netip.Addr]Entry
	if path != "" {
		if stale {
			age, _ := lookup.Age(path)
			ctx.Log().Warn("asn: the routing dataset could not be refreshed; using the cached copy",
				"age", age.Round(time.Minute).String(), "source", ds.URL, "error", lookup.Describe(err))
		}
		if found, err = Lookup(ctx, path, addrs); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// An unreadable copy is no copy: ask the registries.
			path = ""
		}
	}
	if path == "" {
		return runRDAP(ctx, client, local, dir, targets, addrs, hostOf(ds.URL), err)
	}
	var asns []int
	for _, tg := range targets {
		e, ok := found[tg.addr]
		if !ok {
			// A finished lookup: the address is not routed.
			ctx.Log().Info("asn: not in any announced range", "target", tg.t.Value)
			ctx.TargetDone(tg.t)
			continue
		}
		if err := emitReport(ctx, TargetReport(tg, e)); err != nil {
			return err
		}
		if !slices.Contains(asns, e.ASN) {
			asns = append(asns, e.ASN)
		}
		ctx.TargetDone(tg.t)
	}
	if !cfg.IncludeAnnounced || len(asns) == 0 {
		return nil
	}
	announced, err := Announced(ctx, path, asns, cfg.MaxRanges)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tool.Failed(fmt.Errorf("asn: routing dataset: %w", err))
	}
	orgs := map[int]Entry{}
	for _, e := range found {
		orgs[e.ASN] = e
	}
	// Ranges already reported (a target range, a target address's own
	// range) are not reported again: an asset id is reported once.
	seen := map[netip.Prefix]bool{}
	for _, tg := range targets {
		if tg.prefix.IsValid() {
			seen[tg.prefix] = true
		} else if e, ok := found[tg.addr]; ok {
			for _, p := range e.Prefixes(maxOwnPrefixes) {
				seen[p] = true
			}
		}
	}
	for _, a := range asns {
		for _, p := range announced[a] {
			if seen[p] {
				continue
			}
			seen[p] = true
			if err := emit(ctx, RangeAsset(p.String(), orgs[a])); err != nil {
				return err
			}
		}
	}
	return nil
}

func emit(ctx tool.Context, a ctis.Asset) error {
	if err := ctx.Emit().Asset(a); err != nil {
		if errors.Is(err, tool.ErrOutputLimit) {
			return err
		}
		ctx.Log().Warn("asn: a record was refused", "error", err.Error())
	}
	return nil
}

func emitReport(ctx tool.Context, r *ctis.Report) error {
	if err := ctx.Emit().Report(r); err != nil {
		if errors.Is(err, tool.ErrOutputLimit) {
			return err
		}
		ctx.Log().Warn("asn: a record was refused", "error", err.Error())
	}
	return nil
}

// TargetReport re-observes a target (the value as the platform sent it)
// with its origin system: an address with the announced ranges that
// contain it (ip_range assets and contains relationships), a range as
// itself. Asset ids are document-local, derived from the values.
func TargetReport(tg target, e Entry) *ctis.Report {
	r := &ctis.Report{}
	if tg.prefix.IsValid() {
		r.Assets = append(r.Assets, RangeAsset(tg.t.Value, e))
		return r
	}
	version := 4
	if tg.addr.Is6() {
		version = 6
	}
	ip := ctis.Asset{
		ID:    localID(ctis.AssetTypeIPAddress, tg.t.Value),
		Type:  ctis.AssetTypeIPAddress,
		Value: tg.t.Value,
		Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{
			Version: version, ASN: e.ASN, ASNOrg: e.Org, Country: e.Country,
		}},
	}
	r.Assets = append(r.Assets, ip)
	for _, p := range e.Prefixes(maxOwnPrefixes) {
		rng := RangeAsset(p.String(), e)
		r.Assets = append(r.Assets, rng)
		r.Relationships = append(r.Relationships, ctis.Relationship{Type: ctis.RelContains, FromRef: rng.ID, ToRef: ip.ID})
	}
	return r
}

// RangeAsset is an ip_range (its value as given, a CIDR) with its origin
// system, holder and country.
func RangeAsset(value string, e Entry) ctis.Asset {
	return ctis.Asset{
		ID:    localID(ctis.AssetTypeIPRange, value),
		Type:  ctis.AssetTypeIPRange,
		Value: value,
		Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{
			ASN: e.ASN, ASNOrg: e.Org, Country: e.Country,
		}},
	}
}

// localID is the document-local id of an asset: its type and its canonical
// value (never UUID-shaped: it carries the type prefix and the value).
func localID(t ctis.AssetType, value string) string {
	return string(t) + ":" + ctis.NormalizeAssetName(t, value)
}
