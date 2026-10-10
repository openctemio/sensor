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
	path, stale, err := client.Fetch(ctx, dir, dataset)
	if path == "" {
		return tool.Failed(fmt.Errorf("asn: routing dataset: %w", err))
	}
	if stale {
		ctx.Log().Warn("asn: the routing dataset could not be refreshed; using the cached copy", "error", err.Error())
	}
	found, err := Lookup(ctx, path, addrs)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tool.Failed(fmt.Errorf("asn: routing dataset: %w", err))
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
		if err := emit(ctx, TargetAsset(tg, e)); err != nil {
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
	seen := map[netip.Prefix]bool{}
	for _, tg := range targets {
		if tg.prefix.IsValid() {
			seen[tg.prefix] = true
		}
	}
	for _, a := range asns {
		for _, p := range announced[a] {
			if seen[p] {
				continue
			}
			seen[p] = true
			if err := emit(ctx, NetworkAsset(p.String(), orgs[a], nil)); err != nil {
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

// TargetAsset re-observes a target (the value as the platform sent it)
// with its origin system and announced range.
func TargetAsset(tg target, e Entry) ctis.Asset {
	prefixes := make([]string, 0, maxOwnPrefixes)
	for _, p := range e.Prefixes(maxOwnPrefixes) {
		prefixes = append(prefixes, p.String())
	}
	if tg.prefix.IsValid() {
		return NetworkAsset(tg.t.Value, e, prefixes)
	}
	version := 4
	if tg.addr.Is6() {
		version = 6
	}
	return ctis.Asset{
		Type:  ctis.AssetTypeIPAddress,
		Value: tg.t.Value,
		Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{
			Version: version, ASN: e.ASN, ASNOrg: e.Org, Country: e.Country,
		}},
		Properties: ctis.Properties{"asn_prefixes": prefixes},
	}
}

// NetworkAsset is a network (its value as given) with its origin system
// and, when known, the prefixes of its announced range.
func NetworkAsset(value string, e Entry, prefixes []string) ctis.Asset {
	props := ctis.Properties{"asn": e.ASN}
	if e.Org != "" {
		props["asn_org"] = e.Org
	}
	if e.Country != "" {
		props["country"] = e.Country
	}
	if len(prefixes) > 0 {
		props["asn_prefixes"] = prefixes
	}
	return ctis.Asset{Type: ctis.AssetTypeNetwork, Value: value, Properties: props}
}
