package rdap

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
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

// Manifest describes the rdap tool.
var Manifest = toolrun.MustManifest(ToolYAML)

// Tool runs rdap in the tool child.
var Tool = toolrun.Register(tool.New(Manifest, run))

var settingsSchema = core.MustParseSettingsSchema(string(Manifest.Config))

// Config is the tool's configuration (tool.yaml config).
type Config struct {
	FollowRegistrar *bool `json:"follow_registrar,omitempty"`
}

// NewScanner is the rdap scanner the command executor dispatches.
func NewScanner() *lookup.Scanner {
	return lookup.New(lookup.Spec{Tool: Tool, Schema: settingsSchema, Config: configFrom})
}

func configFrom(ts *core.ToolSettings) (json.RawMessage, error) {
	var c Config
	if v, ok := ts.Bool("follow_registrar"); ok {
		c.FollowRegistrar = &v
	}
	return json.Marshal(c)
}

// requestInterval is the minimum time between two requests to one RDAP
// server (a var for tests).
var requestInterval = time.Second

// run is the tool's Run in the child: one lookup per registered domain.
func run(ctx tool.Context, task tool.Task, _ json.RawMessage) error {
	local, err := lookup.ReadLocal(task)
	if err != nil {
		return err
	}
	var cfg Config
	if len(local.Config) > 0 {
		if err := json.Unmarshal(local.Config, &cfg); err != nil {
			return tool.Invalid("rdap: the configuration is unreadable")
		}
	}
	follow := cfg.FollowRegistrar == nil || *cfg.FollowRegistrar
	dir := local.CacheDir
	if dir == "" {
		dir = ctx.Workdir()
	}
	client := lookup.NewClient(Manifest, task.Targets, 30*time.Second)
	bs, stale, err := LoadBootstrap(ctx, client, dir)
	if bs == nil {
		return tool.Failed(fmt.Errorf("rdap: IANA bootstrap: %w", err))
	}
	if stale {
		ctx.Log().Warn("rdap: the IANA bootstrap could not be refreshed; using the cached copy", "error", err.Error())
	}
	looker := &Looker{Client: client, Bootstrap: bs, FollowRegistrar: follow, Interval: requestInterval}

	// A registry answers for the registered domain only: every target is
	// looked up as its registrable domain, once, and the answer is the
	// registered domain's (a subdomain target reports its root).
	var groups []*group
	byDomain := map[string]*group{}
	for _, t := range task.Targets {
		domain, err := NormalizeDomain(t.Value)
		if err != nil {
			ctx.TargetSkipped(t, err.Error())
			continue
		}
		reg, err := RegistrableDomain(domain)
		if err != nil {
			ctx.TargetSkipped(t, fmt.Sprintf("%s %v", domain, err))
			continue
		}
		g := byDomain[reg]
		if g == nil {
			g = &group{domain: reg}
			byDomain[reg] = g
			groups = append(groups, g)
		}
		g.targets = append(g.targets, t)
		if domain == reg && g.value == "" {
			g.value = t.Value // the target as the platform sent it
		}
	}
	done := func(g *group) {
		for _, t := range g.targets {
			ctx.TargetDone(t)
		}
	}
	for i, g := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		ctx.Progress(i, len(groups), g.domain)
		value := g.value
		if value == "" {
			value = g.domain
		}
		reg, err := looker.Lookup(ctx, g.domain)
		var asset ctis.Asset
		switch {
		case errors.Is(err, ErrNoService), errors.Is(err, ErrNotFound):
			// A finished lookup with nothing to report from the registry:
			// the domain says why, so a run never shows "nothing".
			ctx.Log().Info("rdap: "+err.Error(), "domain", g.domain)
			asset = StatusAsset(value, statusOf(err))
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			for _, t := range g.targets {
				ctx.TargetError(t, tool.Unreachable(err))
			}
			continue
		default:
			asset = Asset(value, reg)
		}
		if err := ctx.Emit().Asset(asset); err != nil {
			if errors.Is(err, tool.ErrOutputLimit) {
				return err
			}
			ctx.Log().Warn("rdap: a record was refused", "error", err.Error())
		}
		done(g)
	}
	return nil
}

// group is the targets that share one registrable domain.
type group struct {
	domain  string
	value   string
	targets []tool.Target
}

// RDAP statuses of a domain the registry did not describe (whois key
// rdap_status of the domain asset).
const (
	// StatusNoService: the domain's top-level domain has no https RDAP
	// service in the IANA bootstrap (many country-code domains).
	StatusNoService = "registry_has_no_rdap"
	// StatusNotRegistered: the registry has no registration for the domain.
	StatusNotRegistered = "not_registered"
)

func statusOf(err error) string {
	if errors.Is(err, ErrNoService) {
		return StatusNoService
	}
	return StatusNotRegistered
}

// StatusAsset is the domain asset of a domain whose registry gave no
// registration, carrying only why (whois rdap_status).
func StatusAsset(value, status string) ctis.Asset {
	return ctis.Asset{
		Type:  ctis.AssetTypeDomainName,
		Value: value,
		Technical: &ctis.AssetTechnical{Domain: &ctis.DomainTechnical{
			WHOIS: map[string]string{"rdap_status": status},
		}},
	}
}

// Asset is the domain asset carrying the registration (the target as the
// platform sent it, so it re-observes that asset).
func Asset(value string, r *Registration) ctis.Asset {
	whois := map[string]string{"rdap_server": r.Server}
	put := func(k, v string) {
		if v != "" {
			whois[k] = v
		}
	}
	put("handle", r.Handle)
	put("registrant_org", r.RegistrantOrg)
	put("registrant_country", r.RegistrantCountry)
	put("registrar_iana_id", r.RegistrarIANAID)
	if len(r.Status) > 0 {
		b, _ := json.Marshal(r.Status)
		whois["status"] = string(b)
	}
	if r.UpdatedAt != nil {
		whois["updated_at"] = r.UpdatedAt.Format(time.RFC3339)
	}
	return ctis.Asset{
		Type:  ctis.AssetTypeDomainName,
		Value: value,
		Technical: &ctis.AssetTechnical{Domain: &ctis.DomainTechnical{
			Registrar:    r.Registrar,
			RegisteredAt: r.RegisteredAt,
			ExpiresAt:    r.ExpiresAt,
			Nameservers:  r.Nameservers,
			WHOIS:        whois,
		}},
	}
}
