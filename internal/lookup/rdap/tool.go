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

// run is the tool's Run in the child: one lookup per domain target.
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
	for i, t := range task.Targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		ctx.Progress(i, len(task.Targets), t.Value)
		domain, err := NormalizeDomain(t.Value)
		if err != nil {
			ctx.TargetSkipped(t, err.Error())
			continue
		}
		reg, err := looker.Lookup(ctx, domain)
		switch {
		case errors.Is(err, ErrNoService), errors.Is(err, ErrNotFound):
			// A finished lookup with nothing to report.
			ctx.Log().Info("rdap: "+err.Error(), "domain", domain)
			ctx.TargetDone(t)
			continue
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			ctx.TargetError(t, tool.Unreachable(err))
			continue
		}
		if err := ctx.Emit().Asset(Asset(t.Value, reg)); err != nil {
			if errors.Is(err, tool.ErrOutputLimit) {
				return err
			}
			ctx.Log().Warn("rdap: a record was refused", "error", err.Error())
		}
		ctx.TargetDone(t)
	}
	return nil
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
		Type:  ctis.AssetTypeDomain,
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
