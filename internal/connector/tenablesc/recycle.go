package tenablesc

// Licence rotation by recycling the rotation repository (opt-in, operation
// recycle). Tenable.sc has no API that removes selected IPs or
// vulnerabilities from a repository; deleting a repository removes its data
// and the licence count updates at once (Security Center user guide,
// "License Requirements"). So a coverage batch may, after the platform
// confirmed the previous batch's results were ingested, delete the one
// rotation repository the sensor owner named and recreate it with the same
// definition before it launches. Only a repository whose name the owner
// configured (with the OpenCTEM prefix) is ever touched, with administrator
// keys used for nothing else. The repository definition fields sent back on
// create follow the API reference and are not yet verified against a real
// instance.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// repositoryFields are read from the rotation repository and sent back
// unchanged when it is recreated.
const repositoryFields = "id,name,description,type,dataFormat,ipRange,trendingDays,trendWithRaw," +
	"activeVulnsLifetime,passiveVulnsLifetime,lceVulnsLifetime,complianceVulnsLifetime,mitigatedVulnsLifetime,organizations"

// repositoryDef is a repository definition as /rest/repository returns it.
type repositoryDef struct {
	ID                      flexString `json:"id"`
	Name                    string     `json:"name"`
	Description             string     `json:"description"`
	Type                    string     `json:"type"`
	DataFormat              string     `json:"dataFormat"`
	IPRange                 string     `json:"ipRange"`
	TrendingDays            flexString `json:"trendingDays"`
	TrendWithRaw            flexString `json:"trendWithRaw"`
	ActiveVulnsLifetime     flexString `json:"activeVulnsLifetime"`
	PassiveVulnsLifetime    flexString `json:"passiveVulnsLifetime"`
	LCEVulnsLifetime        flexString `json:"lceVulnsLifetime"`
	ComplianceVulnsLifetime flexString `json:"complianceVulnsLifetime"`
	MitigatedVulnsLifetime  flexString `json:"mitigatedVulnsLifetime"`
	Organizations           []idName   `json:"organizations"`
}

// RepositoryByName returns the one Local repository named name, or an
// error when there is none or more than one.
func (c *Client) RepositoryByName(ctx context.Context, name string) (*repositoryDef, error) {
	var list []repositoryDef
	if err := c.do(ctx, http.MethodGet, "/repository", url.Values{"fields": {repositoryFields}}, nil, 0, &list); err != nil {
		return nil, err
	}
	var found *repositoryDef
	for i := range list {
		if list[i].Name != name {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("more than one repository is named %q", name)
		}
		found = &list[i]
	}
	if found == nil {
		return nil, fmt.Errorf("no repository is named %q", name)
	}
	if !strings.EqualFold(found.Type, "Local") || numericID(string(found.ID)) == "" {
		return nil, fmt.Errorf("repository %q is not a local repository with an id", name)
	}
	return found, nil
}

// DeleteRepository deletes repository id and its data.
func (c *Client) DeleteRepository(ctx context.Context, id string) error {
	if numericID(id) == "" {
		return errors.New("tenable.sc: not a repository id")
	}
	return c.do(ctx, http.MethodDelete, "/repository/"+id, nil, nil, 0, nil)
}

// CreateRepository creates a repository with def's definition and returns
// its id.
func (c *Client) CreateRepository(ctx context.Context, def *repositoryDef) (string, error) {
	body := map[string]any{"name": def.Name, "description": def.Description, "type": "Local", "dataFormat": def.DataFormat}
	for k, v := range map[string]string{
		"ipRange": def.IPRange, "trendingDays": string(def.TrendingDays), "trendWithRaw": string(def.TrendWithRaw),
		"activeVulnsLifetime": string(def.ActiveVulnsLifetime), "passiveVulnsLifetime": string(def.PassiveVulnsLifetime),
		"lceVulnsLifetime": string(def.LCEVulnsLifetime), "complianceVulnsLifetime": string(def.ComplianceVulnsLifetime),
		"mitigatedVulnsLifetime": string(def.MitigatedVulnsLifetime),
	} {
		if v != "" {
			body[k] = v
		}
	}
	orgs := make([]map[string]string, 0, len(def.Organizations))
	for _, o := range def.Organizations {
		if id := numericID(string(o.ID)); id != "" {
			orgs = append(orgs, map[string]string{"id": id})
		}
	}
	body["organizations"] = orgs
	var r struct {
		ID flexString `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/repository", nil, body, 0, &r); err != nil {
		return "", err
	}
	id := numericID(string(r.ID))
	if id == "" {
		return "", errors.New("tenable.sc created a repository without a usable id")
	}
	return id, nil
}

// adminInstance is in with the recycle administrator keys: the client for
// repository changes only.
func adminInstance(in *Instance) *Instance {
	cp := *in
	cp.AccessKey, cp.SecretKey = in.Recycle.AdminAccessKey, in.Recycle.AdminSecretKey
	return &cp
}

// rotationRepository resolves (and, when asked, recycles) the instance's
// rotation repository and returns the id the scan uses. The repository is
// found by the configured name only; a payload never names it.
func (r *scanRun) rotationRepository(recycle bool) (int, error) {
	rc := r.job.inst.Recycle
	newClient := r.e.newClient
	if newClient == nil {
		newClient = NewClient
	}
	admin, err := newClient(adminInstance(r.job.inst))
	if err != nil {
		return 0, err
	}
	def, err := admin.RepositoryByName(r.ctx, rc.RepositoryName)
	if err != nil {
		return 0, fmt.Errorf("rotation repository: %w", err)
	}
	id := string(def.ID)
	if recycle {
		if err := admin.DeleteRepository(r.ctx, id); err != nil {
			return 0, fmt.Errorf("recycle rotation repository %q: delete: %w", rc.RepositoryName, err)
		}
		newID, err := admin.CreateRepository(r.ctx, def)
		if err != nil {
			// The data is gone and the repository is not back: the owner
			// must recreate it; every later batch fails until then.
			return 0, fmt.Errorf("recycle rotation repository %q: deleted but not recreated: %w", rc.RepositoryName, err)
		}
		r.e.logf("tenable.sc %s: rotation repository %q recycled (%s -> %s)", r.job.inst.Name, rc.RepositoryName, id, newID)
		r.recycledFrom = id
		id = newID
		// The licence count changed: read it again for the guard.
		r.license = nil
	}
	n, err := strconv.Atoi(id)
	if err != nil {
		return 0, fmt.Errorf("rotation repository id %q: %w", id, err)
	}
	return n, nil
}
