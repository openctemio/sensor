// Package assetctx gives the SDK's converters the asset their findings belong
// to. Protocol v2 ingest accepts a finding only when it resolves to an asset
// of its own report (ctis.CheckFindingAssets), and there is no fallback asset
// on the server, so every converter names one or fails with
// ctis.ErrNoAssetForFindings.
package assetctx

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/cirepo"
)

// DefaultID is the asset ID a single-asset report uses when the caller does
// not choose one.
const DefaultID = "asset-1"

// Explicit returns the asset the caller named in opts: AssetValue (typed
// AssetType, a repository when unset), else BranchInfo.RepositoryURL. It
// returns false when opts names none.
func Explicit(opts *core.ParseOptions) (ctis.Asset, bool) {
	if opts == nil {
		return ctis.Asset{}, false
	}
	id := opts.AssetID
	if id == "" {
		id = DefaultID
	}

	if v := strings.TrimSpace(opts.AssetValue); v != "" {
		t := opts.AssetType
		if t == "" {
			t = ctis.AssetTypeRepository
		}
		return ctis.Asset{
			ID:          id,
			Type:        t,
			Value:       opts.AssetValue,
			Name:        opts.AssetValue,
			Criticality: ctis.CriticalityHigh,
			Properties:  ctis.Properties{"source": "parse_options"},
		}, true
	}

	if bi := opts.BranchInfo; bi != nil && strings.TrimSpace(bi.RepositoryURL) != "" {
		props := ctis.Properties{
			"source":            "branch_info",
			"auto_created":      true,
			"is_default_branch": bi.IsDefaultBranch,
		}
		if bi.CommitSHA != "" {
			props["commit_sha"] = bi.CommitSHA
		}
		if bi.Name != "" {
			props["branch"] = bi.Name
		}
		return ctis.Asset{
			ID:          id,
			Type:        ctis.AssetTypeRepository,
			Value:       bi.RepositoryURL,
			Name:        bi.RepositoryURL,
			Criticality: ctis.CriticalityHigh,
			Properties:  props,
		}, true
	}
	return ctis.Asset{}, false
}

// CI returns the repository the CI job (GitHub Actions, GitLab CI) is
// building as an asset with the given ID (DefaultID when empty), and false
// outside CI.
func CI(id string) (ctis.Asset, bool) {
	repo, ok := cirepo.Detect()
	if !ok {
		return ctis.Asset{}, false
	}
	return repoAsset(id, repo.URL, repo.Branch, repo.Commit, "ci_environment"), true
}

// Repository returns the repository a code scan described by opts ran over:
// the asset opts names (Explicit), else the CI job's repository (CI).
func Repository(opts *core.ParseOptions) (ctis.Asset, bool) {
	if a, ok := Explicit(opts); ok {
		return a, true
	}
	id := ""
	if opts != nil {
		id = opts.AssetID
	}
	return CI(id)
}

// AdapterRepository is Repository for core.AdapterOptions: the Repository
// option (with Branch and CommitSHA), else the CI job's repository.
func AdapterRepository(opts *core.AdapterOptions) (ctis.Asset, bool) {
	if a, ok := AdapterExplicit(opts); ok {
		return a, true
	}
	return CI(DefaultID)
}

// ScopeOptions maps ParseOptions to the AdapterOptions an adapter reads
// besides the asset (the report scope name), for the adapters' ParseToCTIS.
func ScopeOptions(opts *core.ParseOptions) *core.AdapterOptions {
	if opts == nil {
		return nil
	}
	ao := &core.AdapterOptions{Repository: opts.AssetValue}
	if opts.BranchInfo != nil && opts.BranchInfo.RepositoryURL != "" {
		ao.Repository = opts.BranchInfo.RepositoryURL
	}
	return ao
}

// AdapterExplicit returns the repository the Repository option names (with
// Branch and CommitSHA), and false when it is empty.
func AdapterExplicit(opts *core.AdapterOptions) (ctis.Asset, bool) {
	if opts != nil && strings.TrimSpace(opts.Repository) != "" {
		return repoAsset(DefaultID, opts.Repository, opts.Branch, opts.CommitSHA, "adapter_options"), true
	}
	return ctis.Asset{}, false
}

// TrivyArtifact returns the asset a Trivy report's artifact names by itself:
// the image of a container_image scan, or the remote repository of a
// repository scan. A filesystem scan's ArtifactName is a local path, not an
// asset, so it returns false, as for any other artifact type.
func TrivyArtifact(artifactType, artifactName string) (ctis.Asset, bool) {
	name := strings.TrimSpace(artifactName)
	if name == "" {
		return ctis.Asset{}, false
	}
	var t ctis.AssetType
	switch artifactType {
	case "container_image":
		t = ctis.AssetTypeContainer
	case "repository":
		t = ctis.AssetTypeRepository
	default:
		return ctis.Asset{}, false
	}
	return ctis.Asset{
		ID:         DefaultID,
		Type:       t,
		Value:      name,
		Name:       name,
		Properties: ctis.Properties{"source": "trivy_artifact"},
	}, true
}

func repoAsset(id, value, branch, commit, source string) ctis.Asset {
	if id == "" {
		id = DefaultID
	}
	props := ctis.Properties{"source": source}
	if branch != "" {
		props["branch"] = branch
	}
	if commit != "" {
		props["commit_sha"] = commit
	}
	return ctis.Asset{
		ID:          id,
		Type:        ctis.AssetTypeRepository,
		Value:       value,
		Name:        value,
		Criticality: ctis.CriticalityHigh,
		Properties:  props,
	}
}

// Bind adds a to r and points every finding of r at it. Use it for
// converters whose findings all belong to one asset (a repository, an
// image, a host).
func Bind(r *ctis.Report, a ctis.Asset) {
	if a.ID == "" {
		a.ID = DefaultID
	}
	r.Assets = append(r.Assets, a)
	for i := range r.Findings {
		r.Findings[i].AssetRef = a.ID
	}
}

// BindOrFail binds r's findings to a when ok, and otherwise returns the
// ErrNoAssetForFindings error for tool if r has findings. A report with no
// finding and no asset is fine.
func BindOrFail(r *ctis.Report, a ctis.Asset, ok bool, tool string) error {
	if ok {
		Bind(r, a)
		return nil
	}
	if len(r.Findings) == 0 {
		return nil
	}
	return NoRepository(tool, len(r.Findings))
}

// NoRepository is the error a code converter returns when it has findings
// but no repository to file them on.
func NoRepository(tool string, findings int) error {
	return fmt.Errorf("%w: %s reported %d finding(s) but no repository is known: "+
		"pass the scanned repository (ParseOptions.AssetValue or BranchInfo.RepositoryURL) "+
		"or run inside GitHub Actions / GitLab CI", ctis.ErrNoAssetForFindings, tool, findings)
}

// Hosts adds one asset per distinct network target to a report, for
// converters whose findings each name their own host (nuclei).
type Hosts struct {
	r     *ctis.Report
	byKey map[string]string
}

// NewHosts returns a Hosts adding to r.
func NewHosts(r *ctis.Report) *Hosts {
	return &Hosts{r: r, byKey: make(map[string]string)}
}

// Ref returns the ID of the asset for target (a host name, an IP address, a
// host:port or a URL), adding the asset on first use. It returns "" when
// target names no host.
func (h *Hosts) Ref(target string) string {
	t, v := HostAsset(target)
	if v == "" {
		return ""
	}
	key := string(t) + "\x00" + v
	if id, ok := h.byKey[key]; ok {
		return id
	}
	id := fmt.Sprintf("asset-%d", len(h.byKey)+1)
	h.byKey[key] = id
	h.r.Assets = append(h.r.Assets, ctis.Asset{ID: id, Type: t, Value: v, Name: v})
	return id
}

// HostAsset returns the asset type and value of a network target: the host
// name of a URL or host:port, typed ip_address for an IP and domain
// otherwise. The value is "" when target names no host.
func HostAsset(target string) (ctis.AssetType, string) {
	s := strings.TrimSpace(target)
	if s == "" {
		return "", ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	} else {
		if i := strings.IndexAny(s, "/?#"); i >= 0 {
			s = s[:i]
		}
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		}
	}
	s = strings.TrimSuffix(strings.Trim(s, "[]"), ".")
	if s == "" {
		return "", ""
	}
	if net.ParseIP(s) != nil {
		return ctis.AssetTypeIPAddress, s
	}
	return ctis.AssetTypeDomain, strings.ToLower(s)
}
