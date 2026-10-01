package executor

import (
	"path/filepath"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/git"
)

// repoParseOptions are the parse options of a code scan: BasePath for
// repo-relative paths and snippets, and the repository the findings belong
// to, from the job payload (repo_url, branch) or else from the git remote of
// the scanned directory. Without a repository the SDK's code parsers refuse
// findings they cannot file on an asset (protocol v2 rejects those).
func repoParseOptions(targetPath string, payload *vulnScanPayload) *core.ParseOptions {
	opts := &core.ParseOptions{BasePath: targetPath}
	if payload != nil && payload.RepoURL != "" {
		opts.AssetType = ctis.AssetTypeRepository
		opts.AssetValue = payload.RepoURL
		opts.BranchInfo = &ctis.BranchInfo{
			RepositoryURL:   payload.RepoURL,
			Name:            payload.Branch,
			CommitSHA:       payload.CommitSHA,
			IsDefaultBranch: payload.IsDefault,
		}
		return opts
	}
	if targetPath == "" {
		return opts
	}
	if root := git.FindRoot(targetPath); root != "" {
		if remote := git.ReadRemoteURL(filepath.Join(root, ".git", "config")); remote != "" {
			opts.AssetType = ctis.AssetTypeRepository
			opts.AssetValue = git.NormalizeURL(remote)
		}
	}
	return opts
}
