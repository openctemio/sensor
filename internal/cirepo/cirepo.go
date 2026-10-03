// Package cirepo reads the repository a CI job is building from the CI
// environment (GitHub Actions, GitLab CI), for converters that must name the
// repository their findings belong to when the caller did not.
package cirepo

import "github.com/openctemio/sdk-go/pkg/gitenv"

// Repo is a repository and the revision a CI job checked out.
type Repo struct {
	// URL is the canonical repository name, e.g. github.com/org/repo: the
	// value the sensor uses for repository assets.
	URL    string
	Branch string
	Commit string
}

// Detect returns the repository of the CI job this process runs in, and
// false outside CI or when the CI environment names no repository.
func Detect() (Repo, bool) {
	env := gitenv.Detect()
	if env == nil {
		return Repo{}, false
	}
	url := env.CanonicalRepoName()
	if url == "" {
		url = env.ProjectName()
	}
	if url == "" {
		return Repo{}, false
	}
	return Repo{URL: url, Branch: env.CommitBranch(), Commit: env.CommitSha()}, true
}
