// Package git provides git-related utilities for the agent.
package git

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// FindRoot walks up the directory tree to find the git root (directory containing .git).
func FindRoot(startPath string) string {
	current := startPath

	// Walk up to find .git directory (max 20 levels to avoid infinite loop)
	for i := 0; i < 20; i++ {
		gitPath := filepath.Join(current, ".git")
		if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
			return current
		}

		// Move to parent directory
		parent := filepath.Dir(current)
		if parent == current {
			// Reached root, no git repo found
			break
		}
		current = parent
	}

	return ""
}

// ReadRemoteURL reads the origin remote URL from a git config file.
func ReadRemoteURL(configPath string) string {
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer file.Close() //nolint:errcheck // read-only file

	scanner := bufio.NewScanner(file)
	inRemoteOrigin := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[remote \"origin\"]" {
			inRemoteOrigin = true
			continue
		}

		if inRemoteOrigin {
			if strings.HasPrefix(line, "[") {
				// Reached next section
				break
			}
			if strings.HasPrefix(line, "url = ") {
				return strings.TrimPrefix(line, "url = ")
			}
		}
	}

	return ""
}

// NormalizeURL normalizes a git URL to a standard format.
// Converts SSH URLs to HTTPS-like format: git@github.com:org/repo.git -> github.com/org/repo
func NormalizeURL(url string) string {
	// Convert SSH URLs to HTTPS-like format
	if after, ok := strings.CutPrefix(url, "git@"); ok {
		url = after
		url = strings.Replace(url, ":", "/", 1)
	}

	// Remove https:// or http://
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Remove .git suffix
	url = strings.TrimSuffix(url, ".git")

	// Remove trailing slash
	url = strings.TrimSuffix(url, "/")

	return url
}

// DetectBranch detects the current git branch from a target directory.
// It walks up the directory tree to find the git root.
func DetectBranch(target string) string {
	// Resolve to absolute path
	absPath, err := filepath.Abs(target)
	if err != nil {
		absPath = target
	}

	// Walk up to find git root
	gitRoot := FindRoot(absPath)
	if gitRoot == "" {
		return ""
	}

	// Try to read .git/HEAD file
	headPath := filepath.Join(gitRoot, ".git", "HEAD")
	content, err := os.ReadFile(headPath)
	if err != nil {
		return ""
	}

	headContent := strings.TrimSpace(string(content))

	// HEAD file contains either:
	// 1. "ref: refs/heads/branch-name" (normal branch)
	// 2. A commit hash (detached HEAD)
	if after, ok := strings.CutPrefix(headContent, "ref: refs/heads/"); ok {
		return after
	}

	// Detached HEAD - return short commit hash
	if len(headContent) >= 7 {
		return headContent[:7]
	}

	return ""
}

// DetectDefaultBranch returns the repository's default branch (e.g. "main"),
// read from .git/refs/remotes/origin/HEAD when present (set by `git clone` /
// `git remote set-head`). Falls back to a local main/master branch. Returns ""
// when it cannot be determined — callers must treat "" as "unknown", never as
// "this is the default branch" (that gates auto-resolve, which must fail safe).
func DetectDefaultBranch(target string) string {
	absPath, err := filepath.Abs(target)
	if err != nil {
		absPath = target
	}
	gitRoot := FindRoot(absPath)
	if gitRoot == "" {
		return ""
	}

	// origin/HEAD symref points at the remote's default branch.
	headPath := filepath.Join(gitRoot, ".git", "refs", "remotes", "origin", "HEAD")
	if content, err := os.ReadFile(headPath); err == nil {
		s := strings.TrimSpace(string(content))
		if after, ok := strings.CutPrefix(s, "ref: refs/remotes/origin/"); ok && after != "" {
			return after
		}
	}

	// Fallback: a local main/master branch (shallow clones may lack origin/HEAD).
	for _, cand := range []string{"main", "master"} {
		if _, err := os.Stat(filepath.Join(gitRoot, ".git", "refs", "heads", cand)); err == nil {
			return cand
		}
	}
	return ""
}

// IsRepoRoot reports whether target resolves to the git root itself (a
// whole-repo scan) rather than a subdirectory. Used to gate full-coverage:
// auto-resolve may only conclude a finding is gone from a scan that covered the
// whole repo, never a subdirectory scan.
func IsRepoRoot(target string) bool {
	absPath, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	gitRoot := FindRoot(absPath)
	if gitRoot == "" {
		return false
	}
	rootAbs, err := filepath.Abs(gitRoot)
	if err != nil {
		return false
	}
	return filepath.Clean(absPath) == filepath.Clean(rootAbs)
}
