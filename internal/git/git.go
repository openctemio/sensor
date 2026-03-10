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
