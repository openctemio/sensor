// Package strategy provides scan strategy determination for security scanning.
// It supports AllFiles (full scan) and ChangedFileOnly (differential scan) modes.
package strategy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/gitenv"
)

// ScanStrategy represents how files should be scanned.
type ScanStrategy int

const (
	// AllFiles scans all files in the repository
	AllFiles ScanStrategy = iota
	// ChangedFileOnly scans only files that changed between commits
	ChangedFileOnly
)

// String returns the string representation of the strategy.
func (s ScanStrategy) String() string {
	switch s {
	case AllFiles:
		return "all_files"
	case ChangedFileOnly:
		return "changed_files_only"
	default:
		return "unknown"
	}
}

// MaxChangedFiles is the threshold for switching from ChangedFileOnly to AllFiles.
// If more files have changed, a full scan is more efficient.
const MaxChangedFiles = 512

// ChangedFile represents a file that was changed between commits.
type ChangedFile struct {
	Path    string       // File path relative to repo root
	Status  ChangeStatus // Type of change
	OldPath string       // Previous path (for renames)
}

// ChangeStatus represents the type of file change.
type ChangeStatus string

const (
	ChangeAdded    ChangeStatus = "added"
	ChangeModified ChangeStatus = "modified"
	ChangeDeleted  ChangeStatus = "deleted"
	ChangeRenamed  ChangeStatus = "renamed"
)

// ScanContext holds the context for determining scan strategy.
type ScanContext struct {
	GitEnv            gitenv.GitEnv
	BaselineCommitSha string
	RepoPath          string
	MaxChangedFiles   int
	Verbose           bool
}

// DetermineStrategy determines the scan strategy based on context.
func DetermineStrategy(ctx *ScanContext) (ScanStrategy, []ChangedFile) {
	if ctx == nil {
		return AllFiles, nil
	}

	maxFiles := ctx.MaxChangedFiles
	if maxFiles == 0 {
		maxFiles = MaxChangedFiles
	}

	// If no git environment or not in MR/PR context, scan all files
	if ctx.GitEnv == nil {
		if ctx.Verbose {
			fmt.Println("[strategy] No git environment, using AllFiles strategy")
		}
		return AllFiles, nil
	}

	// Determine baseline commit
	baselineSha := ctx.BaselineCommitSha
	if baselineSha == "" {
		// In MR/PR context, use target branch SHA
		if ctx.GitEnv.MergeRequestID() != "" {
			baselineSha = ctx.GitEnv.TargetBranchSha()
		}
	}

	if baselineSha == "" {
		if ctx.Verbose {
			fmt.Println("[strategy] No baseline commit, using AllFiles strategy")
		}
		return AllFiles, nil
	}

	currentSha := ctx.GitEnv.CommitSha()
	if currentSha == "" || currentSha == baselineSha {
		if ctx.Verbose {
			fmt.Println("[strategy] Same commit as baseline, using AllFiles strategy")
		}
		return AllFiles, nil
	}

	// Get changed files between commits
	changedFiles, err := GetChangedFiles(ctx.RepoPath, currentSha, baselineSha)
	if err != nil {
		if ctx.Verbose {
			fmt.Printf("[strategy] Failed to get changed files: %v, using AllFiles strategy\n", err)
		}
		return AllFiles, nil
	}

	if len(changedFiles) == 0 {
		if ctx.Verbose {
			fmt.Println("[strategy] No changed files detected, using AllFiles strategy")
		}
		return AllFiles, nil
	}

	// If too many files changed, scan all
	if len(changedFiles) >= maxFiles {
		if ctx.Verbose {
			fmt.Printf("[strategy] Too many changed files (%d >= %d), using AllFiles strategy\n", len(changedFiles), maxFiles)
		}
		return AllFiles, nil
	}

	if ctx.Verbose {
		fmt.Printf("[strategy] %d changed files detected, using ChangedFileOnly strategy\n", len(changedFiles))
	}
	return ChangedFileOnly, changedFiles
}

// GetChangedFiles returns the list of changed files between two commits.
func GetChangedFiles(repoPath, currentSha, baselineSha string) ([]ChangedFile, error) {
	// Run git diff to get changed files
	args := []string{"diff", "--name-status", baselineSha, currentSha}
	cmd := exec.Command("git", args...)
	if repoPath != "" {
		cmd.Dir = repoPath
	}
	// git runs in the scanned repository, whose configuration can run
	// commands: it gets the scanner environment (never the sensor's API key
	// or other credentials), plus the variables that locate the repository
	// and its configuration.
	cmd.Env = core.ScannerEnviron(gitLocationEnv(os.Environ()))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff failed: %w (stderr: %s)", err, stderr.String())
	}

	return parseGitDiffOutput(stdout.String()), nil
}

// gitLocationEnv is the subset of env that tells git where the repository
// and its configuration are (a CI runner may set them; safe.directory often
// arrives as GIT_CONFIG_COUNT/KEY/VALUE).
func gitLocationEnv(env []string) map[string]string {
	out := map[string]string{}
	for _, kv := range env {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch {
		case name == "GIT_DIR", name == "GIT_WORK_TREE", name == "GIT_CEILING_DIRECTORIES",
			name == "GIT_DISCOVERY_ACROSS_FILESYSTEM", name == "GIT_CONFIG_GLOBAL",
			name == "GIT_CONFIG_SYSTEM", name == "GIT_CONFIG_NOSYSTEM", name == "GIT_CONFIG_COUNT",
			strings.HasPrefix(name, "GIT_CONFIG_KEY_"), strings.HasPrefix(name, "GIT_CONFIG_VALUE_"):
			out[name] = value
		}
	}
	return out
}

// parseGitDiffOutput parses the output of git diff --name-status.
func parseGitDiffOutput(output string) []ChangedFile {
	var files []ChangedFile
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		status := parts[0]
		path := parts[1]
		oldPath := ""

		// Handle renames (Rxx format)
		if strings.HasPrefix(status, "R") && len(parts) >= 3 {
			oldPath = parts[1]
			path = parts[2]
			status = "R"
		}

		var changeStatus ChangeStatus
		switch status[0] {
		case 'A':
			changeStatus = ChangeAdded
		case 'M':
			changeStatus = ChangeModified
		case 'D':
			changeStatus = ChangeDeleted
		case 'R':
			changeStatus = ChangeRenamed
		default:
			changeStatus = ChangeModified
		}

		files = append(files, ChangedFile{
			Path:    path,
			Status:  changeStatus,
			OldPath: oldPath,
		})
	}

	return files
}

// FilterByExtensions filters changed files by file extensions.
func FilterByExtensions(files []ChangedFile, extensions []string) []ChangedFile {
	if len(extensions) == 0 {
		return files
	}

	extMap := make(map[string]bool)
	for _, ext := range extensions {
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		extMap[strings.ToLower(ext)] = true
	}

	var filtered []ChangedFile
	for _, f := range files {
		// Skip deleted files
		if f.Status == ChangeDeleted {
			continue
		}

		ext := strings.ToLower(getExtension(f.Path))
		if extMap[ext] {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// getExtension returns the file extension.
func getExtension(path string) string {
	lastDot := strings.LastIndex(path, ".")
	if lastDot == -1 {
		return ""
	}
	return path[lastDot:]
}

// GetPaths extracts file paths from changed files.
func GetPaths(files []ChangedFile) []string {
	paths := make([]string, 0, len(files))
	for _, f := range files {
		if f.Status != ChangeDeleted {
			paths = append(paths, f.Path)
		}
	}
	return paths
}

// ContainsPath checks if a path is in the changed files list.
func ContainsPath(files []ChangedFile, path string) bool {
	for _, f := range files {
		if f.Path == path || f.OldPath == path {
			return true
		}
	}
	return false
}
