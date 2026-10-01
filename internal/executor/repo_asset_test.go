package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepoParseOptions(t *testing.T) {
	// Payload repository wins.
	o := repoParseOptions("/x", &vulnScanPayload{RepoURL: "github.com/o/r", Branch: "main", IsDefault: true})
	if o.AssetValue != "github.com/o/r" || o.BranchInfo == nil || !o.BranchInfo.IsDefaultBranch || o.BasePath != "/x" {
		t.Fatalf("payload: %+v", o)
	}

	// Else the git remote of the scanned directory.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "[remote \"origin\"]\n\turl = https://github.com/acme/shop.git\n"
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "src")
	_ = os.MkdirAll(sub, 0o700)
	o = repoParseOptions(sub, nil)
	if o.AssetValue == "" || o.AssetType != "repository" {
		t.Fatalf("git remote: %+v", o)
	}

	// No repository: no guessed asset.
	if o := repoParseOptions(t.TempDir(), nil); o.AssetValue != "" {
		t.Fatalf("invented an asset: %+v", o)
	}
}
