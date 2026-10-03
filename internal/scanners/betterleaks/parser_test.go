package betterleaks

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/assetctx"
)

func TestParser_CreateAssetFromOptions(t *testing.T) {

	tests := []struct {
		name          string
		opts          *core.ParseOptions
		wantAsset     bool
		wantAssetName string
		wantAssetType ctis.AssetType
	}{
		{
			name:      "nil options returns nil asset",
			opts:      nil,
			wantAsset: false,
		},
		{
			name:      "empty options returns nil asset",
			opts:      &core.ParseOptions{},
			wantAsset: false,
		},
		{
			name: "AssetValue creates asset",
			opts: &core.ParseOptions{
				AssetValue: "github.com/org/repo",
				AssetType:  ctis.AssetTypeRepository,
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ctis.AssetTypeRepository,
		},
		{
			name: "BranchInfo creates asset when AssetValue is empty",
			opts: &core.ParseOptions{
				BranchInfo: &ctis.BranchInfo{
					RepositoryURL:   "github.com/org/repo",
					Name:            "main",
					CommitSHA:       "abc123",
					IsDefaultBranch: true,
				},
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ctis.AssetTypeRepository,
		},
		{
			name: "AssetValue takes priority over BranchInfo",
			opts: &core.ParseOptions{
				AssetValue: "explicit-asset",
				AssetType:  ctis.AssetTypeContainer,
				BranchInfo: &ctis.BranchInfo{
					RepositoryURL: "github.com/org/repo",
				},
			},
			wantAsset:     true,
			wantAssetName: "explicit-asset",
			wantAssetType: ctis.AssetTypeContainer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := explicitAsset(tt.opts)

			if tt.wantAsset {
				if asset == nil {
					t.Fatalf("expected asset, got nil")
				}
				if asset.Name != tt.wantAssetName {
					t.Errorf("asset name = %q, want %q", asset.Name, tt.wantAssetName)
				}
				if asset.Type != tt.wantAssetType {
					t.Errorf("asset type = %q, want %q", asset.Type, tt.wantAssetType)
				}
			} else {
				if asset != nil {
					t.Errorf("expected nil asset, got %+v", asset)
				}
			}
		})
	}
}

func TestParser_ParseWithAssetFromBranchInfo(t *testing.T) {
	parser := &Parser{}

	// Empty gitleaks output (no findings)
	data := []byte(`[]`)

	opts := &core.ParseOptions{
		BranchInfo: &ctis.BranchInfo{
			RepositoryURL:   "github.com/myorg/myrepo",
			Name:            "feature-branch",
			CommitSHA:       "abc123def456",
			IsDefaultBranch: false,
		},
	}

	report, err := parser.Parse(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(report.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(report.Assets))
	}

	asset := report.Assets[0]
	if asset.Value != "github.com/myorg/myrepo" {
		t.Errorf("asset value = %q, want %q", asset.Value, "github.com/myorg/myrepo")
	}
	if asset.Type != ctis.AssetTypeRepository {
		t.Errorf("asset type = %q, want %q", asset.Type, ctis.AssetTypeRepository)
	}

	// Verify properties
	if asset.Properties["source"] != "branch_info" {
		t.Errorf("asset source = %v, want branch_info", asset.Properties["source"])
	}
	if asset.Properties["branch"] != "feature-branch" {
		t.Errorf("asset branch = %v, want feature-branch", asset.Properties["branch"])
	}
	if asset.Properties["commit_sha"] != "abc123def456" {
		t.Errorf("asset commit_sha = %v, want abc123def456", asset.Properties["commit_sha"])
	}
}

// TestConvertFinding_RelativePathAndFingerprint locks in that a finding scanned
// from a mounted checkout is reported with a repo-relative path AND a mount-
// independent fingerprint — the two must move together, else the same secret
// dedupes inconsistently across scans from different mount points.
func TestConvertFinding_RelativePathAndFingerprint(t *testing.T) {
	parser := &Parser{}
	opts := &core.ParseOptions{BasePath: "/scan"}

	f := Finding{
		Description: "Generic API Key",
		RuleID:      "generic-api-key",
		File:        "/scan/config/secrets.yaml",
		StartLine:   57,
		Secret:      "AKIA_EXAMPLE_SECRET",
		// gitleaks embeds the path it was given (the absolute mount) in its own
		// fingerprint — this is the segment that must be rewritten.
		Fingerprint: "/scan/config/secrets.yaml:generic-api-key:57",
	}

	got := parser.convertFinding(f, 0, opts)

	if got.Location == nil || got.Location.Path != "config/secrets.yaml" {
		t.Fatalf("path = %v, want repo-relative config/secrets.yaml", got.Location)
	}
	if want := "config/secrets.yaml:generic-api-key:57"; got.Fingerprint != want {
		t.Errorf("fingerprint = %q, want mount-independent %q", got.Fingerprint, want)
	}
}

// TestConvertFinding_NoBasePath leaves paths untouched when no mount root is
// known (e.g. a direct local scan), so nothing regresses for non-mounted runs.
func TestConvertFinding_NoBasePath(t *testing.T) {
	parser := &Parser{}
	f := Finding{
		RuleID:      "generic-api-key",
		File:        "config/secrets.yaml",
		StartLine:   57,
		Fingerprint: "config/secrets.yaml:generic-api-key:57",
	}
	got := parser.convertFinding(f, 0, &core.ParseOptions{})
	if got.Location.Path != "config/secrets.yaml" {
		t.Errorf("path = %q, want unchanged", got.Location.Path)
	}
	if got.Fingerprint != "config/secrets.yaml:generic-api-key:57" {
		t.Errorf("fingerprint = %q, want unchanged", got.Fingerprint)
	}
}

// explicitAsset is the asset the parser files findings on when opts names
// one (CI detection aside).
func explicitAsset(opts *core.ParseOptions) *ctis.Asset {
	a, ok := assetctx.Explicit(opts)
	if !ok {
		return nil
	}
	return &a
}
