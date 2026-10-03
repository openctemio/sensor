package semgrep

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
					RepositoryURL:   "gitlab.com/mygroup/myproject",
					Name:            "develop",
					CommitSHA:       "def456",
					IsDefaultBranch: false,
				},
			},
			wantAsset:     true,
			wantAssetName: "gitlab.com/mygroup/myproject",
			wantAssetType: ctis.AssetTypeRepository,
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

	// Minimal semgrep output (no findings)
	data := []byte(`{"version": "1.0.0", "results": []}`)

	opts := &core.ParseOptions{
		BranchInfo: &ctis.BranchInfo{
			RepositoryURL:   "github.com/myorg/myrepo",
			Name:            "main",
			CommitSHA:       "abc123",
			IsDefaultBranch: true,
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
