package trivy

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

func TestParser_CreateAssetFromContext(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name          string
		report        *Report
		opts          *core.ParseOptions
		wantAsset     bool
		wantAssetName string
		wantAssetType ctis.AssetType
	}{
		{
			name:      "nil options and empty report returns nil asset",
			report:    &Report{},
			opts:      nil,
			wantAsset: false,
		},
		{
			name: "AssetValue takes priority over artifact",
			report: &Report{
				ArtifactName: "myimage:latest",
				ArtifactType: "container_image",
			},
			opts: &core.ParseOptions{
				AssetValue: "github.com/org/repo",
				AssetType:  ctis.AssetTypeRepository,
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ctis.AssetTypeRepository,
		},
		{
			name: "BranchInfo takes priority over artifact",
			report: &Report{
				ArtifactName: "myimage:latest",
				ArtifactType: "container_image",
			},
			opts: &core.ParseOptions{
				BranchInfo: &ctis.BranchInfo{
					RepositoryURL:   "github.com/org/repo",
					Name:            "main",
					IsDefaultBranch: true,
				},
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ctis.AssetTypeRepository,
		},
		{
			name: "falls back to artifact when no options",
			report: &Report{
				ArtifactName: "myimage:latest",
				ArtifactType: "container_image",
			},
			opts:          nil,
			wantAsset:     true,
			wantAssetName: "myimage:latest",
			wantAssetType: ctis.AssetTypeContainer,
		},
		{
			name: "falls back to a remote repository artifact",
			report: &Report{
				ArtifactName: "https://github.com/org/repo",
				ArtifactType: "repository",
			},
			opts:          &core.ParseOptions{},
			wantAsset:     true,
			wantAssetName: "https://github.com/org/repo",
			wantAssetType: ctis.AssetTypeRepository,
		},
		{
			// The local path of a filesystem scan is not an asset: it used
			// to become a fake repository named "." (or the mount path).
			name: "filesystem artifact is not an asset",
			report: &Report{
				ArtifactName: ".",
				ArtifactType: "filesystem",
			},
			opts:      &core.ParseOptions{},
			wantAsset: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := parser.createAssetFromContext(tt.report, tt.opts)

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
	parser := NewParser()

	// Minimal trivy output
	data := []byte(`{"SchemaVersion": 2, "Results": []}`)

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

	// Verify properties
	if asset.Properties["source"] != "branch_info" {
		t.Errorf("asset source = %v, want branch_info", asset.Properties["source"])
	}
}
