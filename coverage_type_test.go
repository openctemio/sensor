package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Every one-shot report states its coverage; full needs a completed scan of
// the repository root on the default branch.
func TestCoverageType(t *testing.T) {
	def := &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}
	feature := &ctis.BranchInfo{Name: "feature/x"}
	cases := []struct {
		name     string
		branch   *ctis.BranchInfo
		repoRoot bool
		scanErr  string
		want     string
	}{
		{"default branch, repo root, completed", def, true, "", "full"},
		{"default branch, subdirectory", def, false, "", "partial"},
		{"feature branch", feature, true, "", "partial"},
		{"no branch info", nil, true, "", "partial"},
		{"stopped part-way", def, true, "nuclei exited with code 1 (results are partial)", "partial"},
	}
	for _, tc := range cases {
		if got := coverageType(tc.branch, tc.repoRoot, tc.scanErr); got != tc.want {
			t.Errorf("%s: coverage %q, want %q", tc.name, got, tc.want)
		}
		if got := coverageType(tc.branch, tc.repoRoot, tc.scanErr); got == "" {
			t.Errorf("%s: coverage must never be empty", tc.name)
		}
	}
}
