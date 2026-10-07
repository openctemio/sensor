// Package importparse reads the native output of the sensor's scanners
// (nuclei, semgrep, trivy, betterleaks) with ctis/importer: one parser
// library for every OpenCTEM component, fuzzed, size- and depth-limited,
// with a field-by-field mapping spec per format and secret values masked in
// every field. The sensor keeps no converter of its own.
//
// What the sensor adds is what only it knows: the asset the scan ran on
// (the repository it checked out, the target it was given, the CI job's
// repository) and the branch context. A report whose findings have no such
// asset is refused (ctis.ErrNoAssetForFindings) rather than filed on a
// made-up one.
package importparse

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/assetctx"
)

// Parser is a core.Parser over one ctis/importer format.
type Parser struct {
	name   string
	format importer.Format
	// code: the findings belong to the scanned repository (semgrep,
	// betterleaks, a trivy file-system scan).
	code bool
}

// The sensor's scanner parsers.
var (
	_ core.Parser = (*Parser)(nil)
)

// Nuclei reads nuclei JSON Lines.
func Nuclei() *Parser { return &Parser{name: "nuclei", format: importer.FormatNuclei} }

// Semgrep reads semgrep JSON.
func Semgrep() *Parser {
	return &Parser{name: "semgrep", format: importer.FormatSemgrep, code: true}
}

// Trivy reads trivy JSON (file-system, repository and image scans).
func Trivy() *Parser { return &Parser{name: "trivy", format: importer.FormatTrivy} }

// Betterleaks reads betterleaks (and gitleaks) JSON, reported under the
// betterleaks name: the platform keeps one secret-scanner identity.
func Betterleaks() *Parser {
	return &Parser{name: core.ScannerBetterleaks, format: importer.FormatBetterleaks, code: true}
}

// Name is the scanner the parser reads.
func (p *Parser) Name() string { return p.name }

// SupportedFormats names the importer format.
func (p *Parser) SupportedFormats() []string { return []string{string(p.format)} }

// CanParse reports whether data starts like the parser's format. gitleaks
// output is accepted where betterleaks is (the same report shape).
func (p *Parser) CanParse(data []byte) bool {
	f, ok := importer.Detect(data)
	if !ok {
		return false
	}
	if p.format == importer.FormatBetterleaks && f == importer.FormatGitleaks {
		return true
	}
	return f == p.format
}

// Parse converts the scanner's output to CTIS.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	if IsToolReport(data, p.name) {
		return readToolReport(data, opts, p.name)
	}
	io := importer.Options{Format: p.format, ToolName: p.name, SourceType: "scanner"}
	asset, haveAsset := p.asset(opts)
	if haveAsset {
		a := asset
		io.DefaultAsset = &a
		if a.Type == ctis.AssetTypeRepository && (p.code || p.format == importer.FormatTrivy) {
			io.Repository = a.Value
			io.Branch, io.CommitSHA = branchOf(opts, a)
		}
	}
	res, err := importer.Parse(ctx, bytes.NewReader(data), io)
	if err != nil {
		return nil, fmt.Errorf("%s output: %w", p.name, err)
	}
	r := res.Report
	if st := res.Stats; st.Records > 0 && st.Skipped == st.Records && len(r.Findings) == 0 {
		msg := "no record is usable"
		if len(res.Issues) > 0 {
			msg = res.Issues[0].Message
		}
		return nil, fmt.Errorf("%s output: %d record(s) and none usable (%s)", p.name, st.Records, msg)
	}
	if p.format == importer.FormatNuclei {
		nucleiPostProcess(r, data)
	}
	if !haveAsset && hasFallbackAsset(r) {
		return nil, assetctx.NoRepository(p.name, len(r.Findings))
	}
	if opts != nil {
		if opts.BranchInfo != nil {
			bi := *opts.BranchInfo
			r.Metadata.Branch = &bi
		} else if opts.Branch != "" || opts.CommitSHA != "" {
			r.Metadata.Branch = &ctis.BranchInfo{Name: opts.Branch, CommitSHA: opts.CommitSHA}
		}
		if opts.BasePath != "" {
			stripBase(r, opts.BasePath)
		}
	}
	return r, nil
}

// asset is the asset the scan ran on, as only the sensor knows it: the one
// the caller names, else (for a code scan) the CI job's repository. A
// nuclei target is typed by its value (a URL, a host, an address).
func (p *Parser) asset(opts *core.ParseOptions) (ctis.Asset, bool) {
	a, ok := assetctx.Explicit(opts)
	if ok && p.format == importer.FormatNuclei && opts.AssetType == "" {
		a.Type, a.Value = assetctx.HostAsset(opts.AssetValue)
		a.Name = a.Value
	}
	if !ok && (p.code || p.format == importer.FormatTrivy) {
		id := ""
		if opts != nil {
			id = opts.AssetID
		}
		a, ok = assetctx.CI(id)
	}
	return a, ok
}

func branchOf(opts *core.ParseOptions, a ctis.Asset) (branch, commit string) {
	if opts != nil {
		if bi := opts.BranchInfo; bi != nil {
			return bi.Name, bi.CommitSHA
		}
		if opts.Branch != "" || opts.CommitSHA != "" {
			return opts.Branch, opts.CommitSHA
		}
	}
	b, _ := a.Properties["branch"].(string)
	c, _ := a.Properties["commit_sha"].(string)
	return b, c
}

// hasFallbackAsset reports whether the importer had to file findings on its
// unclassified stand-in asset: the output named none and the sensor knew
// none.
func hasFallbackAsset(r *ctis.Report) bool {
	if r == nil || len(r.Findings) == 0 {
		return false
	}
	for _, a := range r.Assets {
		if a.Type == ctis.AssetTypeUnclassified {
			return true
		}
	}
	return false
}

// stripBase makes file paths relative to the scanned tree: a path under the
// scan root ("/scan/app/main.go") becomes "app/main.go", so the location
// (and the fingerprint the platform derives from it) does not depend on
// where the repository was checked out.
func stripBase(r *ctis.Report, base string) {
	prefix := strings.TrimSuffix(base, "/") + "/"
	trim := func(p string) string { return strings.TrimPrefix(p, prefix) }
	for i := range r.Findings {
		f := &r.Findings[i]
		if l := f.Location; l != nil {
			l.Path = trim(l.Path)
		}
		f.Fingerprint = trim(f.Fingerprint)
	}
	for i := range r.Dependencies {
		d := &r.Dependencies[i]
		d.Path = trim(d.Path)
		if d.Location != nil {
			d.Location.Path = trim(d.Location.Path)
		}
		for j := range d.Locations {
			d.Locations[j].Path = trim(d.Locations[j].Path)
		}
	}
}
