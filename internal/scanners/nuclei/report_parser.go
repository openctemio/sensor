package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ReportParser adapts nuclei's JSON Lines output to core.Parser, so command
// executors and parser registries can convert nuclei results. Register it next
// to the other scanner parsers:
//
//	registry.Register(&nuclei.ReportParser{})
//
// Without it, a server-dispatched nuclei scan had no parser: its output fell
// through to the SARIF parser, which either failed on the JSON Lines stream or,
// for a single result, read the line as an empty SARIF log and reported 0
// findings while nuclei had matched.
type ReportParser struct {
	Verbose bool
}

var _ core.Parser = (*ReportParser)(nil)

// Name returns the parser name; it matches the nuclei scanner's name, so an
// executor picks this parser for nuclei output first.
func (p *ReportParser) Name() string { return "nuclei" }

// SupportedFormats returns the output formats this parser handles.
func (p *ReportParser) SupportedFormats() []string { return []string{"jsonl", "nuclei-jsonl"} }

// CanParse reports whether data is nuclei JSON Lines: at least one line, and
// every non-empty line a JSON object carrying a template-id.
func (p *ReportParser) CanParse(data []byte) bool {
	if isToolReport(data) {
		return true
	}
	results, rejected, err := splitResults(data)
	return err == nil && rejected == 0 && len(results) > 0
}

// Parse converts nuclei JSON Lines output to a CTIS report. A stream with
// content but no readable nuclei result is an error, never an empty report.
//
// The out-of-process path's output is already a CTIS report (assembled and
// checked by the tool runtime); it is read as it is.
func (p *ReportParser) Parse(_ context.Context, data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	if isToolReport(data) {
		return parseToolReport(data, opts)
	}
	results, rejected, err := splitResults(data)
	if err != nil {
		return nil, fmt.Errorf("read nuclei output: %w", err)
	}
	if len(results) == 0 && rejected > 0 {
		return nil, fmt.Errorf("nuclei output has %d line(s) and none is a nuclei JSON result", rejected)
	}
	if rejected > 0 && p.Verbose {
		fmt.Printf("[nuclei-parser] skipped %d line(s) that are not nuclei JSON results\n", rejected)
	}
	report := (&Parser{Verbose: p.Verbose}).ParseResultsWithOptions(results, "", opts)
	// Every finding is filed on the host it matched (or the scan target);
	// a result naming neither is an error, never a finding without an asset.
	if err := ctis.CheckFindingAssets(report); err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}
	return report, nil
}

// splitResults decodes every non-empty line. rejected counts lines that are
// not a nuclei result (not JSON, or JSON without a template-id).
func splitResults(data []byte) (results []Result, rejected int, err error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	const maxLine = 10 * 1024 * 1024 // responses can be large
	sc.Buffer(make([]byte, 64*1024), maxLine)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Result
		if json.Unmarshal(line, &r) != nil || r.TemplateID == "" {
			rejected++
			continue
		}
		results = append(results, r)
	}
	return results, rejected, sc.Err()
}
