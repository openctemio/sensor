package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Parser converts subfinder output to CTIS format.
type Parser struct{}

// NewParser creates a new subfinder parser.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the parser name.
func (p *Parser) Name() string {
	return "subfinder"
}

// SupportedFormats returns supported output formats.
func (p *Parser) SupportedFormats() []string {
	return []string{"json", "jsonl", "text"}
}

// CanParse checks if the data looks like subfinder output.
func (p *Parser) CanParse(data []byte) bool {
	// Check if it's JSON lines with subfinder structure
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var output SubfinderOutput
		if err := json.Unmarshal([]byte(line), &output); err == nil {
			// Check if it has the expected fields
			if output.Host != "" && output.Source != "" {
				return true
			}
		}

		// If first non-empty line isn't valid JSON with expected fields, not subfinder
		break
	}

	return false
}

// Parse converts subfinder output to CTIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	subdomains, err := p.parseSubdomains(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subfinder output: %w", err)
	}

	// Create assets from subdomains
	var assets []ctis.Asset
	for _, sub := range subdomains {
		asset := ctis.Asset{
			Type:  ctis.AssetTypeDomainName,
			Value: ctis.NormalizeAssetName(ctis.AssetTypeDomainName, sub.Host),
		}
		assets = append(assets, asset)
	}

	report := &ctis.Report{
		Version: ctis.SchemaVersion,
		Metadata: ctis.ReportMetadata{
			ID:          ctis.NewReportID(),
			GeneratedAt: time.Now().UTC(),
			Channel:     ctis.ChannelScanner,
		},
		Tool: &ctis.Tool{
			Name:       "subfinder",
			Vendor:     "projectdiscovery",
			Techniques: []ctis.Technique{ctis.TechniqueEASM},
		},
		Assets: assets,
	}

	return report, nil
}

// parseSubdomains parses raw subfinder output.
func (p *Parser) parseSubdomains(data []byte) ([]core.Subdomain, error) {
	var subdomains []core.Subdomain
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try to parse as JSON
		var output SubfinderOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			// If not JSON, treat as plain subdomain
			host := line
			if !seen[host] {
				seen[host] = true
				subdomains = append(subdomains, core.Subdomain{
					Host: host,
				})
			}
			continue
		}

		// Deduplicate
		if seen[output.Host] {
			continue
		}
		seen[output.Host] = true

		subdomains = append(subdomains, core.Subdomain{
			Host:   output.Host,
			Domain: output.Input,
			Source: output.Source,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

// ParseToSubdomains parses output and returns subdomain list.
func (p *Parser) ParseToSubdomains(data []byte) ([]core.Subdomain, error) {
	return p.parseSubdomains(data)
}

// ParseToHosts parses output and returns just the host list.
func (p *Parser) ParseToHosts(data []byte) ([]string, error) {
	subdomains, err := p.parseSubdomains(data)
	if err != nil {
		return nil, err
	}

	var hosts []string
	for _, sub := range subdomains {
		hosts = append(hosts, sub.Host)
	}

	return hosts, nil
}
