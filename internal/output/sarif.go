// Package output provides output formatting for scan results.
package output

import (
	"encoding/json"
	"strings"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// SARIFOutput represents a SARIF 2.1.0 document.
type SARIFOutput struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run in SARIF.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a rule.
type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription SARIFMessage    `json:"shortDescription,omitempty"`
	FullDescription  SARIFMessage    `json:"fullDescription,omitempty"`
	DefaultConfig    SARIFRuleConfig `json:"defaultConfiguration,omitempty"`
}

// SARIFRuleConfig describes rule configuration.
type SARIFRuleConfig struct {
	Level string `json:"level,omitempty"`
}

// SARIFResult represents a single finding with SARIF 2.1.0 extended fields.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`

	// SARIF 2.1.0 Extended fields
	Fingerprints        map[string]string `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	RelatedLocations    []SARIFLocation   `json:"relatedLocations,omitempty"`
	CodeFlows           []SARIFCodeFlow   `json:"codeFlows,omitempty"`
	Stacks              []SARIFStack      `json:"stacks,omitempty"`
	Attachments         []SARIFAttachment `json:"attachments,omitempty"`
	WorkItemURIs        []string          `json:"workItemUris,omitempty"`
	HostedViewerURI     string            `json:"hostedViewerUri,omitempty"`

	// Risk assessment
	Rank            *float64 `json:"rank,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	BaselineState   string   `json:"baselineState,omitempty"`
	OccurrenceCount int      `json:"occurrenceCount,omitempty"`
	CorrelationGUID string   `json:"correlationGuid,omitempty"`
}

// SARIFMessage represents a message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
	Message          *SARIFMessage          `json:"message,omitempty"`
}

// SARIFPhysicalLocation represents a physical location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation represents an artifact location.
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFRegion represents a region in a file.
type SARIFRegion struct {
	StartLine   int            `json:"startLine,omitempty"`
	EndLine     int            `json:"endLine,omitempty"`
	StartColumn int            `json:"startColumn,omitempty"`
	EndColumn   int            `json:"endColumn,omitempty"`
	Snippet     *SARIFSnippet  `json:"snippet,omitempty"`
	Message     *SARIFMessage  `json:"message,omitempty"`
}

// SARIFSnippet represents a code snippet.
type SARIFSnippet struct {
	Text string `json:"text"`
}

// SARIFLogicalLocation represents a logical location (function, class, etc.).
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	Kind               string `json:"kind,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
}

// SARIFStack represents a call stack.
type SARIFStack struct {
	Message *SARIFMessage  `json:"message,omitempty"`
	Frames  []SARIFFrame   `json:"frames,omitempty"`
}

// SARIFFrame represents a stack frame.
type SARIFFrame struct {
	Location   *SARIFLocation `json:"location,omitempty"`
	Module     string         `json:"module,omitempty"`
	ThreadID   int            `json:"threadId,omitempty"`
	Parameters []string       `json:"parameters,omitempty"`
}

// SARIFAttachment represents an attachment.
type SARIFAttachment struct {
	Description      *SARIFMessage          `json:"description,omitempty"`
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Regions          []SARIFRegion          `json:"regions,omitempty"`
}

// SARIFCodeFlow represents a code flow (taint tracking path).
type SARIFCodeFlow struct {
	Message     *SARIFMessage       `json:"message,omitempty"`
	ThreadFlows []SARIFThreadFlow   `json:"threadFlows"`
}

// SARIFThreadFlow represents a thread flow in a code flow.
type SARIFThreadFlow struct {
	ID        string                    `json:"id,omitempty"`
	Message   *SARIFMessage             `json:"message,omitempty"`
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

// SARIFThreadFlowLocation represents a location in a thread flow.
type SARIFThreadFlowLocation struct {
	Location   *SARIFLocation  `json:"location,omitempty"`
	Index      int             `json:"index,omitempty"`
	Importance string          `json:"importance,omitempty"` // essential, important, unimportant
	Kinds      []string        `json:"kinds,omitempty"`      // source, sink, sanitizer
}

// ToSARIF converts CTIS reports to SARIF 2.1.0 format.
func ToSARIF(reports []*ctis.Report) ([]byte, error) {
	sarif := SARIFOutput{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []SARIFRun{},
	}

	// Group findings by tool
	byTool := make(map[string][]ctis.Finding)
	for _, report := range reports {
		toolName := "unknown"
		if report.Tool != nil && report.Tool.Name != "" {
			toolName = report.Tool.Name
		}
		byTool[toolName] = append(byTool[toolName], report.Findings...)
	}

	for toolName, findings := range byTool {
		run := SARIFRun{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           toolName,
					InformationURI: "https://openctem.io",
				},
			},
			Results: []SARIFResult{},
		}

		rulesSeen := make(map[string]bool)
		var rules []SARIFRule

		for _, f := range findings {
			ruleID := f.RuleID
			if ruleID == "" {
				ruleID = f.Title
			}

			// Add rule if not seen
			if !rulesSeen[ruleID] {
				rulesSeen[ruleID] = true
				rules = append(rules, SARIFRule{
					ID:               ruleID,
					ShortDescription: SARIFMessage{Text: f.Title},
					FullDescription:  SARIFMessage{Text: f.Description},
					DefaultConfig:    SARIFRuleConfig{Level: SeverityToLevel(string(f.Severity))},
				})
			}

			result := SARIFResult{
				RuleID:  ruleID,
				Level:   SeverityToLevel(string(f.Severity)),
				Message: SARIFMessage{Text: f.Description},
			}

			// Add primary location
			if f.Location != nil && f.Location.Path != "" {
				result.Locations = []SARIFLocation{convertCTISLocationToSARIF(f.Location)}
			}

			// Add SARIF 2.1.0 extended fields
			if f.Fingerprint != "" {
				result.Fingerprints = map[string]string{"primary": f.Fingerprint}
			}
			if len(f.PartialFingerprints) > 0 {
				result.PartialFingerprints = f.PartialFingerprints
			}

			// Related locations
			if len(f.RelatedLocations) > 0 {
				result.RelatedLocations = make([]SARIFLocation, 0, len(f.RelatedLocations))
				for _, loc := range f.RelatedLocations {
					result.RelatedLocations = append(result.RelatedLocations, convertCTISLocationToSARIF(loc))
				}
			}

			// Stacks
			if len(f.Stacks) > 0 {
				result.Stacks = make([]SARIFStack, 0, len(f.Stacks))
				for _, st := range f.Stacks {
					result.Stacks = append(result.Stacks, convertCTISStackToSARIF(st))
				}
			}

			// Attachments
			if len(f.Attachments) > 0 {
				result.Attachments = make([]SARIFAttachment, 0, len(f.Attachments))
				for _, att := range f.Attachments {
					result.Attachments = append(result.Attachments, convertCTISAttachmentToSARIF(att))
				}
			}

			// Code flows (taint tracking / data flow analysis)
			if f.DataFlow != nil {
				result.CodeFlows = []SARIFCodeFlow{convertCTISDataFlowToSARIF(f.DataFlow)}
			}

			// Work item URIs
			if len(f.WorkItemURIs) > 0 {
				result.WorkItemURIs = f.WorkItemURIs
			}

			// Hosted viewer URI
			if f.HostedViewerURI != "" {
				result.HostedViewerURI = f.HostedViewerURI
			}

			// Risk assessment fields
			if f.Rank > 0 {
				rank := f.Rank
				result.Rank = &rank
			}
			if f.Kind != "" {
				result.Kind = f.Kind
			}
			if f.BaselineState != "" {
				result.BaselineState = f.BaselineState
			}
			if f.OccurrenceCount > 0 {
				result.OccurrenceCount = f.OccurrenceCount
			}
			if f.CorrelationID != "" {
				result.CorrelationGUID = f.CorrelationID
			}

			run.Results = append(run.Results, result)
		}

		run.Tool.Driver.Rules = rules
		sarif.Runs = append(sarif.Runs, run)
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// convertCTISLocationToSARIF converts a CTIS FindingLocation to SARIF location.
func convertCTISLocationToSARIF(loc *ctis.FindingLocation) SARIFLocation {
	if loc == nil {
		return SARIFLocation{}
	}

	sarifLoc := SARIFLocation{
		PhysicalLocation: &SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{
				URI: loc.Path,
			},
		},
	}

	// Add region with line/column info
	if loc.StartLine > 0 || loc.Snippet != "" {
		region := &SARIFRegion{
			StartLine:   loc.StartLine,
			EndLine:     loc.EndLine,
			StartColumn: loc.StartColumn,
			EndColumn:   loc.EndColumn,
		}
		if loc.Snippet != "" {
			region.Snippet = &SARIFSnippet{Text: loc.Snippet}
		}
		sarifLoc.PhysicalLocation.Region = region
	}

	// Add logical location if present
	if loc.LogicalLocation != nil {
		sarifLoc.LogicalLocations = []SARIFLogicalLocation{{
			Name:               loc.LogicalLocation.Name,
			Kind:               loc.LogicalLocation.Kind,
			FullyQualifiedName: loc.LogicalLocation.FullyQualifiedName,
		}}
	}

	return sarifLoc
}

// convertCTISStackToSARIF converts a CTIS StackTrace to SARIF stack.
func convertCTISStackToSARIF(st *ctis.StackTrace) SARIFStack {
	if st == nil {
		return SARIFStack{}
	}

	stack := SARIFStack{}
	if st.Message != "" {
		stack.Message = &SARIFMessage{Text: st.Message}
	}

	if len(st.Frames) > 0 {
		stack.Frames = make([]SARIFFrame, 0, len(st.Frames))
		for _, frame := range st.Frames {
			sarifFrame := SARIFFrame{
				Module:     frame.Module,
				ThreadID:   frame.ThreadID,
				Parameters: frame.Parameters,
			}
			if frame.Location != nil {
				loc := convertCTISLocationToSARIF(frame.Location)
				sarifFrame.Location = &loc
			}
			stack.Frames = append(stack.Frames, sarifFrame)
		}
	}

	return stack
}

// convertCTISAttachmentToSARIF converts a CTIS Attachment to SARIF attachment.
func convertCTISAttachmentToSARIF(att *ctis.Attachment) SARIFAttachment {
	if att == nil {
		return SARIFAttachment{}
	}

	sarifAtt := SARIFAttachment{}
	if att.Description != "" {
		sarifAtt.Description = &SARIFMessage{Text: att.Description}
	}

	if att.ArtifactLocation != nil {
		sarifAtt.ArtifactLocation = &SARIFArtifactLocation{
			URI:       att.ArtifactLocation.URI,
			URIBaseID: att.ArtifactLocation.URIBaseID,
		}
	}

	if len(att.Regions) > 0 {
		sarifAtt.Regions = make([]SARIFRegion, 0, len(att.Regions))
		for _, reg := range att.Regions {
			if reg != nil {
				sarifReg := SARIFRegion{
					StartLine:   reg.StartLine,
					EndLine:     reg.EndLine,
					StartColumn: reg.StartColumn,
					EndColumn:   reg.EndColumn,
				}
				if reg.Snippet != "" {
					sarifReg.Snippet = &SARIFSnippet{Text: reg.Snippet}
				}
				sarifAtt.Regions = append(sarifAtt.Regions, sarifReg)
			}
		}
	}

	return sarifAtt
}

// SeverityToLevel maps CTIS severity to SARIF level.
func SeverityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "none"
	}
}

// convertCTISDataFlowToSARIF converts a CTIS DataFlow to SARIF code flow.
func convertCTISDataFlowToSARIF(df *ctis.DataFlow) SARIFCodeFlow {
	if df == nil {
		return SARIFCodeFlow{}
	}

	var locations []SARIFThreadFlowLocation
	index := 0

	// Add source locations
	for _, src := range df.Sources {
		locations = append(locations, SARIFThreadFlowLocation{
			Location:   convertDataFlowLocationToSARIF(&src),
			Index:      index,
			Importance: "essential",
			Kinds:      []string{"source"},
		})
		index++
	}

	// Add intermediate locations
	for _, inter := range df.Intermediates {
		locations = append(locations, SARIFThreadFlowLocation{
			Location:   convertDataFlowLocationToSARIF(&inter),
			Index:      index,
			Importance: "important",
			Kinds:      []string{"intermediate"},
		})
		index++
	}

	// Add sink locations
	for _, sink := range df.Sinks {
		locations = append(locations, SARIFThreadFlowLocation{
			Location:   convertDataFlowLocationToSARIF(&sink),
			Index:      index,
			Importance: "essential",
			Kinds:      []string{"sink"},
		})
		index++
	}

	return SARIFCodeFlow{
		ThreadFlows: []SARIFThreadFlow{
			{
				ID:        "dataflow-0",
				Locations: locations,
			},
		},
	}
}

// convertDataFlowLocationToSARIF converts a CTIS DataFlowLocation to SARIF location.
func convertDataFlowLocationToSARIF(loc *ctis.DataFlowLocation) *SARIFLocation {
	if loc == nil {
		return nil
	}

	sarifLoc := &SARIFLocation{
		PhysicalLocation: &SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{
				URI: loc.Path,
			},
		},
	}

	// Add region with line info
	if loc.Line > 0 || loc.Content != "" {
		region := &SARIFRegion{
			StartLine:   loc.Line,
			StartColumn: loc.Column,
		}
		if loc.Content != "" {
			region.Snippet = &SARIFSnippet{Text: loc.Content}
		}
		sarifLoc.PhysicalLocation.Region = region
	}

	// Add label as message if present
	if loc.Label != "" {
		sarifLoc.Message = &SARIFMessage{Text: loc.Label}
	}

	return sarifLoc
}
