package tenablesc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Tenable.sc returns many numbers as JSON strings ("totalRecords": "12",
// "port": "443") and some booleans as "true"/"1"/"Yes". These types accept
// either form; anything they cannot read is an error (the page fails),
// except empty strings and null, which are zero.

// flexInt is an integer sent as a number or a string.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s, ok, err := scalarText(b)
	if err != nil || !ok {
		*f = 0
		return err
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		fv, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return fmt.Errorf("not an integer: %q", truncate(s, 32))
		}
		v = int64(fv)
	}
	*f = flexInt(v)
	return nil
}

// flexFloat is a number sent as a number or a string. "" and null are
// unset (Set false).
type flexFloat struct {
	V   float64
	Set bool
}

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s, ok, err := scalarText(b)
	if err != nil || !ok {
		*f = flexFloat{}
		return err
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("not a number: %q", truncate(s, 32))
	}
	*f = flexFloat{V: v, Set: true}
	return nil
}

// flexBool is a boolean sent as true/false, "true"/"false", "1"/"0" or
// "Yes"/"No".
type flexBool bool

func (f *flexBool) UnmarshalJSON(b []byte) error {
	s, ok, err := scalarText(b)
	if err != nil || !ok {
		*f = false
		return err
	}
	switch strings.ToLower(s) {
	case "true", "1", "yes", "y":
		*f = true
	case "false", "0", "no", "n", "-1":
		*f = false
	default:
		return fmt.Errorf("not a boolean: %q", truncate(s, 32))
	}
	return nil
}

// flexString is a string that may arrive as a number.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	s, _, err := scalarText(b)
	*f = flexString(s)
	return err
}

// scalarText reads a JSON string, number or boolean as text; null is
// (“”, false). Objects and arrays are errors.
func scalarText(b []byte) (string, bool, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return "", false, nil
	}
	switch b[0] {
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		return s, s != "", nil
	case '{', '[':
		return "", false, fmt.Errorf("expected a scalar, got %c", b[0])
	default:
		return string(b), true, nil
	}
}

// namedRef is an object {"id": .., "name": ..} that some versions send as a
// plain string (the name).
type namedRef struct {
	ID   flexString `json:"id"`
	Name string     `json:"name"`
	Type string     `json:"type"`
}

func (n *namedRef) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*n = namedRef{}
		return nil
	}
	if b[0] != '{' {
		s, _, err := scalarText(b)
		*n = namedRef{Name: s}
		return err
	}
	type plain namedRef
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*n = namedRef(p)
	return nil
}

// severityRef is {"id": "4", "name": "Critical"} or a bare id.
type severityRef struct {
	ID   flexInt `json:"id"`
	Name string  `json:"name"`
}

func (s *severityRef) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		type plain severityRef
		var p plain
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		*s = severityRef(p)
		return nil
	}
	var id flexInt
	if err := id.UnmarshalJSON(b); err != nil {
		return err
	}
	*s = severityRef{ID: id}
	return nil
}

// vulnRow is one result of the analysis tool vulndetails (and, with fewer
// fields, sumip). Unknown fields are ignored.
type vulnRow struct {
	PluginID              flexString  `json:"pluginID"`
	PluginName            string      `json:"pluginName"`
	Severity              severityRef `json:"severity"`
	HasBeenMitigated      flexBool    `json:"hasBeenMitigated"`
	AcceptRisk            flexBool    `json:"acceptRisk"`
	RecastRisk            flexBool    `json:"recastRisk"`
	IP                    string      `json:"ip"`
	UUID                  string      `json:"uuid"`
	Port                  flexInt     `json:"port"`
	Protocol              string      `json:"protocol"`
	FirstSeen             flexInt     `json:"firstSeen"`
	LastSeen              flexInt     `json:"lastSeen"`
	LastMitigated         flexInt     `json:"lastMitigated"`
	ExploitAvailable      flexBool    `json:"exploitAvailable"`
	ExploitFrameworks     string      `json:"exploitFrameworks"`
	ExploitEase           string      `json:"exploitEase"`
	Synopsis              string      `json:"synopsis"`
	Description           string      `json:"description"`
	Solution              string      `json:"solution"`
	RiskFactor            string      `json:"riskFactor"`
	VPRScore              flexFloat   `json:"vprScore"`
	BaseScore             flexFloat   `json:"baseScore"`
	CVSSVector            string      `json:"cvssVector"`
	CVSSV3BaseScore       flexFloat   `json:"cvssV3BaseScore"`
	CVSSV3Vector          string      `json:"cvssV3Vector"`
	CVSSV4BaseScore       flexFloat   `json:"cvssV4BaseScore"`
	CVSSV4Vector          string      `json:"cvssV4Vector"`
	CVE                   string      `json:"cve"`
	BID                   string      `json:"bid"`
	CheckType             string      `json:"checkType"`
	Family                namedRef    `json:"family"`
	Repository            namedRef    `json:"repository"`
	HostUUID              string      `json:"hostUUID"`
	VulnUUID              string      `json:"vulnUUID"`
	ACRScore              flexFloat   `json:"acrScore"`
	AssetExposureScore    flexFloat   `json:"assetExposureScore"`
	DNSName               string      `json:"dnsName"`
	MACAddress            string      `json:"macAddress"`
	NetBIOSName           string      `json:"netbiosName"`
	OperatingSystem       string      `json:"operatingSystem"`
	RecastRiskRuleComment string      `json:"recastRiskRuleComment"`
	AcceptRiskRuleComment string      `json:"acceptRiskRuleComment"`
	PluginText            string      `json:"pluginText"`
	SeeAlso               string      `json:"seeAlso"`
	XRefs                 string      `json:"xrefs"`
	CPE                   string      `json:"cpe"`
	PluginPubDate         flexInt     `json:"pluginPubDate"`
	PatchPubDate          flexInt     `json:"patchPubDate"`
	VulnPubDate           flexInt     `json:"vulnPubDate"`
	PluginModDate         flexInt     `json:"pluginModDate"`
}

// plugin is the metadata of /rest/plugin/{id}.
type plugin struct {
	ID                flexString `json:"id"`
	Name              string     `json:"name"`
	Family            namedRef   `json:"family"`
	Type              string     `json:"type"`
	ExploitAvailable  flexBool   `json:"exploitAvailable"`
	ExploitFrameworks string     `json:"exploitFrameworks"`
	ExploitEase       string     `json:"exploitEase"`
	EPSSScore         flexFloat  `json:"epssScore"`
	VPRScore          flexFloat  `json:"vprScore"`
	XRefs             string     `json:"xrefs"`
	SeeAlso           string     `json:"seeAlso"`
	CPE               string     `json:"cpe"`
	PluginPubDate     flexInt    `json:"pluginPubDate"`
	PatchPubDate      flexInt    `json:"patchPubDate"`
	VulnPubDate       flexInt    `json:"vulnPubDate"`
	PluginModDate     flexInt    `json:"pluginModDate"`
	ModifiedTime      flexInt    `json:"modifiedTime"`
}

// pluginFields is the fields= list asked of /rest/plugin/{id}.
const pluginFields = "id,name,family,type,exploitAvailable,exploitFrameworks,exploitEase,epssScore,vprScore," +
	"xrefs,seeAlso,cpe,pluginPubDate,patchPubDate,vulnPubDate,pluginModDate,modifiedTime"

// analysisPage is the response of POST /rest/analysis.
type analysisPage struct {
	TotalRecords    flexInt           `json:"totalRecords"`
	ReturnedRecords flexInt           `json:"returnedRecords"`
	StartOffset     flexInt           `json:"startOffset"`
	EndOffset       flexInt           `json:"endOffset"`
	Results         []json.RawMessage `json:"results"`
}

// Filter is one analysis query filter.
type Filter struct {
	FilterName string `json:"filterName"`
	Operator   string `json:"operator"`
	Value      any    `json:"value"`
}

// Query is a vulnerability analysis query the connector builds (never the
// platform).
type Query struct {
	Tool       string // vulndetails, sumip
	SourceType string // cumulative, patched, individual
	// ScanID and View select one scan result (SourceType individual).
	ScanID    string
	View      string
	Filters   []Filter
	SortField string
	SortDir   string
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
