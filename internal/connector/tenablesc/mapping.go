package tenablesc

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Tool identity of every report the connector pushes. Commands name the
// same tool (payload "scanner"), so result binding accepts the reports.
const (
	ToolName   = "tenable_sc"
	toolVendor = "Tenable"
)

// Tenable states of a vulnerability row.
const (
	stateOpen      = "open"
	stateMitigated = "mitigated"
)

// Per-field caps (api RFC-040 §5.4, RFC-047 §8.4).
const (
	capTitle       = 512
	capLongText    = 16 << 10
	capEvidence    = 64 << 10
	capReference   = 2 << 10
	maxReferences  = 50
	maxCVEs        = 200
	capComment     = 1 << 10
	capShort       = 1 << 10
	capHostname    = 253
	capIdentifier  = 128
	capVersionText = 64
)

var (
	cveRE      = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	hostnameRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$`)
	// minTimestamp: anything before 1990 is not a real Tenable date (Tenable
	// uses -1 and 0 for "unknown").
	minTimestamp = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
)

// mapper turns rows into CTIS assets and findings.
type mapper struct {
	now     time.Time
	plugins map[string]*plugin // enrichment, may miss ids
}

// hostKey identifies the asset a row belongs to.
type hostKey struct {
	assetID string
	asset   ctis.Asset
	ip      string
	repo    string
	hostID  string
}

// host maps a row's host part. ok is false when the row names no usable
// host (no valid IP and no valid DNS name).
func (m *mapper) host(r *vulnRow) (hostKey, bool) {
	ip := normalizeIP(r.IP)
	fqdn := normalizeHostname(r.DNSName)
	value := fqdn
	if value == "" {
		value = ip
	}
	if value == "" {
		return hostKey{}, false
	}
	assetType := ctis.AssetTypeHost
	if net.ParseIP(value) != nil {
		assetType = ctis.AssetTypeIPAddress
	}
	netbios := sanitizeText(r.NetBIOSName, capIdentifier)
	name := value
	if fqdn == "" && netbios != "" {
		name = netbios
	}
	props := ctis.Properties{}
	setStr(props, "ip_address", ip)
	setStr(props, "fqdn", fqdn)
	setStr(props, "netbios_name", netbios)
	setStr(props, "os", sanitizeText(r.OperatingSystem, capShort))
	hostUUID := firstNonEmpty(sanitizeIdentifier(r.HostUUID), sanitizeIdentifier(r.UUID))
	setStr(props, "tenable_host_uuid", hostUUID)
	repoID := sanitizeIdentifier(string(r.Repository.ID))
	setStr(props, "tenable_repository_id", repoID)
	setStr(props, "tenable_repository", sanitizeText(r.Repository.Name, capIdentifier))
	if v, ok := clampRange(r.ACRScore, 1, 10); ok {
		props["tenable_acr"] = v
	}
	if v, ok := clampRange(r.AssetExposureScore, 0, 1000); ok {
		props["tenable_aes"] = v
	}
	asset := ctis.Asset{
		ID:         "host-" + value,
		Type:       assetType,
		Value:      value,
		Name:       name,
		Properties: props,
	}
	if macs := splitMACs(r.MACAddress); len(macs) > 0 {
		asset.Identifiers = &ctis.AssetIdentifiers{MACAddresses: macs}
	}
	return hostKey{assetID: asset.ID, asset: asset, ip: ip, repo: repoID, hostID: hostUUID}, true
}

// finding maps a vulnerability row (state open or mitigated).
func (m *mapper) finding(r *vulnRow, h hostKey, state string) ctis.Finding {
	pluginID := sanitizeIdentifier(string(r.PluginID))
	p := m.plugins[pluginID]
	title := sanitizeText(r.PluginName, capTitle)
	if title == "" && p != nil {
		title = sanitizeText(p.Name, capTitle)
	}
	if title == "" {
		title = "Tenable plugin " + pluginID
	}
	family := sanitizeText(r.Family.Name, capIdentifier)
	if family == "" && p != nil {
		family = sanitizeText(p.Family.Name, capIdentifier)
	}
	proto := strings.ToLower(sanitizeIdentifier(r.Protocol))
	port := int(r.Port)
	if port < 0 || port > 65535 {
		port = 0
	}
	hostRef := firstNonEmpty(h.ip, h.asset.Value)

	f := ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		Title:    title,
		Severity: mapSeverity(int64(r.Severity.ID)),
		AssetRef: h.assetID,
		RuleID:   pluginID,
		RuleName: title,
		Category: family,
		Fingerprint: fmt.Sprintf("%s:%s:%s:%s:%d/%s",
			ToolName, h.repo, hostRef, pluginID, port, proto),
	}
	f.Description = joinNonEmpty("\n\n",
		sanitizeText(r.Synopsis, capLongText), sanitizeText(r.Description, capLongText))
	if len(f.Description) > capLongText {
		f.Description = sanitizeText(f.Description, capLongText)
	}
	f.Evidence = sanitizeText(r.PluginText, capEvidence)
	if port > 0 {
		f.Network = &ctis.NetworkLocation{Host: h.asset.Value, Port: port, Protocol: proto}
	}
	if t := m.timestamp(r.FirstSeen); t != nil {
		f.FirstSeenAt = t
	}
	if t := m.timestamp(r.LastSeen); t != nil {
		f.LastSeenAt = t
	}
	if state == stateMitigated {
		f.Status = ctis.FindingStatusResolved
	}

	f.Vulnerability = m.vulnerability(r, p)
	if sol := sanitizeText(r.Solution, capLongText); sol != "" && !strings.EqualFold(sol, "n/a") {
		f.Remediation = &ctis.Remediation{Recommendation: sol}
	}
	seeAlso := r.SeeAlso
	if seeAlso == "" && p != nil {
		seeAlso = p.SeeAlso
	}
	f.References = references(seeAlso)

	props := ctis.Properties{}
	setStr(props, "tenable_plugin_id", pluginID)
	setStr(props, "tenable_plugin_family", family)
	setStr(props, "tenable_check_type", sanitizeText(r.CheckType, capIdentifier))
	if p != nil {
		setStr(props, "tenable_plugin_type", sanitizeText(p.Type, capIdentifier))
	}
	m.setDate(props, "tenable_plugin_pub_date", r.PluginPubDate, pluginInt(p, func(p *plugin) flexInt { return p.PluginPubDate }))
	m.setDate(props, "tenable_patch_pub_date", r.PatchPubDate, pluginInt(p, func(p *plugin) flexInt { return p.PatchPubDate }))
	m.setDate(props, "tenable_vuln_pub_date", r.VulnPubDate, pluginInt(p, func(p *plugin) flexInt { return p.VulnPubDate }))
	m.setDate(props, "tenable_plugin_mod_date", r.PluginModDate, pluginInt(p, func(p *plugin) flexInt {
		if p.PluginModDate != 0 {
			return p.PluginModDate
		}
		return p.ModifiedTime
	}))
	frameworks, ease := r.ExploitFrameworks, r.ExploitEase
	if p != nil {
		frameworks = firstNonEmpty(frameworks, p.ExploitFrameworks)
		ease = firstNonEmpty(ease, p.ExploitEase)
	}
	setStr(props, "tenable_exploit_frameworks", sanitizeText(frameworks, capShort))
	setStr(props, "tenable_exploit_ease", sanitizeText(ease, capShort))
	props["tenable_accept_risk"] = bool(r.AcceptRisk)
	props["tenable_recast_risk"] = bool(r.RecastRisk)
	setStr(props, "tenable_accept_risk_comment", sanitizeText(r.AcceptRiskRuleComment, capComment))
	setStr(props, "tenable_recast_risk_comment", sanitizeText(r.RecastRiskRuleComment, capComment))
	props["tenable_previously_mitigated"] = bool(r.HasBeenMitigated)
	m.setDate(props, "tenable_last_mitigated", r.LastMitigated, 0)
	props["tenable_state"] = state
	setStr(props, "tenable_repository_id", h.repo)
	setStr(props, "tenable_repository", sanitizeText(r.Repository.Name, capIdentifier))
	setStr(props, "tenable_vuln_uuid", sanitizeIdentifier(r.VulnUUID))
	setStr(props, "tenable_host_uuid", h.hostID)
	if v, ok := clampRange(r.ACRScore, 1, 10); ok {
		props["tenable_acr"] = v
	}
	if v, ok := clampRange(r.AssetExposureScore, 0, 1000); ok {
		props["tenable_aes"] = v
	}
	if v, ok := clampRange(r.CVSSV4BaseScore, 0, 10); ok {
		props["tenable_cvss_v4_score"] = v
		setStr(props, "tenable_cvss_v4_vector", sanitizeText(r.CVSSV4Vector, capIdentifier))
	}
	setStr(props, "tenable_risk_factor", sanitizeText(r.RiskFactor, capIdentifier))
	xrefs := r.XRefs
	if xrefs == "" && p != nil {
		xrefs = p.XRefs
	}
	setStr(props, "tenable_xrefs", sanitizeText(xrefs, capShort))
	setStr(props, "tenable_bid", sanitizeText(r.BID, capShort))
	f.Properties = props
	return f
}

func (m *mapper) vulnerability(r *vulnRow, p *plugin) *ctis.VulnerabilityDetails {
	v := &ctis.VulnerabilityDetails{}
	if cves := splitCVEs(r.CVE); len(cves) > 0 {
		v.CVEID = cves[0]
		v.CVEIDs = cves
	}
	if s, ok := clampRange(r.CVSSV3BaseScore, 0, 10); ok {
		v.CVSSScore, v.CVSSVersion = s, "3.x"
		v.CVSSVector = sanitizeText(r.CVSSV3Vector, capIdentifier)
	} else if s, ok := clampRange(r.BaseScore, 0, 10); ok {
		v.CVSSScore, v.CVSSVersion = s, "2.0"
		v.CVSSVector = sanitizeText(r.CVSSVector, capIdentifier)
	}
	vpr := r.VPRScore
	if !vpr.Set && p != nil {
		vpr = p.VPRScore
	}
	if s, ok := clampRange(vpr, 0, 10); ok {
		v.VPRScore = s
	}
	v.ExploitAvailable = bool(r.ExploitAvailable) || (p != nil && bool(p.ExploitAvailable))
	if p != nil {
		if e, ok := epss(p.EPSSScore); ok {
			v.EPSSScore = e
		}
	}
	cpe := r.CPE
	if cpe == "" && p != nil {
		cpe = p.CPE
	}
	v.CPE = sanitizeText(firstLine(cpe), capShort)
	var pub flexInt
	if r.VulnPubDate != 0 {
		pub = r.VulnPubDate
	} else if p != nil {
		pub = p.VulnPubDate
	}
	v.PublishedAt = m.timestamp(pub)
	if v.CVEID == "" && v.CVSSScore == 0 && v.VPRScore == 0 && v.CPE == "" && !v.ExploitAvailable &&
		v.EPSSScore == 0 && v.PublishedAt == nil {
		return nil
	}
	return v
}

func pluginInt(p *plugin, get func(*plugin) flexInt) flexInt {
	if p == nil {
		return 0
	}
	return get(p)
}

func (m *mapper) setDate(props ctis.Properties, key string, v, fallback flexInt) {
	t := m.timestamp(v)
	if t == nil {
		t = m.timestamp(fallback)
	}
	if t != nil {
		props[key] = t.Format(time.RFC3339)
	}
}

// timestamp reads epoch seconds; implausible values are dropped.
func (m *mapper) timestamp(v flexInt) *time.Time {
	if v <= 0 {
		return nil
	}
	t := time.Unix(int64(v), 0).UTC()
	if t.Before(minTimestamp) || t.After(m.now.Add(24*time.Hour)) {
		return nil
	}
	return &t
}

func mapSeverity(n int64) ctis.Severity {
	switch n {
	case 4:
		return ctis.SeverityCritical
	case 3:
		return ctis.SeverityHigh
	case 2:
		return ctis.SeverityMedium
	case 1:
		return ctis.SeverityLow
	default:
		return ctis.SeverityInfo
	}
}

func clampRange(f flexFloat, lo, hi float64) (float64, bool) {
	if !f.Set || f.V != f.V || f.V < lo || f.V > hi { // NaN check: f.V != f.V
		return 0, false
	}
	return f.V, true
}

// epss accepts a probability (0..1) or a percentage (Tenable shows both).
func epss(f flexFloat) (float64, bool) {
	if !f.Set || f.V != f.V || f.V < 0 {
		return 0, false
	}
	switch {
	case f.V <= 1:
		return f.V, true
	case f.V <= 100:
		return f.V / 100, true
	}
	return 0, false
}

func splitCVEs(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		c := strings.ToUpper(strings.TrimSpace(f))
		if !cveRE.MatchString(c) || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		if len(out) == maxCVEs {
			break
		}
	}
	return out
}

func references(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' || r == '\t' }) {
		f = strings.TrimSpace(f)
		if f == "" || len(f) > capReference || seen[f] {
			continue
		}
		u, err := url.Parse(f)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		clean := sanitizeText(f, capReference)
		if clean != f {
			continue
		}
		seen[f] = true
		out = append(out, f)
		if len(out) == maxReferences {
			break
		}
	}
	return out
}

func normalizeIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func normalizeHostname(s string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if h == "" || len(h) > capHostname || net.ParseIP(h) != nil || !hostnameRE.MatchString(h) {
		return ""
	}
	return h
}

// splitMACs splits a MAC list (newline, space or comma separated), lower
// case, de-duplicated.
func splitMACs(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ','
	}) {
		mac := strings.ToLower(f)
		if _, err := net.ParseMAC(mac); err != nil || seen[mac] {
			continue
		}
		seen[mac] = true
		out = append(out, mac)
		if len(out) == 32 {
			break
		}
	}
	return out
}

// sanitizeText makes a Tenable string safe to carry: valid UTF-8, no NUL,
// no C0/C1 controls except tab and newline, no bidi overrides, at most max
// bytes (cut at a rune boundary), trimmed.
func sanitizeText(s string, max int) string {
	if s == "" {
		return ""
	}
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(min(len(s), max))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n':
		case r == '\r':
			continue
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			continue
		case (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f:
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

var identifierRE = regexp.MustCompile(`^[A-Za-z0-9._:\-]+$`)

// sanitizeIdentifier keeps a short id-like value (plugin id, uuid,
// repository id, protocol), or "".
func sanitizeIdentifier(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > capIdentifier || !identifierRE.MatchString(s) {
		return ""
	}
	return s
}

func setStr(p ctis.Properties, k, v string) {
	if v != "" {
		p[k] = v
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func joinNonEmpty(sep string, vals ...string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, sep)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
