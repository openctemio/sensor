// Package scmock is a small Tenable Security Center (Tenable.sc) REST API
// mock for tests and scratch end-to-end runs of the connector. It follows the
// shapes documented in the Tenable.sc API reference (Scan, Scan Result,
// Analysis, Repository, Status, System, Policy, Scan Zone, Plugin) and the
// licence rules of the Security Center user guide:
//
//   - every response is the documented envelope {type, response, error_code,
//     error_msg, warnings, timestamp}; numbers are sent as JSON strings, as
//     the product does;
//   - API keys are checked in the x-apikey header (accesskey=…; secretkey=…;);
//   - a launched scan result moves through Queued, Running and Completed, one
//     state per read, with totalIPs/completedIPs and totalChecks/
//     completedChecks counters; its import moves through Importing to
//     Finished, or to Blocked when importing it would exceed the IP licence;
//   - only hosts that reply (Alive) appear in a result; every scanned host
//     carries the scan-information plugin 19506 (severity info);
//   - the licence counts unique IPs across repositories that hold at least
//     one plugin outside the documented discovery-only list;
//   - deleting a repository removes its data and updates the count at once
//     (the documented way the count changes immediately).
//
// It is not the product: nothing here is a statement about undocumented
// behaviour. It never listens on its own; callers serve Handler().
package scmock

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DiscoveryPlugins are plugin ids that do not make a host count against the
// licence (Security Center user guide, "License Requirements").
var DiscoveryPlugins = map[string]bool{
	"10180": true, "10287": true, "10335": true, "11219": true, "11933": true, "11936": true, "12053": true,
	"14272": true, "14274": true, "19506": true, "22964": true, "33812": true, "33813": true, "34220": true,
	"34277": true, "45590": true, "54615": true, "87413": true, "112154": true, "161455": true, "179042": true,
	"209654": true, "204872": true,
}

// Vuln is one plugin result on a host.
type Vuln struct {
	PluginID string  `json:"plugin_id"`
	Name     string  `json:"name"`
	Severity int     `json:"severity"` // 0 info .. 4 critical
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	CVE      string  `json:"cve,omitempty"` // comma-separated
	CVSSV3   float64 `json:"cvss_v3,omitempty"`
	Synopsis string  `json:"synopsis,omitempty"`
	Solution string  `json:"solution,omitempty"`
	Family   string  `json:"family,omitempty"`
}

// Host is one address of the simulated network.
type Host struct {
	IP      string `json:"ip"`
	DNSName string `json:"dns_name,omitempty"`
	NetBIOS string `json:"netbios_name,omitempty"`
	MAC     string `json:"mac,omitempty"`
	OS      string `json:"os,omitempty"`
	// Alive hosts reply to a scan; others are dead (absent from results).
	Alive bool   `json:"alive"`
	Vulns []Vuln `json:"vulns,omitempty"`
}

// Named is an id and a name (repositories, policies, zones).
type Named struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Options configure a mock.
type Options struct {
	AccessKey, SecretKey string
	Version              string // default 6.4.0
	LicensedIPs          int
	Hosts                []Host
	Repositories         []Named
	Policies             []Named
	Zones                []Named
	// RunningReads is how many reads of a running scan result pass before
	// it completes (default 2).
	RunningReads int
	// PartialScans makes every scan end "Partial" (finished, some results
	// available) with only the first half of its addresses scanned, as when
	// a scanner of the zone fails mid-scan.
	PartialScans bool
}

type scanDef struct {
	id, name, ipList string
	repo             int
}

type scanResult struct {
	id, name     string
	repo         int
	targets      []string // addresses in the scan
	reads        int
	status       string
	importStatus string
	scanned      []string // addresses whose data the result holds
	checks       int
}

// Server is a running mock; safe for concurrent use.
type Server struct {
	mu      sync.Mutex
	o       Options
	hosts   map[string]*Host
	repos   map[int]Named
	data    map[int]map[string]bool // repository -> addresses with data
	scans   map[string]*scanDef
	results map[string]*scanResult
	next    int
	// Log, when set, receives one line per request (method, path, status).
	Log func(string)
}

// New returns a mock for o.
func New(o Options) *Server {
	if o.Version == "" {
		o.Version = "6.4.0"
	}
	if o.RunningReads <= 0 {
		o.RunningReads = 2
	}
	s := &Server{o: o, hosts: map[string]*Host{}, repos: map[int]Named{}, data: map[int]map[string]bool{},
		scans: map[string]*scanDef{}, results: map[string]*scanResult{}, next: 100}
	for i := range o.Hosts {
		h := o.Hosts[i]
		if a, err := netip.ParseAddr(h.IP); err == nil {
			h.IP = a.String()
			s.hosts[h.IP] = &h
		}
	}
	for _, r := range o.Repositories {
		s.repos[r.ID] = r
		s.data[r.ID] = map[string]bool{}
	}
	return s
}

// ActiveIPs is the licence count: unique addresses, across repositories,
// holding a plugin outside DiscoveryPlugins.
func (s *Server) ActiveIPs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked(nil)
}

func (s *Server) activeLocked(extra []string) int {
	seen := map[string]bool{}
	count := func(ip string) {
		if h := s.hosts[ip]; h != nil && h.Alive && licensed(h) {
			seen[ip] = true
		}
	}
	for _, ips := range s.data {
		for ip := range ips {
			count(ip)
		}
	}
	for _, ip := range extra {
		count(ip)
	}
	return len(seen)
}

func licensed(h *Host) bool {
	for _, v := range h.Vulns {
		if !DiscoveryPlugins[v.PluginID] {
			return true
		}
	}
	return false
}

// Handler serves the REST API under /rest.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &statusWriter{ResponseWriter: w, status: 200}
		s.serve(rw, r)
		if s.Log != nil {
			s.Log(fmt.Sprintf("%s %s %d", r.Method, r.URL.Path, rw.status))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("x-apikey") != fmt.Sprintf("accesskey=%s; secretkey=%s;", s.o.AccessKey, s.o.SecretKey) {
		writeError(w, 401, 74, "Invalid login credentials")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/rest")
	seg := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/system" && r.Method == http.MethodGet:
		writeOK(w, map[string]any{"version": s.o.Version, "buildID": "mock"})
	case p == "/status" && r.Method == http.MethodGet:
		writeOK(w, map[string]any{"licenseStatus": "Valid", "licensedIPs": strconv.Itoa(s.o.LicensedIPs),
			"activeIPs": strconv.Itoa(s.activeLocked(nil))})
	case p == "/repository" && r.Method == http.MethodGet:
		writeOK(w, s.namedList(s.repoList()))
	case len(seg) == 2 && seg[0] == "repository" && r.Method == http.MethodDelete:
		id, _ := strconv.Atoi(seg[1])
		if _, ok := s.repos[id]; !ok {
			writeError(w, 403, 143, "Repository not found")
			return
		}
		delete(s.repos, id)
		delete(s.data, id)
		writeOK(w, "")
	case p == "/policy" && r.Method == http.MethodGet:
		writeOK(w, map[string]any{"usable": s.namedList(s.o.Policies), "manageable": []any{}})
	case p == "/zone" && r.Method == http.MethodGet:
		writeOK(w, s.namedList(s.o.Zones))
	case p == "/scan" && r.Method == http.MethodGet:
		var list []map[string]any
		for _, d := range s.scans {
			list = append(list, map[string]any{"id": d.id, "name": d.name})
		}
		writeOK(w, map[string]any{"usable": list, "manageable": []any{}})
	case p == "/scan" && r.Method == http.MethodPost:
		s.createScan(w, r)
	case len(seg) == 2 && seg[0] == "scan" && r.Method == http.MethodDelete:
		if _, ok := s.scans[seg[1]]; !ok {
			writeError(w, 403, 143, "Scan not found")
			return
		}
		delete(s.scans, seg[1])
		writeOK(w, "")
	case len(seg) == 3 && seg[0] == "scan" && seg[2] == "launch" && r.Method == http.MethodPost:
		s.launch(w, seg[1])
	case p == "/scanResult" && r.Method == http.MethodGet:
		var list []map[string]any
		for _, res := range s.results {
			list = append(list, map[string]any{"id": res.id, "name": res.name, "status": res.status,
				"importStatus": res.importStatus, "repository": map[string]any{"id": strconv.Itoa(res.repo)}})
		}
		writeOK(w, map[string]any{"usable": list, "manageable": []any{}})
	case len(seg) == 2 && seg[0] == "scanResult" && r.Method == http.MethodGet:
		s.readResult(w, seg[1])
	case len(seg) == 3 && seg[0] == "scanResult" && seg[2] == "stop" && r.Method == http.MethodPost:
		s.stop(w, seg[1])
	case p == "/analysis" && r.Method == http.MethodPost:
		s.analysis(w, r)
	case len(seg) == 2 && seg[0] == "plugin" && r.Method == http.MethodGet:
		writeOK(w, map[string]any{"id": seg[1], "name": "Plugin " + seg[1], "type": "active",
			"family": map[string]any{"id": "1", "name": "General"}})
	default:
		writeError(w, 404, 404, "Unknown resource")
	}
}

func (s *Server) repoList() []Named {
	out := make([]Named, 0, len(s.repos))
	for _, r := range s.repos {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Named) int { return a.ID - b.ID })
	return out
}

func (s *Server) namedList(in []Named) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, n := range in {
		out = append(out, map[string]any{"id": strconv.Itoa(n.ID), "name": n.Name})
	}
	return out
}

func (s *Server) id() string {
	s.next++
	return strconv.Itoa(s.next)
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		IPList     string `json:"ipList"`
		Repository struct {
			ID string `json:"id"`
		} `json:"repository"`
		Policy struct {
			ID string `json:"id"`
		} `json:"policy"`
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(b, &body) != nil || body.Name == "" || body.Type != "policy" {
		writeError(w, 400, 146, "Invalid scan definition")
		return
	}
	repo, _ := strconv.Atoi(body.Repository.ID)
	if _, ok := s.repos[repo]; !ok {
		writeError(w, 403, 143, "Repository not found")
		return
	}
	pol, _ := strconv.Atoi(body.Policy.ID)
	if !slices.ContainsFunc(s.o.Policies, func(n Named) bool { return n.ID == pol }) {
		writeError(w, 403, 143, "Policy not found")
		return
	}
	d := &scanDef{id: s.id(), name: body.Name, ipList: body.IPList, repo: repo}
	s.scans[d.id] = d
	writeOK(w, map[string]any{"id": d.id, "name": d.name})
}

func (s *Server) launch(w http.ResponseWriter, id string) {
	d, ok := s.scans[id]
	if !ok {
		writeError(w, 403, 143, "Scan not found")
		return
	}
	res := &scanResult{id: s.id(), name: d.name, repo: d.repo, targets: s.expand(d.ipList),
		status: "Queued", importStatus: "No Results"}
	s.results[res.id] = res
	writeOK(w, map[string]any{"scanID": d.id, "scanResult": map[string]any{"id": res.id, "name": res.name,
		"status": res.status, "repositoryID": strconv.Itoa(d.repo)}})
}

// expand turns an ipList into the known addresses it covers (addresses,
// CIDR ranges and DNS names of known hosts).
func (s *Server) expand(ipList string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	for _, t := range strings.Split(ipList, ",") {
		t = strings.TrimSpace(t)
		if pfx, err := netip.ParsePrefix(t); err == nil {
			for ip := range s.hosts {
				if a, _ := netip.ParseAddr(ip); pfx.Contains(a) {
					add(ip)
				}
			}
			continue
		}
		if a, err := netip.ParseAddr(t); err == nil {
			add(a.String())
			continue
		}
		for ip, h := range s.hosts {
			if strings.EqualFold(h.DNSName, t) {
				add(ip)
			}
		}
	}
	slices.Sort(out)
	return out
}

func (s *Server) readResult(w http.ResponseWriter, id string) {
	res, ok := s.results[id]
	if !ok {
		writeError(w, 403, 143, "Scan Result not found")
		return
	}
	s.advance(res)
	done := 0
	switch res.status {
	case "Completed", "Partial":
		done = len(res.targets)
	case "Running":
		done = len(res.targets) * res.reads / (s.o.RunningReads + 1)
	}
	writeOK(w, map[string]any{
		"id": res.id, "name": res.name, "status": res.status, "importStatus": res.importStatus,
		"running":  strconv.FormatBool(res.status == "Running" || res.status == "Queued"),
		"totalIPs": strconv.Itoa(len(res.targets)), "completedIPs": strconv.Itoa(done),
		"totalChecks": strconv.Itoa(len(res.targets) * 1000), "completedChecks": strconv.Itoa(res.checks),
		"repository": map[string]any{"id": strconv.Itoa(res.repo)},
	})
}

// advance moves a result one state on per read: Queued → Running (×
// RunningReads) → Completed + Importing → Finished or Blocked.
func (s *Server) advance(res *scanResult) {
	switch res.status {
	case "Queued":
		res.status = "Running"
	case "Running":
		res.reads++
		res.checks = len(res.targets) * 1000 * res.reads / (s.o.RunningReads + 1)
		if res.reads >= s.o.RunningReads {
			res.status, res.importStatus = "Completed", "Importing"
			res.checks = len(res.targets) * 1000
			res.scanned = s.alive(res.targets)
			if s.o.PartialScans {
				res.status = "Partial"
				res.scanned = s.alive(res.targets[:len(res.targets)/2])
			}
		}
	case "Completed", "Partial":
		if res.importStatus == "Importing" {
			s.importResult(res)
		}
	}
}

func (s *Server) alive(ips []string) []string {
	var out []string
	for _, ip := range ips {
		if h := s.hosts[ip]; h != nil && h.Alive {
			out = append(out, ip)
		}
	}
	return out
}

// importResult imports a result's hosts into its repository unless that
// would exceed the licence (Blocked, nothing imported).
func (s *Server) importResult(res *scanResult) {
	if len(res.scanned) == 0 {
		res.importStatus = "No Results"
		return
	}
	if s.activeLocked(res.scanned) > s.o.LicensedIPs {
		res.importStatus = "Blocked"
		return
	}
	for _, ip := range res.scanned {
		s.data[res.repo][ip] = true
	}
	res.importStatus = "Finished"
}

func (s *Server) stop(w http.ResponseWriter, id string) {
	res, ok := s.results[id]
	if !ok {
		writeError(w, 403, 143, "Scan Result not found")
		return
	}
	if res.status == "Running" || res.status == "Queued" {
		// What was scanned so far is kept: the first half of the targets.
		res.scanned = s.alive(res.targets[:len(res.targets)/2])
		res.status, res.importStatus = "Partial", "Importing"
	}
	writeOK(w, "")
}

type analysisBody struct {
	Type       string `json:"type"`
	SourceType string `json:"sourceType"`
	ScanID     string `json:"scanID"`
	Query      struct {
		Tool        string `json:"tool"`
		StartOffset int    `json:"startOffset"`
		EndOffset   int    `json:"endOffset"`
		Filters     []struct {
			FilterName string          `json:"filterName"`
			Value      json.RawMessage `json:"value"`
		} `json:"filters"`
	} `json:"query"`
}

func (s *Server) analysis(w http.ResponseWriter, r *http.Request) {
	var q analysisBody
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(b, &q) != nil || q.Type != "vuln" {
		writeError(w, 400, 146, "Invalid analysis query")
		return
	}
	var ips []string
	repoOf := map[string]int{}
	switch q.SourceType {
	case "individual":
		res, ok := s.results[q.ScanID]
		if !ok {
			writeError(w, 403, 143, "Scan Result not found")
			return
		}
		if res.importStatus == "Finished" {
			ips = res.scanned
			for _, ip := range ips {
				repoOf[ip] = res.repo
			}
		}
	case "cumulative":
		allowed := s.repoFilter(q)
		for _, rep := range s.repoList() {
			if allowed != nil && !allowed[rep.ID] {
				continue
			}
			for ip := range s.data[rep.ID] {
				if _, dup := repoOf[ip]; !dup {
					ips = append(ips, ip)
					repoOf[ip] = rep.ID
				}
			}
		}
		slices.Sort(ips)
	case "patched":
	default:
		writeError(w, 400, 146, "Invalid sourceType")
		return
	}
	sev := s.severityFilter(q)
	var rows []map[string]any
	for _, ip := range ips {
		h := s.hosts[ip]
		switch q.Query.Tool {
		case "sumip":
			rows = append(rows, s.hostRow(h, repoOf[ip]))
		case "vulndetails":
			for _, v := range append([]Vuln{{PluginID: "19506", Name: "Nessus Scan Information", Family: "Settings"}}, h.Vulns...) {
				if sev != nil && !sev[v.Severity] {
					continue
				}
				row := s.hostRow(h, repoOf[ip])
				row["pluginID"], row["pluginName"] = v.PluginID, v.Name
				row["severity"] = map[string]any{"id": strconv.Itoa(v.Severity)}
				row["port"], row["protocol"] = strconv.Itoa(v.Port), v.Protocol
				row["cve"], row["synopsis"], row["solution"] = v.CVE, v.Synopsis, v.Solution
				row["family"] = map[string]any{"id": "1", "name": v.Family}
				if v.CVSSV3 > 0 {
					row["cvssV3BaseScore"] = strconv.FormatFloat(v.CVSSV3, 'f', 1, 64)
				}
				now := strconv.FormatInt(time.Now().Unix(), 10)
				row["firstSeen"], row["lastSeen"] = now, now
				rows = append(rows, row)
			}
		default:
			writeError(w, 400, 146, "Unsupported tool")
			return
		}
	}
	start, end := max(q.Query.StartOffset, 0), q.Query.EndOffset
	if end <= 0 || end > len(rows) {
		end = len(rows)
	}
	if start > end {
		start = end
	}
	page := rows[start:end]
	if page == nil {
		page = []map[string]any{}
	}
	writeOK(w, map[string]any{"totalRecords": strconv.Itoa(len(rows)), "returnedRecords": strconv.Itoa(len(page)),
		"startOffset": strconv.Itoa(start), "endOffset": strconv.Itoa(end), "results": page})
}

func (s *Server) hostRow(h *Host, repo int) map[string]any {
	return map[string]any{"ip": h.IP, "dnsName": h.DNSName, "netbiosName": h.NetBIOS, "macAddress": h.MAC,
		"operatingSystem": h.OS, "repository": map[string]any{"id": strconv.Itoa(repo), "name": s.repos[repo].Name}}
}

func (s *Server) repoFilter(q analysisBody) map[int]bool {
	for _, f := range q.Query.Filters {
		if f.FilterName != "repository" {
			continue
		}
		var list []struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(f.Value, &list) != nil {
			return map[int]bool{}
		}
		out := map[int]bool{}
		for _, r := range list {
			id, _ := strconv.Atoi(r.ID)
			out[id] = true
		}
		return out
	}
	return nil
}

func (s *Server) severityFilter(q analysisBody) map[int]bool {
	for _, f := range q.Query.Filters {
		if f.FilterName != "severity" {
			continue
		}
		var v string
		if json.Unmarshal(f.Value, &v) != nil {
			return map[int]bool{}
		}
		out := map[int]bool{}
		for _, p := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err == nil {
				out[n] = true
			}
		}
		return out
	}
	return nil
}

func writeOK(w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "regular", "response": response, "error_code": 0,
		"error_msg": "", "warnings": []any{}, "timestamp": time.Now().Unix()})
}

func writeError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "regular", "response": "", "error_code": code,
		"error_msg": msg, "warnings": []any{}, "timestamp": time.Now().Unix()})
}
