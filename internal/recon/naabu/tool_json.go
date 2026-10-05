package naabu

import "encoding/json"

// The sensor hands a configured scanner to its tool child as JSON (the
// out-of-process path, internal/recon/tool.go). A scan's settings set two
// unexported fields (the lowered packet rate and whether retries were
// given), so they travel too; the version travels separately (SetVersion).

type scannerAlias Scanner

type scannerJSON struct {
	*scannerAlias
	ScanRate   int  `json:"ScanRate,omitempty"`
	RetriesSet bool `json:"RetriesSet,omitempty"`
}

// MarshalJSON encodes the scanner with the settings a scan applied.
func (s *Scanner) MarshalJSON() ([]byte, error) {
	return json.Marshal(scannerJSON{scannerAlias: (*scannerAlias)(s), ScanRate: s.scanRate, RetriesSet: s.retriesSet})
}

// UnmarshalJSON decodes what MarshalJSON wrote.
func (s *Scanner) UnmarshalJSON(data []byte) error {
	v := scannerJSON{scannerAlias: (*scannerAlias)(s)}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	s.scanRate, s.retriesSet = v.ScanRate, v.RetriesSet
	return nil
}

// SetVersion sets the version IsInstalled found (a tool child that did not
// probe the binary itself reports the parent's).
func (s *Scanner) SetVersion(v string) { s.version = v }

// RawSockets reports whether the scan needs raw sockets (a SYN scan). The
// tool sandbox grants no capabilities, so such a scan stays on the direct
// path; the sensor pins the connect scan, which needs none.
func (s *Scanner) RawSockets() bool { return s.ScanType == ScanTypeSYN }
