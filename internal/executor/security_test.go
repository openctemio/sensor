package executor

import (
	"strings"
	"testing"
)

func TestValidateExtraArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		// Valid arguments
		{
			name:    "severity flag",
			args:    []string{"-severity", "critical"},
			wantErr: false,
		},
		{
			name:    "rate-limit flag",
			args:    []string{"--rate-limit", "100"},
			wantErr: false,
		},
		{
			name:    "multiple valid flags",
			args:    []string{"-severity", "critical", "--rate-limit", "100"},
			wantErr: false,
		},
		{
			name:    "empty args",
			args:    []string{},
			wantErr: false,
		},
		{
			name:    "nil args",
			args:    nil,
			wantErr: false,
		},

		// Dangerous flags: output
		{
			name:    "short output flag blocked",
			args:    []string{"-o", "/tmp/output.json"},
			wantErr: true,
		},
		{
			name:    "long output flag blocked",
			args:    []string{"--output", "/tmp/out"},
			wantErr: true,
		},
		{
			name:    "nmap-style output flags blocked -oA",
			args:    []string{"-oA", "/tmp/scan"},
			wantErr: true,
		},
		{
			name:    "nmap-style output flags blocked -oN",
			args:    []string{"-oN", "/tmp/scan"},
			wantErr: true,
		},
		{
			name:    "nmap-style output flags blocked -oX",
			args:    []string{"-oX", "/tmp/scan"},
			wantErr: true,
		},

		// Dangerous flags: proxy
		{
			name:    "proxy flag blocked",
			args:    []string{"--proxy", "http://evil.com"},
			wantErr: true,
		},
		{
			name:    "short proxy flag blocked",
			args:    []string{"-proxy", "http://evil.com"},
			wantErr: true,
		},
		{
			name:    "proxy with equals syntax blocked",
			args:    []string{"-proxy=http://evil.com"},
			wantErr: true,
		},
		{
			name:    "http-proxy flag blocked",
			args:    []string{"-http-proxy", "http://evil.com"},
			wantErr: true,
		},

		// Dangerous flags: config
		{
			name:    "config flag blocked",
			args:    []string{"--config", "/etc/nuclei.yaml"},
			wantErr: true,
		},
		{
			name:    "short config flag blocked",
			args:    []string{"-c", "/etc/nuclei.yaml"},
			wantErr: true,
		},

		// Dangerous flags: interactsh
		{
			name:    "interactsh-url flag blocked",
			args:    []string{"--interactsh-url", "http://evil.com"},
			wantErr: true,
		},

		// Dangerous flags: input list
		{
			name:    "input list flag blocked",
			args:    []string{"-iL", "/tmp/targets.txt"},
			wantErr: true,
		},
		{
			name:    "long input list flag blocked",
			args:    []string{"--input-list", "/tmp/targets.txt"},
			wantErr: true,
		},

		// Dangerous flags: headless
		{
			name:    "headless flag blocked",
			args:    []string{"--headless"},
			wantErr: true,
		},

		// Dangerous flags: report-db
		{
			name:    "report-db flag blocked",
			args:    []string{"--report-db", "/tmp/db"},
			wantErr: true,
		},

		// Equals syntax for other flags
		{
			name:    "output with equals syntax blocked",
			args:    []string{"--output=/tmp/out"},
			wantErr: true,
		},
		{
			name:    "config with equals syntax blocked",
			args:    []string{"--config=/etc/nuclei.yaml"},
			wantErr: true,
		},

		// Case insensitivity
		{
			name:    "uppercase output flag blocked",
			args:    []string{"--OUTPUT", "/tmp/out"},
			wantErr: true,
		},
		{
			name:    "mixed case proxy flag blocked",
			args:    []string{"--Proxy", "http://evil.com"},
			wantErr: true,
		},

		// Dangerous flag mixed with valid args
		{
			name:    "dangerous flag among valid args",
			args:    []string{"-severity", "critical", "--proxy", "http://evil.com"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExtraArgs(tt.args)
			if tt.wantErr && err == nil {
				t.Errorf("validateExtraArgs(%v) expected error, got nil", tt.args)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateExtraArgs(%v) unexpected error: %v", tt.args, err)
			}
		})
	}
}

func TestValidateExtraArgs_ErrorContainsFlag(t *testing.T) {
	// Verify the error message mentions which flag was disallowed
	err := validateExtraArgs([]string{"--proxy", "http://evil.com"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "disallowed flag") {
		t.Errorf("error = %q, want to contain 'disallowed flag'", err.Error())
	}
}

func TestDangerousToolFlags_Completeness(t *testing.T) {
	// Map keys are stored canonically lowercase because validateExtraArgs
	// lowercases each ExtraArgs entry before lookup — the runtime is
	// case-insensitive, the map is not. Tests must mirror the storage
	// convention, not the on-the-wire casing of the underlying tools.
	expectedFlags := []string{
		"-o", "--output",
		"-oa", "-on", "-ox", "-og", "-oj",
		"-proxy", "--proxy", "-http-proxy",
		"-il", "--input-list",
		"--report-db",
		"-c", "--config",
		"-t", "--templates",
		"-iserver", "--interactsh-url",
		"--headless",
		"-r", "--resolvers",
		"-interface", "--interface",
		"-source-ip", "--source-ip",
	}

	for _, flag := range expectedFlags {
		if !dangerousToolFlags[flag] {
			t.Errorf("expected %q to be in dangerousToolFlags map", flag)
		}
	}
}

// TestValidateExtraArgs_CaseInsensitive pins the case-insensitivity
// contract explicitly so a future refactor that moves to a case-
// sensitive lookup can't silently regress (nmap etc. use -oA / -oN
// capitalised). This is the behaviour the SDK scanners + agent
// security audit relies on; TestDangerousToolFlags_Completeness alone
// doesn't exercise it.
func TestValidateExtraArgs_CaseInsensitive(t *testing.T) {
	cases := []string{"-oA", "-oN", "-oX", "-iL", "--PROXY", "--Config", "--Resolvers", "--Headless"}
	for _, arg := range cases {
		if err := validateExtraArgs([]string{arg}); err == nil {
			t.Errorf("expected validateExtraArgs(%q) to reject — case-insensitive lookup failed", arg)
		}
	}
}
