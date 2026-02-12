//go:build !hybrid

package executor

// =============================================================================
// HYBRID MODE STUB (Default build without -tags hybrid)
// CLI-only mode - no library dependencies
// =============================================================================

// HybridModeEnabled indicates hybrid library mode is NOT available.
const HybridModeEnabled = false

// HybridReconConfig extends ReconConfig with library preference settings.
// In non-hybrid mode, library preferences are ignored.
type HybridReconConfig struct {
	*ReconConfig

	// Prefer library over CLI when available (ignored in non-hybrid mode)
	PreferLibrary bool

	// Per-tool library preference (ignored in non-hybrid mode)
	SubfinderUseLib bool
	DNSXUseLib      bool
	NaabuUseLib     bool
	HTTPXUseLib     bool
	KatanaUseLib    bool
}

// DefaultHybridReconConfig returns CLI-only defaults in non-hybrid mode.
func DefaultHybridReconConfig() *HybridReconConfig {
	return &HybridReconConfig{
		ReconConfig:   DefaultReconConfig(),
		PreferLibrary: false, // Library mode not available
	}
}

// CreateHybridTools creates CLI-only tool executors in non-hybrid mode.
func CreateHybridTools(cfg *HybridReconConfig, verbose bool) map[string]ToolExecutor {
	tools := make(map[string]ToolExecutor)

	if cfg.SubfinderEnabled {
		tools["subfinder"] = &cliToolExecutor{
			name:         "subfinder",
			binary:       getPathOrDefaultStub("subfinder", cfg.SubfinderPath),
			capabilities: []string{"subdomain"},
			outputFlag:   "-oJ",
			targetFlag:   "-d",
			defaultArgs:  []string{"-silent"},
		}
	}

	if cfg.DNSXEnabled {
		tools["dnsx"] = &cliToolExecutor{
			name:         "dnsx",
			binary:       getPathOrDefaultStub("dnsx", cfg.DNSXPath),
			capabilities: []string{"dns"},
			outputFlag:   "-j",
			targetFlag:   "-d",
			defaultArgs:  []string{"-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt"},
		}
	}

	if cfg.NaabuEnabled {
		tools["naabu"] = &cliToolExecutor{
			name:         "naabu",
			binary:       getPathOrDefaultStub("naabu", cfg.NaabuPath),
			capabilities: []string{"portscan"},
			outputFlag:   "-j",
			targetFlag:   "-host",
			defaultArgs:  []string{"-silent"},
		}
	}

	if cfg.HTTPXEnabled {
		tools["httpx"] = &cliToolExecutor{
			name:         "httpx",
			binary:       getPathOrDefaultStub("httpx", cfg.HTTPXPath),
			capabilities: []string{"http", "tech-detect"},
			outputFlag:   "-j",
			targetFlag:   "-u",
			defaultArgs:  []string{"-silent", "-sc", "-title", "-server", "-td", "-ct"},
		}
	}

	if cfg.KatanaEnabled {
		tools["katana"] = &cliToolExecutor{
			name:         "katana",
			binary:       getPathOrDefaultStub("katana", cfg.KatanaPath),
			capabilities: []string{"crawler", "url-discovery"},
			outputFlag:   "-j",
			targetFlag:   "-u",
			defaultArgs:  []string{"-silent"},
		}
	}

	return tools
}

func getPathOrDefaultStub(name, configPath string) string {
	if configPath != "" {
		return configPath
	}
	return name
}
