// Package config provides configuration types for the modular platform agent.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the main configuration for the platform agent.
type Config struct {
	Agent     AgentConfig     `yaml:"agent"`
	API       APIConfig       `yaml:"api"`
	Executors ExecutorsConfig `yaml:"executors"`
}

// AgentConfig contains agent-level settings.
type AgentConfig struct {
	Name          string        `yaml:"name"`
	Region        string        `yaml:"region"`
	MaxJobs       int           `yaml:"max_jobs"`
	LeaseDuration time.Duration `yaml:"lease_duration"`
	RenewInterval time.Duration `yaml:"renew_interval"`
	Verbose       bool          `yaml:"verbose"`
}

// APIConfig contains API connection settings.
type APIConfig struct {
	BaseURL string `yaml:"base_url"`
	APIKey  string `yaml:"api_key"`
	AgentID string `yaml:"agent_id"`
	Timeout int    `yaml:"timeout"` // seconds
}

// ExecutorsConfig contains settings for all executor modules.
type ExecutorsConfig struct {
	Recon    ReconExecutorConfig    `yaml:"recon"`
	VulnScan VulnScanExecutorConfig `yaml:"vulnscan"`
	Secrets  SecretsExecutorConfig  `yaml:"secrets"`
	Assets   AssetsExecutorConfig   `yaml:"assets"`
}

// ReconExecutorConfig configures the recon executor.
type ReconExecutorConfig struct {
	Enabled      bool            `yaml:"enabled"`
	Tools        ReconToolsConfig `yaml:"tools"`
	Capabilities []string        `yaml:"capabilities"`
	Settings     ReconSettings   `yaml:"settings"`
}

// ReconToolsConfig enables/disables individual recon tools.
type ReconToolsConfig struct {
	Subfinder bool `yaml:"subfinder"`
	DNSX      bool `yaml:"dnsx"`
	Naabu     bool `yaml:"naabu"`
	HTTPX     bool `yaml:"httpx"`
	Katana    bool `yaml:"katana"`
}

// ReconSettings contains global settings for recon tools.
type ReconSettings struct {
	DefaultTimeout int `yaml:"default_timeout"` // seconds
	DefaultThreads int `yaml:"default_threads"`
	RateLimit      int `yaml:"rate_limit"`

	// Custom binary paths
	SubfinderPath string `yaml:"subfinder_path"`
	DNSXPath      string `yaml:"dnsx_path"`
	NaabuPath     string `yaml:"naabu_path"`
	HTTPXPath     string `yaml:"httpx_path"`
	KatanaPath    string `yaml:"katana_path"`
}

// VulnScanExecutorConfig configures the vulnerability scanning executor.
type VulnScanExecutorConfig struct {
	Enabled      bool                `yaml:"enabled"`
	Tools        VulnScanToolsConfig `yaml:"tools"`
	Capabilities []string            `yaml:"capabilities"`
}

// VulnScanToolsConfig enables/disables individual vuln scan tools.
type VulnScanToolsConfig struct {
	Nuclei  bool `yaml:"nuclei"`
	Trivy   bool `yaml:"trivy"`
	Semgrep bool `yaml:"semgrep"`
}

// SecretsExecutorConfig configures the secret scanning executor.
type SecretsExecutorConfig struct {
	Enabled      bool               `yaml:"enabled"`
	Tools        SecretsToolsConfig `yaml:"tools"`
	Capabilities []string           `yaml:"capabilities"`
}

// SecretsToolsConfig enables/disables individual secret scan tools.
type SecretsToolsConfig struct {
	Gitleaks   bool `yaml:"gitleaks"`
	Trufflehog bool `yaml:"trufflehog"`
}

// AssetsExecutorConfig configures the asset collection executor.
type AssetsExecutorConfig struct {
	Enabled      bool              `yaml:"enabled"`
	Tools        AssetsToolsConfig `yaml:"tools"`
	Capabilities []string          `yaml:"capabilities"`
}

// AssetsToolsConfig enables/disables individual asset collectors.
type AssetsToolsConfig struct {
	AWS    bool `yaml:"aws"`
	GCP    bool `yaml:"gcp"`
	Azure  bool `yaml:"azure"`
	GitHub bool `yaml:"github"`
	GitLab bool `yaml:"gitlab"`
}

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Agent: AgentConfig{
			Name:          "platform-agent",
			Region:        "default",
			MaxJobs:       5,
			LeaseDuration: 60 * time.Second,
			RenewInterval: 20 * time.Second,
			Verbose:       false,
		},
		API: APIConfig{
			BaseURL: "https://api.openctem.io",
			Timeout: 30,
		},
		Executors: ExecutorsConfig{
			Recon: ReconExecutorConfig{
				Enabled: true,
				Tools: ReconToolsConfig{
					Subfinder: true,
					DNSX:      true,
					Naabu:     true,
					HTTPX:     true,
					Katana:    true,
				},
				Capabilities: []string{"subdomain", "dns", "portscan", "http", "crawler", "tech-detect"},
				Settings: ReconSettings{
					DefaultTimeout: 300,
					DefaultThreads: 50,
					RateLimit:      150,
				},
			},
			VulnScan: VulnScanExecutorConfig{
				Enabled: true,
				Tools: VulnScanToolsConfig{
					Nuclei:  true,
					Trivy:   true,
					Semgrep: true,
				},
				Capabilities: []string{"dast", "sca", "iac", "container", "sast"},
			},
			Secrets: SecretsExecutorConfig{
				Enabled: false,
				Tools: SecretsToolsConfig{
					Gitleaks:   true,
					Trufflehog: true,
				},
				Capabilities: []string{"secret"},
			},
			Assets: AssetsExecutorConfig{
				Enabled: false,
				Tools: AssetsToolsConfig{
					AWS:    false,
					GCP:    false,
					Azure:  false,
					GitHub: false,
					GitLab: false,
				},
				Capabilities: []string{"cloud", "scm"},
			},
		},
	}
}

// =============================================================================
// LOADING
// =============================================================================

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return LoadFromBytes(data)
}

// LoadFromBytes loads configuration from YAML bytes.
func LoadFromBytes(data []byte) (*Config, error) {
	cfg := DefaultConfig()

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// =============================================================================
// HELPERS
// =============================================================================

// GetEnabledExecutors returns the names of enabled executors.
func (c *Config) GetEnabledExecutors() []string {
	var enabled []string

	if c.Executors.Recon.Enabled {
		enabled = append(enabled, "recon")
	}
	if c.Executors.VulnScan.Enabled {
		enabled = append(enabled, "vulnscan")
	}
	if c.Executors.Secrets.Enabled {
		enabled = append(enabled, "secrets")
	}
	if c.Executors.Assets.Enabled {
		enabled = append(enabled, "assets")
	}

	return enabled
}

// GetAllCapabilities returns all capabilities from enabled executors.
func (c *Config) GetAllCapabilities() []string {
	var caps []string

	if c.Executors.Recon.Enabled {
		caps = append(caps, c.Executors.Recon.Capabilities...)
	}
	if c.Executors.VulnScan.Enabled {
		caps = append(caps, c.Executors.VulnScan.Capabilities...)
	}
	if c.Executors.Secrets.Enabled {
		caps = append(caps, c.Executors.Secrets.Capabilities...)
	}
	if c.Executors.Assets.Enabled {
		caps = append(caps, c.Executors.Assets.Capabilities...)
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := make([]string, 0, len(caps))
	for _, cap := range caps {
		if !seen[cap] {
			unique = append(unique, cap)
			seen[cap] = true
		}
	}

	return unique
}

// GetEnabledReconTools returns the list of enabled recon tools.
func (c *Config) GetEnabledReconTools() []string {
	var tools []string

	if !c.Executors.Recon.Enabled {
		return tools
	}

	if c.Executors.Recon.Tools.Subfinder {
		tools = append(tools, "subfinder")
	}
	if c.Executors.Recon.Tools.DNSX {
		tools = append(tools, "dnsx")
	}
	if c.Executors.Recon.Tools.Naabu {
		tools = append(tools, "naabu")
	}
	if c.Executors.Recon.Tools.HTTPX {
		tools = append(tools, "httpx")
	}
	if c.Executors.Recon.Tools.Katana {
		tools = append(tools, "katana")
	}

	return tools
}
