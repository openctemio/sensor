// Package tools provides tool installation and management utilities.
package tools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Info contains information about a scanner tool.
type Info struct {
	Name           string
	Description    string
	Binary         string
	InstallMacOS   string
	InstallLinux   string
	InstallWindows string
	InstallURL     string
}

// NativeTools defines the native scanners with installation info.
var NativeTools = []Info{
	{
		Name:           "semgrep",
		Description:    "SAST scanner with dataflow/taint tracking",
		Binary:         "semgrep",
		InstallMacOS:   "brew install semgrep",
		InstallLinux:   "pip install semgrep",
		InstallWindows: "pip install semgrep",
		InstallURL:     "https://semgrep.dev/docs/getting-started/",
	},
	{
		Name:           "betterleaks",
		Description:    "Secret detection scanner",
		Binary:         "betterleaks",
		InstallMacOS:   "brew install --cask betterleaks/tap/betterleaks@1  # installs betterleaks-v1",
		InstallLinux:   "go install github.com/betterleaks/betterleaks@v1.9.0  # or a v1.x release archive",
		InstallWindows: "go install github.com/betterleaks/betterleaks@v1.9.0",
		InstallURL:     "https://github.com/betterleaks/betterleaks#installation",
	},
	{
		Name:           "trivy",
		Description:    "SCA/Container/IaC scanner",
		Binary:         "trivy",
		InstallMacOS:   "brew install trivy",
		InstallLinux:   "sudo apt-get install trivy  # or brew install trivy",
		InstallWindows: "choco install trivy",
		InstallURL:     "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
	},
	{
		Name:           "nuclei",
		Description:    "Vulnerability scanner (DAST)",
		Binary:         "nuclei",
		InstallMacOS:   "brew install nuclei",
		InstallLinux:   "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		InstallWindows: "choco install nuclei",
		InstallURL:     "https://docs.projectdiscovery.io/tools/nuclei/install",
	},
}

// DetectOS returns the current operating system.
func DetectOS() string {
	return runtime.GOOS
}

// CheckInstalled checks if a binary is installed and returns its version.
func CheckInstalled(ctx context.Context, binary string) (bool, string, error) {
	st := Probe(ctx, binary)
	if st.State != Available {
		return false, "", st.Err
	}
	return true, st.Version, nil
}

// State is the result of probing a scanner binary.
type State int

const (
	// Available: the binary is on PATH and `--version` succeeds.
	Available State = iota
	// NotInstalled: the binary is not on PATH.
	NotInstalled
	// Broken: the binary is on PATH but `--version` fails. A broken tool
	// is never "not installed": the image or host shipped it and it does
	// not run (for example semgrep without pkg_resources), which must be
	// reported, not silently skipped.
	Broken
)

// Status describes one probed binary.
type Status struct {
	Binary  string
	State   State
	Path    string // resolved path, when found
	Version string // parsed version, when Available
	Err     error  // why it is not Available
}

// maxDetailLines bounds how much of a failing tool's output Status keeps.
const maxDetailLines = 6

// Probe looks the binary up on PATH and runs `<binary> --version`.
func Probe(ctx context.Context, binary string) Status {
	st := Status{Binary: binary}
	path, err := exec.LookPath(binary)
	if err != nil {
		st.State = NotInstalled
		st.Err = fmt.Errorf("%s not found on PATH", binary)
		return st
	}
	st.Path = path
	output, err := exec.CommandContext(ctx, path, "--version").CombinedOutput() //nolint:gosec // probing a known scanner binary
	if err != nil {
		st.State = Broken
		st.Err = fmt.Errorf("%s is installed (%s) but `%s --version` failed: %w%s", binary, path, binary, err, tail(string(output)))
		return st
	}
	st.State = Available
	st.Version = ParseVersion(binary, string(output))
	return st
}

// Describe is a one-line, human-readable status ("available: 1.2.3",
// "not installed", "BROKEN: ...").
func (s Status) Describe() string {
	switch s.State {
	case Available:
		return "available: " + s.Version
	case NotInstalled:
		return "not installed"
	default:
		return "BROKEN: " + s.Err.Error()
	}
}

// tail returns the last lines of a tool's output, indented, for an error.
func tail(output string) string {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return ""
	}
	if len(lines) > maxDetailLines {
		lines = lines[len(lines)-maxDetailLines:]
	}
	return "\n    " + strings.Join(lines, "\n    ")
}

// BinaryFor returns the binary a scanner name runs ("trivy-fs" runs trivy).
func BinaryFor(scanner string) string {
	scanner = core.CanonicalScannerName(scanner)
	if strings.HasPrefix(scanner, "trivy") {
		return "trivy"
	}
	for _, t := range NativeTools {
		if t.Name == scanner {
			return t.Binary
		}
	}
	return scanner
}

// CheckAndReport checks tool installation status and prints a report.
// If install is true, it also installs missing tools interactively.
func CheckAndReport(ctx context.Context, w io.Writer, install bool) {
	_, _ = fmt.Fprintln(w, "Checking scanner tools installation...")
	_, _ = fmt.Fprintln(w)

	osType := DetectOS()
	var missingTools []Info

	for _, tool := range NativeTools {
		st := Probe(ctx, tool.Binary)

		switch st.State {
		case Available:
			_, _ = fmt.Fprintf(w, "  ✓ %-12s %s (installed: %s)\n", tool.Name, tool.Description, st.Version)
		case NotInstalled:
			_, _ = fmt.Fprintf(w, "  ✗ %-12s %s (NOT INSTALLED)\n", tool.Name, tool.Description)
			missingTools = append(missingTools, tool)
		default:
			_, _ = fmt.Fprintf(w, "  ✗ %-12s %s (INSTALLED BUT BROKEN)\n    %v\n", tool.Name, tool.Description, st.Err)
			missingTools = append(missingTools, tool)
		}
	}

	_, _ = fmt.Fprintln(w)

	if len(missingTools) == 0 {
		_, _ = fmt.Fprintln(w, "All tools are installed! Ready to scan.")
		return
	}

	_, _ = fmt.Fprintf(w, "Missing %d tool(s).\n\n", len(missingTools))

	if install {
		InstallInteractive(ctx, missingTools, osType)
	} else {
		PrintInstructions(w, missingTools, osType)
	}
}

// PrintInstructions prints installation instructions for missing tools.
func PrintInstructions(w io.Writer, tools []Info, osType string) {
	_, _ = fmt.Fprintln(w, "Installation instructions:")
	_, _ = fmt.Fprintln(w)

	for _, tool := range tools {
		_, _ = fmt.Fprintf(w, "  %s:\n", tool.Name)
		switch osType {
		case "darwin":
			_, _ = fmt.Fprintf(w, "    macOS:   %s\n", tool.InstallMacOS)
		case "linux":
			_, _ = fmt.Fprintf(w, "    Linux:   %s\n", tool.InstallLinux)
		case "windows":
			_, _ = fmt.Fprintf(w, "    Windows: %s\n", tool.InstallWindows)
		default:
			_, _ = fmt.Fprintf(w, "    macOS:   %s\n", tool.InstallMacOS)
			_, _ = fmt.Fprintf(w, "    Linux:   %s\n", tool.InstallLinux)
			_, _ = fmt.Fprintf(w, "    Windows: %s\n", tool.InstallWindows)
		}
		_, _ = fmt.Fprintf(w, "    Docs:    %s\n", tool.InstallURL)
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintln(w, "Run with -install-tools to install interactively.")
}

// InstallInteractive installs missing tools interactively.
func InstallInteractive(ctx context.Context, tools []Info, osType string) {
	reader := bufio.NewReader(os.Stdin)

	for _, tool := range tools {
		var installCmd string
		switch osType {
		case "darwin":
			installCmd = tool.InstallMacOS
		case "linux":
			installCmd = tool.InstallLinux
		case "windows":
			installCmd = tool.InstallWindows
		default:
			installCmd = tool.InstallMacOS
		}

		fmt.Printf("Install %s? [y/N] ", tool.Name)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input != "y" && input != "yes" {
			fmt.Printf("  Skipped %s\n\n", tool.Name)
			continue
		}

		fmt.Printf("  Installing %s...\n", tool.Name)
		fmt.Printf("  Command: %s\n", installCmd)

		// Parse and execute command
		parts := strings.Fields(installCmd)
		if len(parts) == 0 {
			fmt.Println("  Error: invalid install command")
			continue
		}

		// Execute the install command
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...) //nolint:gosec // Intentional tool installation
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("  Error installing %s: %v\n", tool.Name, err)
			fmt.Printf("  Please install manually: %s\n\n", tool.InstallURL)
			continue
		}

		// Verify installation
		installed, version, _ := CheckInstalled(ctx, tool.Binary)
		if installed {
			fmt.Printf("  ✓ %s installed successfully (version: %s)\n\n", tool.Name, version)
		} else {
			fmt.Printf("  Warning: %s may not be in PATH. Please verify installation.\n\n", tool.Name)
		}
	}
}

// ansiEscape matches terminal color sequences (nuclei colors its log lines).
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// ParseVersion extracts clean version string from tool output.
func ParseVersion(tool, output string) string {
	output = strings.TrimSpace(ansiEscape.ReplaceAllString(output, ""))
	lines := strings.Split(output, "\n")

	// Get first non-empty, non-warning line
	var firstLine string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip warning lines
		if strings.Contains(line, "WARNING") || strings.Contains(line, "warning") {
			continue
		}
		firstLine = line
		break
	}

	if firstLine == "" && len(lines) > 0 {
		firstLine = strings.TrimSpace(lines[0])
	}

	// Tool-specific parsing
	switch tool {
	case "semgrep":
		// semgrep output is noisy - version is usually the last line that looks like a version
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			if IsVersionString(line) {
				return line
			}
		}
		// Fallback: try to find version in any line
		for _, line := range lines {
			for _, part := range strings.Fields(line) {
				if IsVersionString(part) {
					return part
				}
			}
		}
		return firstLine

	case "betterleaks":
		// betterleaks --version: "betterleaks version 1.9.0"
		if strings.Contains(firstLine, "version") {
			parts := strings.Fields(firstLine)
			for i, p := range parts {
				if p == "version" && i+1 < len(parts) {
					return parts[i+1]
				}
			}
		}
		return firstLine

	case "trivy":
		// trivy output: "Version: 0.67.2"
		if after, ok := strings.CutPrefix(firstLine, "Version:"); ok {
			return strings.TrimSpace(after)
		}
		return firstLine

	case "nuclei":
		// nuclei output: "[INF] Nuclei Engine Version: v3.4.1" among other lines
		for _, line := range lines {
			if _, after, ok := strings.Cut(line, "Engine Version:"); ok {
				return strings.TrimSpace(after)
			}
		}
		return firstLine

	default:
		return firstLine
	}
}

// IsVersionString checks if a string looks like a version number.
func IsVersionString(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Version strings typically start with a digit
	if s[0] >= '0' && s[0] <= '9' {
		return true
	}
	// Or start with 'v' followed by digit
	if len(s) > 1 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
		return true
	}
	return false
}
