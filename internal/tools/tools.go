// Package tools provides tool installation and management utilities.
package tools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
		Name:           "gitleaks",
		Description:    "Secret detection scanner",
		Binary:         "gitleaks",
		InstallMacOS:   "brew install gitleaks",
		InstallLinux:   "brew install gitleaks  # or download from GitHub releases",
		InstallWindows: "choco install gitleaks",
		InstallURL:     "https://github.com/gitleaks/gitleaks#installing",
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
	cmd := exec.CommandContext(ctx, binary, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", err
	}

	version := ParseVersion(binary, string(output))
	return true, version, nil
}

// CheckAndReport checks tool installation status and prints a report.
// If install is true, it also installs missing tools interactively.
func CheckAndReport(ctx context.Context, w io.Writer, install bool) {
	fmt.Fprintln(w, "Checking scanner tools installation...")
	fmt.Fprintln(w)

	osType := DetectOS()
	var missingTools []Info

	for _, tool := range NativeTools {
		installed, version, _ := CheckInstalled(ctx, tool.Binary)

		if installed {
			fmt.Fprintf(w, "  ✓ %-12s %s (installed: %s)\n", tool.Name, tool.Description, version)
		} else {
			fmt.Fprintf(w, "  ✗ %-12s %s (NOT INSTALLED)\n", tool.Name, tool.Description)
			missingTools = append(missingTools, tool)
		}
	}

	fmt.Fprintln(w)

	if len(missingTools) == 0 {
		fmt.Fprintln(w, "All tools are installed! Ready to scan.")
		return
	}

	fmt.Fprintf(w, "Missing %d tool(s).\n\n", len(missingTools))

	if install {
		InstallInteractive(ctx, missingTools, osType)
	} else {
		PrintInstructions(w, missingTools, osType)
	}
}

// PrintInstructions prints installation instructions for missing tools.
func PrintInstructions(w io.Writer, tools []Info, osType string) {
	fmt.Fprintln(w, "Installation instructions:")
	fmt.Fprintln(w)

	for _, tool := range tools {
		fmt.Fprintf(w, "  %s:\n", tool.Name)
		switch osType {
		case "darwin":
			fmt.Fprintf(w, "    macOS:   %s\n", tool.InstallMacOS)
		case "linux":
			fmt.Fprintf(w, "    Linux:   %s\n", tool.InstallLinux)
		case "windows":
			fmt.Fprintf(w, "    Windows: %s\n", tool.InstallWindows)
		default:
			fmt.Fprintf(w, "    macOS:   %s\n", tool.InstallMacOS)
			fmt.Fprintf(w, "    Linux:   %s\n", tool.InstallLinux)
			fmt.Fprintf(w, "    Windows: %s\n", tool.InstallWindows)
		}
		fmt.Fprintf(w, "    Docs:    %s\n", tool.InstallURL)
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Run with -install-tools to install interactively.")
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

// ParseVersion extracts clean version string from tool output.
func ParseVersion(tool, output string) string {
	output = strings.TrimSpace(output)
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

	case "gitleaks":
		// gitleaks output: "gitleaks version 8.28.0"
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
