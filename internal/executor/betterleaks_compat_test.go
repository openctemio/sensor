package executor

import "testing"

func TestRetiredSecretScannerNameIsRoutedAndConfined(t *testing.T) {
	for _, name := range []string{"betterleaks", "gitleaks"} {
		if got := inferJobType(name); got != "secrets" {
			t.Errorf("inferJobType(%q) = %q, want secrets", name, got)
		}
		if !IsCodeScanner(name) {
			t.Errorf("IsCodeScanner(%q) = false: its target must be confined to the scan workspace", name)
		}
	}
}
