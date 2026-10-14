package executor

import "testing"

// A port scan hands probes "address:port" targets; the guard checks the host
// part, never a DNS lookup of the whole string.
func TestValidateScannerTargetHostPort(t *testing.T) {
	ok := []string{"8.8.8.8:80", "8.8.8.8:443", "[2001:4860:4860::8888]:443", "2001:4860:4860::8888", "https://8.8.8.8:8443/x"}
	for _, target := range ok {
		if err := validateScannerTarget(target); err != nil {
			t.Errorf("%s: %v", target, err)
		}
	}
	refused := []string{"127.0.0.1:80", "169.254.169.254:80", "[::1]:443", "localhost:8080"}
	for _, target := range refused {
		if err := validateScannerTarget(target); err == nil {
			t.Errorf("%s: want refused", target)
		}
	}
}
