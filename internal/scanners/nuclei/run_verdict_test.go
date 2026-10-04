package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const oneResult = `{"template-id":"fake-check","info":{"name":"Fake","severity":"low"},"host":"h.example.test","matched-at":"https://h.example.test/","type":"http"}` + "\n"

func TestRunVerdict(t *testing.T) {
	cases := []struct {
		name        string
		exit        int
		out, stderr string
		wantErr     bool
		wantPartial bool
	}{
		{"clean run, no findings", 0, "", "[INF] Templates loaded: 120", false, false},
		{"clean run, findings", 0, oneResult, "", false, false},
		{"no templates loaded", 1, "", "[FTL] Could not run nuclei: no templates provided for scan", true, false},
		{"exit 1, no output", 1, "", "something broke", true, false},
		{"exit 2, no output", 2, "  \n", "", true, false},
		{"fatal line on exit 0, no output", 0, "", "[FTL] could not create runner", true, false},
		{"stopped part-way", 1, oneResult, "[FTL] context deadline exceeded", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := runVerdict(tc.exit, []byte(tc.out), tc.stderr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if partial := msg != ""; partial != tc.wantPartial {
				t.Fatalf("errMsg = %q, want partial %v", msg, tc.wantPartial)
			}
			if tc.wantErr && tc.stderr != "" && strings.HasPrefix(tc.stderr, "[FTL]") && !strings.Contains(err.Error(), "[FTL]") {
				t.Errorf("error should quote the fatal line: %v", err)
			}
		})
	}
}

// stubNucleiRun writes a stand-in nuclei binary that prints stdout and stderr
// and exits with code.
func stubNucleiRun(t *testing.T, stdout, stderr string, code int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "out.txt"), []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "err.txt"), []byte(stderr), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "nuclei")
	script := "#!/bin/sh\ncat '" + filepath.Join(dir, "out.txt") + "'\ncat '" + filepath.Join(dir, "err.txt") + "' >&2\nexit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test stand-in must be executable
		t.Fatal(err)
	}
	return bin
}

// A nuclei run that loaded no templates exits 1 with no output. It must fail,
// not complete as a clean 0-finding scan.
func TestRun_NoTemplatesFails(t *testing.T) {
	s := NewScanner()
	s.Binary = stubNucleiRun(t, "", "[FTL] Could not run nuclei: no templates provided for scan\n", 1)
	res, err := s.run(context.Background(), []string{"-u", "https://h.example.test"}, nil, nil, "h.example.test")
	if err == nil {
		t.Fatalf("run succeeded with result %+v, want an error", res)
	}
	if !strings.Contains(err.Error(), "no templates") {
		t.Errorf("error does not say why: %v", err)
	}
}

// A run that stopped part-way keeps its results and says it is partial.
func TestRun_PartialRunKeepsResultsAndSaysSo(t *testing.T) {
	s := NewScanner()
	s.Binary = stubNucleiRun(t, oneResult, "[FTL] context deadline exceeded\n", 1)
	res, err := s.run(context.Background(), []string{"-u", "https://h.example.test"}, nil, nil, "h.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RawOutput) == 0 || res.Error == "" || !strings.Contains(res.Error, "partial") {
		t.Fatalf("result = output %d bytes, error %q; want results and a partial error", len(res.RawOutput), res.Error)
	}
}

func TestRun_CleanRun(t *testing.T) {
	s := NewScanner()
	s.Binary = stubNucleiRun(t, oneResult, "[INF] done\n", 0)
	res, err := s.run(context.Background(), []string{"-u", "https://h.example.test"}, nil, nil, "h.example.test")
	if err != nil || res.Error != "" {
		t.Fatalf("clean run: err %v, result error %q", err, res.Error)
	}
}
