package httpx

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func TestRequestTimeout(t *testing.T) {
	s := NewScanner() // 2 retries
	cases := map[time.Duration]time.Duration{
		0:                0, // no budget: httpx's own default
		30 * time.Second: 10 * time.Second,
		3 * time.Second:  MinRequestTimeout,
	}
	for budget, want := range cases {
		if got := s.RequestTimeout(budget); got != want {
			t.Errorf("RequestTimeout(%s) = %s, want %s", budget, got, want)
		}
	}
	s.Retries = 0
	if got := s.RequestTimeout(30 * time.Second); got != 30*time.Second {
		t.Errorf("no retries: %s", got)
	}
}

// One process reads the whole list (-l) with its per-request timeout; every
// JSON line is handed over with the input it names, as it is printed.
func TestScanList_OneProcessStreamsLines(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	bin := filepath.Join(dir, "httpx")
	script := `#!/bin/sh
echo "$@" >> ` + argsFile + `
prev=""; for a in "$@"; do [ "$prev" = "-l" ] && list="$a"; prev="$a"; done
while IFS= read -r t; do printf '{"input":"%s","url":"%s","status_code":200}\n' "$t" "$t"; done < "$list"
echo 'not json'
printf '{"url":"https://no-input.example"}\n'
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	s := NewScanner()
	s.Binary = bin
	targets := []string{"https://a.example", "https://b.example", "https://c.example"}
	var mu sync.Mutex
	var got []string
	res, err := s.ScanList(context.Background(), targets, nil, 10*time.Second, func(input string, line []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, input)
		if !strings.Contains(string(line), input) {
			t.Errorf("line %s for %s", line, input)
		}
	})
	if err != nil || res.ExitCode != 0 || res.Error != "" {
		t.Fatalf("res %+v err %v", res, err)
	}
	if !slices.Equal(got, targets) {
		t.Fatalf("inputs %v", got)
	}
	raw, _ := os.ReadFile(argsFile)
	calls := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(calls) != 1 {
		t.Fatalf("%d httpx processes for one list", len(calls))
	}
	args := strings.Fields(calls[0])
	if !slices.Contains(args, "-l") || slices.Contains(args, "-u") || !strings.Contains(calls[0], "-timeout 10") || !slices.Contains(args, "-threads") {
		t.Fatalf("args %q", calls[0])
	}
	flagcheck.Check(t, helpFile, args)
	r, err := s.ResultFor("https://a.example", []byte(`{"input":"https://a.example","url":"https://a.example","status_code":200}`+"\n"))
	if err != nil || len(r.LiveHosts) != 1 || r.Target != "https://a.example" {
		t.Fatalf("result %+v err %v", r, err)
	}
}
