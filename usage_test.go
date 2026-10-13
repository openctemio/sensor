package main

import (
	"bytes"
	"strings"
	"testing"
)

// -help lists the subcommands, which are not flags and so are not in
// flag.PrintDefaults.
func TestMainUsageListsSubcommands(t *testing.T) {
	var b bytes.Buffer
	mainUsage(&b)
	for _, want := range []string{binName + " pair ", binName + " policy ", binName + " tools manifests", "Flags:"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("usage lacks %q:\n%s", want, b.String())
		}
	}
}
