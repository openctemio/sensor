package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The command prints exactly the profile file of the repository (the one CI
// tests the image with), as valid JSON that keeps the namespace rule.
func TestSeccompProfileCommand(t *testing.T) {
	want, err := os.ReadFile("docker/seccomp/sensor.json")
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runSeccompProfileCommand(nil, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatal("printed profile differs from docker/seccomp/sensor.json")
	}
	var doc struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names []string `json:"names"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("profile is not JSON: %v", err)
	}
	if doc.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("default action %q: the profile must deny by default", doc.DefaultAction)
	}
	unshare := false
	for _, s := range doc.Syscalls {
		for _, n := range s.Names {
			unshare = unshare || n == "unshare"
		}
	}
	if !unshare {
		t.Fatal("the profile lost the unshare rule that network confinement needs")
	}

	errOut.Reset()
	if code := runSeccompProfileCommand([]string{"extra"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage") {
		t.Fatalf("extra argument: exit %d, %q", code, errOut.String())
	}
}
