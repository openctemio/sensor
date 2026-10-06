package main

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit"
)

func TestResolveJobID(t *testing.T) {
	t.Setenv(sensorkit.EnvJobID, "")
	if got := resolveJobID(""); got != "" {
		t.Fatalf("no flag, no env: %q", got)
	}
	t.Setenv(sensorkit.EnvJobID, " 0192a3b4-0000-7000-8000-0000000000a2 ")
	if got := resolveJobID(""); got != "0192a3b4-0000-7000-8000-0000000000a2" {
		t.Fatalf("env: %q", got)
	}
	if got := resolveJobID("0192a3b4-0000-7000-8000-0000000000a3"); got != "0192a3b4-0000-7000-8000-0000000000a3" {
		t.Fatalf("the flag beats the env: %q", got)
	}
}
