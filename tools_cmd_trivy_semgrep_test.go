package main

import "testing"

func TestToolsManifestsListsTrivySemgrep(t *testing.T) { requireListed(t, "trivy", "semgrep") }
