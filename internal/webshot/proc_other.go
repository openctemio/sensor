//go:build !linux

package webshot

import "os/exec"

// The browser tool runs only in the Linux task sandbox; elsewhere the
// sandbox refuses it before it starts. These keep the package building.
func setProcessGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
