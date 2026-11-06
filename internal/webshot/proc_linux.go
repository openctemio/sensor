//go:build linux

package webshot

import (
	"os/exec"
	"syscall"
)

// setProcessGroup starts the browser in its own process group, killed when
// the tool dies, so the whole tree (zygote, renderers, utility processes)
// ends with it.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// killGroup kills the browser's process group.
func killGroup(cmd *exec.Cmd) { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
