//go:build unix

package main

import "syscall"

// sendReload asks the sensor process pid to reload its local policy.
func sendReload(pid int) error {
	return syscall.Kill(pid, syscall.SIGHUP)
}
