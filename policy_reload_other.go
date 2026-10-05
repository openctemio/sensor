//go:build !unix

package main

import "errors"

// sendReload: no SIGHUP on this platform; restart the sensor instead.
func sendReload(int) error {
	return errors.New("this platform has no SIGHUP; restart the sensor")
}
