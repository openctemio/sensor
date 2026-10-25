package main

// `openctemio-sensor seccomp-profile`: prints the container seccomp profile
// this image was built and tested with (docker/seccomp/sensor.json). The
// install commands write it from the image itself:
//
//	docker run --rm ghcr.io/openctemio/sensor:<version> seccomp-profile \
//	  | sudo tee /etc/openctem/sensor-seccomp.json >/dev/null
//
// so the profile always matches the release that runs, and it comes from
// the signed image rather than from a download whose checksum the same
// server also supplies. It reads no settings and talks to nobody.

import (
	_ "embed"
	"fmt"
	"io"
)

//go:embed docker/seccomp/sensor.json
var seccompProfile []byte

func runSeccompProfileCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		_, _ = fmt.Fprintln(stderr, "usage: openctemio-sensor seccomp-profile   (prints the container seccomp profile of this release)")
		return 2
	}
	if _, err := stdout.Write(seccompProfile); err != nil {
		_, _ = fmt.Fprintf(stderr, "seccomp-profile: %v\n", err)
		return 1
	}
	return 0
}
