package main

import (
	"fmt"
	"io"
)

// mainUsage is the head of -help: the subcommands, then the flags
// (flag.PrintDefaults) of the scanner and daemon modes.
func mainUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage:
  %[1]s [flags]                 run a scan once, or the daemon (-daemon)
  %[1]s pair [flags] [CODE]     pair this sensor with the platform
  %[1]s policy <command> ...    validate, explain or install the sensor-local policy
  %[1]s tools manifests [--json]
                                      print the tool-contract manifests this sensor enforces

Run "%[1]s <subcommand> -help" for a subcommand's flags.

Flags:
`, binName)
}
