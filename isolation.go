package main

import "github.com/openctemio/sdk-go/pkg/sensorkit/executor"

// strongIsolationBackends are the strong isolation backends this sensor can
// offer for probing (a gVisor or microVM task per tool run). None ships yet,
// so the sensor never advertises isolation.strong@1; the capability appears
// only when a backend listed here passes its probe.
func strongIsolationBackends() []executor.Candidate { return nil }
