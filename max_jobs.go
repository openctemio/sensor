package main

import (
	"fmt"
	"strconv"
	"strings"
)

// How many commands the daemon (and a platform sensor) runs at once. The
// command poller takes a slot before it claims a command and asks the
// platform for no more than its free slots, and the heartbeat reports the
// number as max_concurrent_jobs, so the platform never hands this sensor
// more than it runs (api RFC-030 Phase 0, B6/B11).
const (
	defaultMaxJobs = 5
	// maxMaxJobs matches the platform's limit on a sensor's concurrency.
	maxMaxJobs = 100
	// envMaxJobs sets it without a flag (containers).
	envMaxJobs = "SENSOR_MAX_JOBS"
)

// resolveMaxJobs picks the concurrency: the -max-concurrent flag when given,
// else SENSOR_MAX_JOBS, else sensor.max_jobs from the config file, else 5.
// A value outside 1..100 is an error: the sensor refuses to start rather
// than run a different number than the operator asked for.
func resolveMaxJobs(flagSet bool, flagVal int, env string, cfgVal int) (int, error) {
	switch {
	case flagSet:
		return checkMaxJobs("-max-concurrent", flagVal)
	case strings.TrimSpace(env) != "":
		n, err := strconv.Atoi(strings.TrimSpace(env))
		if err != nil {
			return 0, fmt.Errorf("%s=%q is not a number", envMaxJobs, env)
		}
		return checkMaxJobs(envMaxJobs, n)
	case cfgVal != 0:
		return checkMaxJobs("sensor.max_jobs", cfgVal)
	default:
		return defaultMaxJobs, nil
	}
}

func checkMaxJobs(source string, n int) (int, error) {
	if n < 1 || n > maxMaxJobs {
		return 0, fmt.Errorf("%s=%d: the sensor runs between 1 and %d jobs at once", source, n, maxMaxJobs)
	}
	return n, nil
}
