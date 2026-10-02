package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/resource"
)

// The most commands the daemon runs at once: an operator CAP, not a fixed
// count. Without one the SDK sizes the slots from the CPU and memory the
// sensor may use and its tools' learned cost (sdk-go resource.Manager), up
// to the SDK's hard maximum. The command poller takes a slot before it
// claims a command and asks the platform for no more than its free slots;
// the heartbeat reports the cap as max_concurrent_jobs and the live slots
// as capacity.slots_total (api RFC-030).
const (
	// defaultMaxJobs is platform mode's concurrency when none is set (its
	// lease poller has no resource-aware slots).
	defaultMaxJobs = 5
	// maxMaxJobs matches the platform's limit on a sensor's concurrency.
	maxMaxJobs = 100
	// envMaxJobs sets it without a flag (containers).
	envMaxJobs = "SENSOR_MAX_JOBS"
)

// resolveMaxJobs picks the cap: the -max-concurrent flag when given, else
// SENSOR_MAX_JOBS, else sensor.max_jobs from the config file, else 0 (no
// cap: the slots follow the resources). A value outside 1..100 is an
// error: the sensor refuses to start rather than run a different number
// than the operator asked for.
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
		return 0, nil
	}
}

func checkMaxJobs(source string, n int) (int, error) {
	if n < 1 || n > maxMaxJobs {
		return 0, fmt.Errorf("%s=%d: the sensor runs between 1 and %d jobs at once", source, n, maxMaxJobs)
	}
	return n, nil
}

// envStateDir overrides where the sensor keeps local state.
const envStateDir = "SENSOR_STATE_DIR"

// resolveStateDir is SENSOR_STATE_DIR, else the outbox's parent directory
// (/var/lib/openctem in the images), else ~/.openctem.
func resolveStateDir(ob outboxPlan) string {
	if d := strings.TrimSpace(os.Getenv(envStateDir)); d != "" {
		return d
	}
	if ob.Config.Dir != "" {
		return filepath.Dir(ob.Config.Dir)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".openctem")
	}
	return ""
}

// newResourceManager sizes the daemon's slots for its tools.
func newResourceManager(cfg *Config, stateDir string, roots []string) *resource.Manager {
	tools := make([]string, 0, len(cfg.Scanners))
	for _, s := range cfg.Scanners {
		if s.Enabled {
			tools = append(tools, canonicalToolName(s.Name))
		}
	}
	workDir := stateDir
	if len(roots) > 0 {
		workDir = roots[0]
	}
	var stateFile string
	if stateDir != "" {
		stateFile = filepath.Join(stateDir, "tool-costs.json")
	}
	return resource.NewManager(resource.ManagerConfig{
		Cap:       cfg.Sensor.MaxJobs,
		Tools:     tools,
		StateFile: stateFile,
		Prober:    &resource.Prober{WorkDir: workDir},
		OnError:   func(err error) { fmt.Fprintf(os.Stderr, "Warning: %v\n", err) },
	})
}

// canonicalToolName maps a configured scanner name to the tool it runs
// ("trivy-fs" → "trivy").
func canonicalToolName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if base, _, ok := strings.Cut(n, "-"); ok && base != "" {
		return base
	}
	return n
}

// envDrainGrace is how long a stopping daemon lets running scans finish
// before it stops them and hands them back to the platform.
const envDrainGrace = "SENSOR_DRAIN_GRACE"

// resolveDrainGrace parses SENSOR_DRAIN_GRACE ("45s", "2m"); unset is the
// SDK default (30s). An invalid or out-of-range (1s-1h) value is an error.
func resolveDrainGrace(env string) (time.Duration, error) {
	env = strings.TrimSpace(env)
	if env == "" {
		return core.DefaultDrainGrace, nil
	}
	d, err := time.ParseDuration(env)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a duration (e.g. 45s, 2m)", envDrainGrace, env)
	}
	if d < time.Second || d > time.Hour {
		return 0, fmt.Errorf("%s=%s: between 1s and 1h", envDrainGrace, d)
	}
	return d, nil
}
