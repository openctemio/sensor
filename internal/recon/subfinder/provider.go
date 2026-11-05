package subfinder

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/contract/secretref"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// The source keys of a task. The tool contract delivers the keys the
// manifest declares (permissions.credentials, one per passive source) in the
// task's run message; the tool child writes them into a provider
// configuration in the task's own directory (mode 0600, removed with the
// directory) and points subfinder at it. Every task reads that file and no
// other, so subfinder never falls back to a provider configuration of the
// host user (its default location), and one task's keys are never another's.

// providerConfigName is the file written in the task directory.
const providerConfigName = "provider-config.yaml"

// WithCredentials returns the scanner configured for one task: the keys by
// source written to dir, the scan reading them, and per-source statistics
// handed to log after the run (nil: none).
func (s *Scanner) WithCredentials(dir string, keys map[string]string, log func(msg string, args ...any)) (core.ReconScanner, error) {
	if dir == "" {
		return nil, errors.New("subfinder: no task directory for the provider configuration")
	}
	path, err := writeProviderConfig(dir, keys, log)
	if err != nil {
		return nil, err
	}
	c := *s
	c.providerConfig = path
	c.statsLog = log
	return &c, nil
}

// writeProviderConfig writes keys as subfinder's provider configuration (a
// map of source to its list of keys) to a new file in dir, readable by the
// task's user only. YAML encoding quotes every value: a key cannot add a
// source or a line.
func writeProviderConfig(dir string, keys map[string]string, log func(msg string, args ...any)) (string, error) {
	cfg := make(map[string][]string, len(keys))
	for name, v := range keys {
		if v == "" {
			continue
		}
		if !keyAllowed(name, v) {
			// Not a registry provider, or a key the provider's rules
			// refuse (a host outside the source's own service, for one):
			// subfinder would connect there from this sensor.
			if log != nil {
				log("subfinder source key refused: it does not meet the source's rules", "source", name)
			}
			continue
		}
		cfg[name] = []string{v}
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("subfinder: encode the provider configuration: %w", err)
	}
	path, err := tool.WriteSecretFile(dir, providerConfigName, raw)
	if err != nil {
		return "", fmt.Errorf("subfinder: provider configuration: %w", err)
	}
	return path, nil
}

// SourceStat is what subfinder reports of one source after a run (-stats).
type SourceStat struct {
	Source   string
	Results  int
	Requests int
	Errors   int
}

// parseStats reads subfinder's statistics table from its log output:
// " <source> <duration> <results> <requests> <errors>" under the
// "Source Duration Results Requests Errors" header. Lines that do not fit
// are skipped.
func parseStats(out []byte) []SourceStat {
	var stats []SourceStat
	in := false
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		f := strings.Fields(line)
		switch {
		case len(f) == 5 && f[0] == "Source" && f[2] == "Results":
			in = true
			continue
		case !in:
			continue
		case len(f) != 5:
			if line != "" && !strings.HasPrefix(line, "─") {
				in = false
			}
			continue
		}
		res, e1 := strconv.Atoi(f[2])
		req, e2 := strconv.Atoi(f[3])
		errs, e3 := strconv.Atoi(f[4])
		if e1 != nil || e2 != nil || e3 != nil || !sourceName(f[0]) {
			continue
		}
		stats = append(stats, SourceStat{Source: f[0], Results: res, Requests: req, Errors: errs})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Source < stats[j].Source })
	return stats
}

func sourceName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// logStats hands each source's statistics to the task log: what each source
// gave, and which sources failed (a refused or exhausted key shows as
// errors without results).
func (s *Scanner) logStats(stderr []byte) {
	if s.statsLog == nil {
		return
	}
	for _, st := range parseStats(stderr) {
		args := []any{"source", st.Source, "results", st.Results, "requests", st.Requests, "errors", st.Errors}
		switch {
		case st.Errors > 0 && st.Results == 0:
			s.statsLog("subfinder source failed: check its key or quota", args...)
		default:
			s.statsLog("subfinder source", args...)
		}
	}
}

// keyAllowed reports whether the key v of source name may be written: name
// is a provider of the secrets contract's registry and v passes its rules
// (format, minimum length, and for a key that names where subfinder
// connects, a host on the source's own service only: never an IP address,
// a port, user information or another host). The platform checks the same
// rules when a key is saved; they are checked again here because keys an
// operator stored on the sensor flow through too.
func keyAllowed(name, v string) bool {
	p, ok := secretref.LookupProvider(name)
	return ok && p.ValidateKey(v) == nil
}
