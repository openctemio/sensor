package main

// `openctemio-sensor policy …`: the network owner's tools for the
// sensor-local policy (api docs/rfcs/RFC-040-platform-sensor-mutual-
// distrust.md §5.7; openctemio/openctem research/25 §3.8). They read local
// files only and never talk to the platform:
//
//	policy validate [file]                 parse with the sensor's own loader
//	policy digest   [file]                 the sha256 the sensor reports
//	policy explain  [file] -target T [-tool X] [-check scan]
//	                                       would this job be admitted, and if
//	                                       not, by which rule
//	policy install  <file> -expect-sha256 H [-dest P] [-dry-run] [-pid N]
//	                                       install the reviewed bytes
//
// install is how a policy file downloaded from the platform reaches the
// host: the operator compares the hash the platform showed with the hash
// of the bytes they reviewed. The platform never writes the file; the hash
// is not a platform trust anchor, it proves the installed bytes are the
// reviewed ones.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// runPolicyCommand runs `policy <sub> …` and returns the exit code: 0 ok,
// 1 refused (invalid policy, hash mismatch, job not admitted), 2 usage.
func runPolicyCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		policyUsage(stderr)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "validate":
		return policyValidate(rest, stdout, stderr)
	case "digest":
		return policyDigest(rest, stdout, stderr)
	case "explain":
		return policyExplain(rest, stdout, stderr)
	case "install":
		return policyInstall(rest, stdout, stderr)
	case "-h", "-help", "--help", "help":
		policyUsage(stdout)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "Error: unknown policy command %q\n", sub)
	policyUsage(stderr)
	return 2
}

func policyUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: openctemio-sensor policy <command> [flags] [file]

The sensor-local policy (default file: $%s, else %s). Local only: nothing
is sent to the platform.

  validate [file]                     parse it as the sensor does; exit 1 if invalid
  digest [file]                       print its sha256 (what the sensor reports)
  explain [file] -target T [-tool X] [-check scan]
                                      say whether a job would be admitted, and which rule refuses it
  install <file> -expect-sha256 HEX [-dest PATH] [-dry-run] [-pid N]
                                      check the hash and the policy, then install it atomically
                                      (0644) and reload the sensor (SIGHUP to -pid)

Schemas read by this sensor: %s
`, core.EnvLocalPolicy, core.DefaultLocalPolicyPath, strings.Join(core.LocalPolicySchemas, ", "))
}

// policyPath is the file argument, else SENSOR_LOCAL_POLICY, else the
// default path.
func policyPath(flags *flag.FlagSet) string {
	if p := flags.Arg(0); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv(core.EnvLocalPolicy)); p != "" {
		return p
	}
	return core.DefaultLocalPolicyPath
}

// parseInterleaved parses flags that may come before or after the one
// positional argument (Go's flag package stops at the first non-flag).
func parseInterleaved(fs *flag.FlagSet, args []string) error {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) > 1 {
		return fmt.Errorf("one file at most, got %q", pos)
	}
	return fs.Parse(pos)
}

func newPolicyFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("policy "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// loadPolicyFile loads path with the sensor's loader (the same checks as at
// start: strict keys, mode, size, one document).
func loadPolicyFile(path string) (*core.LocalPolicy, error) {
	return core.LoadLocalPolicy(core.LocalPolicyOptions{Path: path})
}

func policyValidate(args []string, stdout, stderr io.Writer) int {
	flags := newPolicyFlags("validate", stderr)
	if err := parseInterleaved(flags, args); err != nil {
		return 2
	}
	path := policyPath(flags)
	lp, err := loadPolicyFile(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "valid (schema %s): %s\n", lp.Schema(), lp.Describe())
	for _, w := range lp.Warnings() {
		_, _ = fmt.Fprintf(stdout, "warning: %s\n", w)
	}
	return 0
}

func policyDigest(args []string, stdout, stderr io.Writer) int {
	flags := newPolicyFlags("digest", stderr)
	if err := parseInterleaved(flags, args); err != nil {
		return 2
	}
	lp, err := loadPolicyFile(policyPath(flags))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, lp.Digest())
	return 0
}

func policyExplain(args []string, stdout, stderr io.Writer) int {
	flags := newPolicyFlags("explain", stderr)
	target := flags.String("target", "", "the job's target (host, IP, URL, host:port)")
	tool := flags.String("tool", "nuclei", "the job's tool")
	check := flags.String("check", "scan", "the job's type (scan, validate, collect, refresh_content)")
	if err := parseInterleaved(flags, args); err != nil {
		return 2
	}
	if strings.TrimSpace(*target) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: -target is required")
		return 2
	}
	lp, err := loadPolicyFile(policyPath(flags))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid: %v\n", err)
		return 1
	}
	payload, _ := json.Marshal(map[string]any{"scanner": *tool, "target": *target})
	cmd := &core.Command{ID: "explain", Type: *check, Payload: payload}
	if adm, err := lp.AdmitCommandTargets(context.Background(), cmd); err != nil {
		var lpe *core.LocalPolicyError
		if errors.As(err, &lpe) {
			reason := ""
			if adm != nil && len(adm.Refused) > 0 {
				// The per-target reason the platform shows for a skipped target.
				reason = " (" + adm.Refused[0].Reason + ")"
			}
			_, _ = fmt.Fprintf(stdout, "refused by the local policy: rule %s%s: %s\n", lpe.Rule, reason, lpe.Detail)
		} else {
			_, _ = fmt.Fprintf(stdout, "refused: %v\n", err)
		}
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "admitted by the local policy (%s %s on %s)\n", *check, *tool, *target)
	return 0
}

// maxInstallBytes bounds the file install reads (the loader's own limit).
const maxInstallBytes = core.MaxLocalPolicyBytes

func policyInstall(args []string, stdout, stderr io.Writer) int {
	flags := newPolicyFlags("install", stderr)
	expect := flags.String("expect-sha256", "", "the sha256 the platform showed for this file (hex, or sha256:hex); required")
	dest := flags.String("dest", "", "where to install it (default $"+core.EnvLocalPolicy+", else "+core.DefaultLocalPolicyPath+")")
	dryRun := flags.Bool("dry-run", false, "check everything and show the change, install nothing")
	pid := flags.Int("pid", 0, "the running sensor's process id: send it SIGHUP to reload the policy")
	if err := parseInterleaved(flags, args); err != nil {
		return 2
	}
	src := flags.Arg(0)
	if src == "" {
		_, _ = fmt.Fprintln(stderr, "Error: the policy file to install is required")
		return 2
	}
	want, err := parseExpectedSHA256(*expect)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: -expect-sha256: %v\n", err)
		return 2
	}
	to := *dest
	if to == "" {
		to = strings.TrimSpace(os.Getenv(core.EnvLocalPolicy))
	}
	if to == "" {
		to = core.DefaultLocalPolicyPath
	}
	if !filepath.IsAbs(to) {
		_, _ = fmt.Fprintf(stderr, "Error: -dest %q must be an absolute path\n", to)
		return 2
	}

	data, err := readBoundedRegular(src, maxInstallBytes)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "refused: %v\n", err)
		return 1
	}
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		_, _ = fmt.Fprintf(stderr, "refused: sha256 mismatch: the file is sha256:%s, expected sha256:%s; do not install bytes you did not review\n", hex.EncodeToString(got[:]), hex.EncodeToString(want))
		return 1
	}
	next, err := core.ParseLocalPolicy(data, core.LocalPolicyOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "refused: the policy is not valid for this sensor (schemas %s): %v\n", strings.Join(core.LocalPolicySchemas, ", "), err)
		return 1
	}

	// The current policy, for the change summary (none, or one that no
	// longer loads, is fine: this replaces it).
	before := "none"
	if st, err := os.Lstat(to); err == nil {
		if !st.Mode().IsRegular() {
			_, _ = fmt.Fprintf(stderr, "refused: %s exists and is not a regular file (a symlink or device is never replaced)\n", to)
			return 1
		}
		if cur, err := loadPolicyFile(to); err == nil {
			before = cur.Describe()
		} else {
			before = "invalid (" + err.Error() + ")"
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		_, _ = fmt.Fprintf(stderr, "refused: %s: %v\n", to, err)
		return 1
	}
	if err := checkInstallDir(filepath.Dir(to)); err != nil {
		_, _ = fmt.Fprintf(stderr, "refused: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "sha256:%s matches\nschema %s\nbefore: %s\nafter:  %s\n", hex.EncodeToString(got[:]), next.Schema(), before, next.Describe())
	if *dryRun {
		_, _ = fmt.Fprintf(stdout, "dry run: %s not changed\n", to)
		return 0
	}
	if err := writeAtomic(to, data, 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: install %s: %v\n", to, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "installed %s\n", to)
	if *pid > 0 {
		if err := sendReload(*pid); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: SIGHUP to %d: %v; restart the sensor or send it SIGHUP to apply the policy\n", *pid, err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "sent SIGHUP to %d: the sensor reloads the policy (a file it cannot load stops every job)\n", *pid)
		return 0
	}
	_, _ = fmt.Fprintln(stdout, "apply it: send the sensor SIGHUP (kill -HUP <pid>, docker kill -s HUP <container>) or restart it")
	return 0
}

// parseExpectedSHA256 accepts 64 hex digits, optionally "sha256:"-prefixed.
func parseExpectedSHA256(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "sha256:")
	if s == "" {
		return nil, errors.New("required: the hash shown with the file")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("%q is not a sha256 (64 hex digits)", s)
	}
	return b, nil
}

// readBoundedRegular reads a regular file of at most limit bytes.
func readBoundedRegular(path string, limit int) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the operator names the file to install
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// checkInstallDir refuses a destination directory others can write: anyone
// who can write it can replace the policy after it is installed.
func checkInstallDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("directory %s: %w (create it, owned by root, 0755)", dir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st.Mode().Perm()&0o002 != 0 && st.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("directory %s is writable by every user (mode %v); anyone could replace the policy", dir, st.Mode().Perm())
	}
	return nil
}

// writeAtomic writes data to path through a temporary file in the same
// directory (fsync, chmod, rename): a reader sees the old file or the new
// one, never a half-written policy.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { //nolint:gosec // the destination's own directory
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
