package svcdetect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// nervaModule is the nerva version whose plugins were audited.
const nervaModule = "github.com/praetorian-inc/nerva"

// auditedSources are the sha256 digests of every non-test Go file of every
// nerva package the tool links (nerva v1.84.0, read for the audit in
// plugins.go). A nerva upgrade that changes any of them, or adds a file or
// a package, fails here until the changed code is audited again and the
// digests are updated with the audit.
var auditedSources = map[string]string{
	"pkg/plugins/finding_catalog.go":              "1101843b38838cb3e9c9f2b8c39f124bb0ae3f6a7b7008875a7c326317c4f93b",
	"pkg/plugins/plugins.go":                      "3bfb9216313aaf4c76a3032eab1e5a7fc9681e8a44eb262c27edb4aa1938e36e",
	"pkg/plugins/tlscheck_ciphers.go":             "5f678bd889713d3e55ae11e3117e3cab385935425e2e891847dea6b3c3582ee5",
	"pkg/plugins/tlscheck.go":                     "17bc2a22eca54457789482d62218705fd2572db88d9e2d6c3a2ce8dcbd210fc0",
	"pkg/plugins/types.go":                        "69ad3ffbaf0d80dc178b900194347134a904bddfd6e7a3fe531774be60cec198",
	"pkg/plugins/pluginutils/error.go":            "8d840db957654460595de2f8bda00374e3b13a8544f2afa792f469197448439b",
	"pkg/plugins/pluginutils/grpc_utils.go":       "a84c36cccd7bf7c395a58bcb63de01921d8f0c65e16a8d68befde577588f7eec",
	"pkg/plugins/pluginutils/requests.go":         "6df0e6de637740a2971d58665fa0101268e488ceff6123dfd0d151832f653ee1",
	"pkg/plugins/services/ftp/ftp.go":             "d61411b61fccd657f2ef3dc87ae59139a42374d360d90caaf0e5152cc36a18fe",
	"pkg/plugins/services/imap/imap.go":           "ec09f297724f48f3ec0ea9fe931f2bb864f71bcdce0239e85297b860d6fc1368",
	"pkg/plugins/services/memcached/memcached.go": "3eed9421ea883ba078c91078e17284ae2cc533795602bad99ffa7be578eec8e7",
	"pkg/plugins/services/mongodb/mongodb.go":     "14d14722ab9eff8125e55b36f330849f2142f6630b015179dacf74925774208b",
	"pkg/plugins/services/mssql/mssql.go":         "acb7b64e3adddb540260067838ec4a0607366793a3d3b4fdda93e20514808cc6",
	"pkg/plugins/services/mysql/mysql.go":         "dcd9edd93b78d6a8df34dbf6c9aedeb4afea878c7d8e3569168c3dcd37bbc1aa",
	"pkg/plugins/services/pop3/pop3.go":           "bab87b8cd0b1d20c65c0c892d0408e8b1f4c664f2f8d6c3d8174878be5d0dd4b",
	"pkg/plugins/services/rdp/rdp.go":             "ebf46c71cd7d23bf0dff54f72dc69815ab670eca50fe010235155b9ac3352790",
	"pkg/plugins/services/redis/redis.go":         "122b0702e87f0de8f11bb7f378115ef8cea914d0fb7f63a67fa73f4875eed88f",
	"pkg/plugins/services/rsync/rsync.go":         "82f92144790475e3b9767c7704e33ea6ba378835367bf134f8bf551fa2ec3669",
	"pkg/plugins/services/smtp/smtp.go":           "42966965924350e5c0dd2ecec6755985736a6ddb6b9fd3342713068b3d67cf2d",
	"pkg/plugins/services/telnet/telnet.go":       "7be073b4c54dd55e374b8e611f637051fa5c380292cab877f029215ab7e5a1aa",
	"pkg/plugins/services/vnc/vnc.go":             "12418f617694b70d7348ae44800573af81d2ea193869c2e1a814a9e0c2597d27",
}

// moduleDir is the module cache directory of the nerva version this module
// requires.
func moduleDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", nervaModule).Output()
	if err != nil {
		t.Fatalf("go list -m %s: %v", nervaModule, err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatalf("%s is not in the module cache", nervaModule)
	}
	return dir
}

func TestNervaSourcesAreTheAuditedOnes(t *testing.T) {
	dir := moduleDir(t)
	// The nerva packages linked into the tool are exactly the audited ones.
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	var linked []string
	for _, p := range strings.Fields(string(out)) {
		if rest, ok := strings.CutPrefix(p, nervaModule+"/"); ok {
			linked = append(linked, rest)
		}
	}
	var audited []string
	for f := range auditedSources {
		if d := filepath.Dir(f); !slices.Contains(audited, d) {
			audited = append(audited, d)
		}
	}
	slices.Sort(linked)
	slices.Sort(audited)
	if !slices.Equal(linked, audited) {
		t.Fatalf("linked nerva packages %v, audited %v: audit the new package before linking it", linked, audited)
	}
	// Every non-test file of those packages has its audited digest.
	seen := map[string]bool{}
	for _, pkg := range audited {
		files, err := filepath.Glob(filepath.Join(dir, pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			rel := filepath.ToSlash(strings.TrimPrefix(f, dir+string(filepath.Separator)))
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			seen[rel] = true
			want, ok := auditedSources[rel]
			if !ok {
				t.Errorf("%s: a new file in an audited package: audit it and add its digest", rel)
				continue
			}
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Errorf("%s changed (sha256 %s, audited %s): audit the change and update the digest", rel, got, want)
			}
		}
	}
	for f := range auditedSources {
		if !seen[f] {
			t.Errorf("%s: audited but no longer in the module", f)
		}
	}
}

// The plugins registered in this binary are the allowed ones plus the
// listed ones an allowed package registers and the tool never runs.
func TestRegisteredPluginsAreTheAllowList(t *testing.T) {
	var registered []string
	for proto, list := range plugins.Plugins {
		for _, p := range list {
			registered = append(registered, pluginKey{proto, p.Name()}.String())
		}
	}
	var want []string
	for _, a := range allowList {
		want = append(want, a.key.String())
	}
	for _, k := range registeredUnused {
		want = append(want, k.String())
	}
	slices.Sort(registered)
	slices.Sort(want)
	if !slices.Equal(registered, want) {
		t.Fatalf("registered plugins %v, want %v", registered, want)
	}
	if len(nervaProbes) != len(allowList) {
		t.Fatalf("%d probes from %d allowed plugins", len(nervaProbes), len(allowList))
	}
	// No probe is a TCPTLS/rdp (CredSSP and NTLM), whatever its name.
	for _, p := range nervaProbes {
		if p.tls && p.name == "rdp" {
			t.Fatal("the RDP CredSSP plugin is run")
		}
	}
}
