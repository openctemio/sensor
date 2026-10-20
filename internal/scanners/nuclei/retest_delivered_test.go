package nuclei

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// A retest item with a delivered check (tool.RetestItem.TemplatePath) runs
// exactly that file: matched is still present, ran on the reachable target
// without a match is fixed, a file nuclei does not load or excludes is
// unverifiable and never fixed; each conclusive verdict carries the
// file's digest. Items without one run the managed template as before.
func TestRetestDeliveredTemplates(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	bin := fakeNucleiBin(t)
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = up.Close() }()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dir := t.TempDir()
	write := func(name, id string) (string, string) {
		body := "id: " + id + "\ninfo:\n  name: n\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/x']\n"
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		return p, "sha256:" + hex.EncodeToString(sum[:])
	}
	detect, detectDigest := write("detect.yaml", "clean-detect")
	nomatch, nomatchDigest := write("nomatch.yaml", "clean-nomatch")
	broken, _ := write("broken.yaml", "broken")
	intrusive, _ := write("intrusive.yaml", "activemq-upload")

	task := tool.Task{
		ID:      "retest-delivered",
		Targets: []tool.Target{{Ref: "t1", Value: "http://" + up.Addr().String()}},
		Retest: []tool.RetestItem{
			{Ref: "d", Target: "t1", Kind: tool.RetestFinding, RuleID: "custom", TemplatePath: detect},
			{Ref: "n", Target: "t1", Kind: tool.RetestFinding, RuleID: "custom", TemplatePath: nomatch},
			{Ref: "b", Target: "t1", Kind: tool.RetestFinding, RuleID: "clean-nomatch", TemplatePath: broken},
			{Ref: "i", Target: "t1", Kind: tool.RetestFinding, RuleID: "custom", TemplatePath: intrusive},
			{Ref: "m", Target: "t1", Kind: tool.RetestFinding, RuleID: "clean-nomatch"},
		},
	}
	out, err := Retest(context.Background(), ValidateOptions{Binary: bin}, task)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]tool.RetestVerdict{}
	for _, v := range out.Verdicts {
		got[v.Ref] = v
	}
	want := map[string]tool.Verdict{"d": tool.StillPresent, "n": tool.Fixed, "b": tool.Unverifiable, "i": tool.Unverifiable, "m": tool.Fixed}
	for ref, v := range want {
		if got[ref].Verdict != v {
			t.Errorf("%s: %s (%s), want %s (stderr %s)", ref, got[ref].Verdict, got[ref].Detail, v, out.Stderr)
		}
	}
	if got["d"].TemplateDigest != detectDigest || got["n"].TemplateDigest != nomatchDigest {
		t.Errorf("digests d=%q n=%q; want the delivered files' %q %q", got["d"].TemplateDigest, got["n"].TemplateDigest, detectDigest, nomatchDigest)
	}
	if !strings.Contains(got["b"].Detail, "the check could not be loaded") {
		t.Errorf("an unloadable delivered check: detail %q", got["b"].Detail)
	}
	if !strings.Contains(got["n"].Detail, "the delivered check ran") {
		t.Errorf("fixed detail %q", got["n"].Detail)
	}
}

// Only a delivered template file runs without nuclei's own signature
// requirement; a managed id or a configured path keeps it.
func TestBuildValidateArgs_UnsignedOnlyForDelivered(t *testing.T) {
	cases := []struct {
		name string
		opts ValidateOptions
		want bool // -disable-unsigned-templates present
	}{
		{"managed id", ValidateOptions{Target: "http://t", TemplateID: "x"}, true},
		{"configured path", ValidateOptions{Target: "http://t", TemplatePath: "/tpl/x.yaml"}, true},
		{"delivered without a path", ValidateOptions{Target: "http://t", TemplateID: "x", Delivered: true}, true},
		{"delivered file", ValidateOptions{Target: "http://t", TemplatePath: "/tmp/d/x.yaml", Delivered: true}, false},
	}
	for _, tc := range cases {
		args, err := buildValidateArgs(tc.opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := slices.Contains(args, "-disable-unsigned-templates"); got != tc.want {
			t.Errorf("%s: -disable-unsigned-templates %t, want %t (%v)", tc.name, got, tc.want, args)
		}
		if !slices.Contains(args, "-etags") {
			t.Errorf("%s: the tag exclusions are missing: %v", tc.name, args)
		}
	}
}
