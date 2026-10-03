package nuclei

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Interactsh (out-of-band callbacks to oast.* servers) is off unless
// something opts in; NoInteractsh always wins.
func TestBuildArgsInteractshOffByDefault(t *testing.T) {
	has := func(args []string, flag string) bool { return slices.Contains(args, flag) }

	cases := []struct {
		name       string
		scanner    func() *Scanner
		opts       *core.ScanOptions
		wantOn     bool
		wantServer bool
		wantToken  bool
	}{
		{name: "default scanner, nil opts", scanner: NewScanner, opts: nil},
		{name: "default scanner, empty opts", scanner: NewScanner, opts: &core.ScanOptions{}},
		{name: "DAST preset stays off", scanner: NewDAST, opts: &core.ScanOptions{}},
		{
			name: "token alone does not opt in", opts: &core.ScanOptions{},
			scanner: func() *Scanner { s := NewScanner(); s.InteractshToken = "secret"; return s },
		},
		{
			name: "scanner opts in", opts: nil, wantOn: true,
			scanner: func() *Scanner { s := NewScanner(); s.AllowInteractsh = true; return s },
		},
		{
			name: "own server opts in and is passed with its token", opts: nil, wantOn: true, wantServer: true, wantToken: true,
			scanner: func() *Scanner {
				s := NewScanner()
				s.InteractshServer = "https://oast.internal.example"
				s.InteractshToken = "secret"
				return s
			},
		},
		{name: "scan opts in", scanner: NewScanner, opts: &core.ScanOptions{AllowInteractsh: true}, wantOn: true},
		{
			name: "NoInteractsh beats every opt-in", opts: &core.ScanOptions{AllowInteractsh: true},
			scanner: func() *Scanner {
				s := NewScanner()
				s.NoInteractsh = true
				s.AllowInteractsh = true
				s.InteractshServer = "https://oast.internal.example"
				s.InteractshToken = "secret"
				return s
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.scanner()
			args := s.buildArgs("https://example.com", tc.opts)
			if got := s.InteractshEnabled(tc.opts); got != tc.wantOn {
				t.Errorf("InteractshEnabled = %v, want %v", got, tc.wantOn)
			}
			if has(args, "-ni") == tc.wantOn {
				t.Errorf("-ni present=%v with interactsh on=%v: %v", has(args, "-ni"), tc.wantOn, args)
			}
			if has(args, "-iserver") != tc.wantServer {
				t.Errorf("-iserver present=%v, want %v: %v", has(args, "-iserver"), tc.wantServer, args)
			}
			if has(args, "-itoken") != tc.wantToken {
				t.Errorf("-itoken present=%v, want %v: %v", has(args, "-itoken"), tc.wantToken, args)
			}
		})
	}

	// The multi-target (list) path builds the same way.
	if args := NewScanner().buildArgsFor("", "/tmp/targets.txt", nil); !has(args, "-ni") {
		t.Errorf("list scan without -ni: %v", args)
	}
}
