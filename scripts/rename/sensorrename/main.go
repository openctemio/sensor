// Command sensorrename performs the type-aware "agent" -> "sensor" rename of
// the sensor binary's own Go code (RFC-023 §9.5). It is driven by
// scripts/rename/sensor-rename.sh and is safe to re-run: on a tree that is
// already renamed it changes nothing.
//
// Identifiers are resolved with go/types (the go/packages loader gopls
// uses), so a word inside a string, or an identifier from a dependency, is
// never confused with one of ours. The rename is a pure function of the
// identifier, so an interface method and its implementations, a struct
// field and every composite-literal key land on the same name. Before
// anything is written every renamed occurrence is checked against the scope
// it sits in; a collision aborts the run with nothing written.
//
// The module is loaded once per build configuration (default and
// -tags platform) and the edits merged: platform mode lives behind
// //go:build platform and shares main.go with the default build.
//
// What it changes: identifiers declared in this module, import aliases,
// comments, and .go files with "agent" in their name (git mv). What it never
// changes: string literals and struct tags (environment variable names,
// flags, YAML keys, the protocol v1 wire — those move by hand, with their
// upgrade path), and the module path github.com/openctemio/agent (the
// repository is renamed by its owner, not by this script). SDK identifiers
// were already renamed by the SDK's codemod (cmd/sensor-migrate).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const modulePath = "github.com/openctemio/agent"

// buildConfigs are the build tag sets the module is type-checked under.
var buildConfigs = []string{"", "platform"}

// keep lists identifiers that contain "agent" but do not mean a sensor.
var keep = map[string]bool{}

// overrides are names whose mechanical rename would read wrongly.
var overrides = map[string]string{}

var userAgentRe = regexp.MustCompile(`(?i)user[-_ ]?agent`)

func newName(name string) string {
	if keep[name] {
		return name
	}
	if v, ok := overrides[name]; ok {
		return v
	}
	var protected []string
	s := userAgentRe.ReplaceAllStringFunc(name, func(m string) string {
		protected = append(protected, m)
		return fmt.Sprintf("\x00%d\x00", len(protected)-1)
	})
	s = strings.ReplaceAll(s, "AGENT", "SENSOR")
	s = strings.ReplaceAll(s, "Agent", "Sensor")
	s = strings.ReplaceAll(s, "agent", "sensor")
	for i, p := range protected {
		s = strings.Replace(s, fmt.Sprintf("\x00%d\x00", i), p, 1)
	}
	return s
}

func needsRename(name string) bool { return newName(name) != name }

type edit struct {
	off, end int
	text     string
}

func main() {
	dir := flag.String("dir", ".", "module root")
	dry := flag.Bool("dry-run", false, "report only, do not write")
	flag.Parse()

	root, err := filepath.Abs(*dir)
	must(err)

	c := &collector{root: root, edits: map[string]map[int]edit{}, seen: map[string]bool{}}
	for _, tags := range buildConfigs {
		cfg := &packages.Config{
			Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
				packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
			Dir:   root,
			Tests: true,
			Env:   append(os.Environ(), "GOWORK=off"),
		}
		if tags != "" {
			cfg.BuildFlags = []string{"-tags=" + tags}
		}
		pkgs, err := packages.Load(cfg, "./...")
		must(err)
		if packages.PrintErrors(pkgs) > 0 {
			fail(fmt.Sprintf("the tree does not type-check (tags %q); fix it before renaming", tags))
		}
		for _, pkg := range pkgs {
			c.collect(pkg)
		}
	}

	if len(c.conflicts) > 0 {
		sort.Strings(c.conflicts)
		for _, x := range c.conflicts {
			fmt.Fprintln(os.Stderr, "conflict:", x)
		}
		fail(fmt.Sprintf("%d conflicts; nothing written", len(c.conflicts)))
	}

	files := make([]string, 0, len(c.edits))
	total := 0
	for f, m := range c.edits {
		files = append(files, f)
		total += len(m)
	}
	sort.Strings(files)
	fmt.Printf("sensorrename: %d edits in %d files\n", total, len(files))
	if *dry {
		for _, f := range files {
			rel, _ := filepath.Rel(root, f)
			fmt.Printf("  %s (%d)\n", rel, len(c.edits[f]))
		}
		return
	}
	for _, f := range files {
		must(applyEdits(f, c.edits[f]))
	}
	must(movePaths(root))
}

type collector struct {
	root      string
	edits     map[string]map[int]edit
	conflicts []string
	seen      map[string]bool
}

func (c *collector) add(fset *token.FileSet, pos token.Pos, oldLen int, text string) {
	p := fset.Position(pos)
	if skipFile(c.root, p.Filename) {
		return
	}
	m := c.edits[p.Filename]
	if m == nil {
		m = map[int]edit{}
		c.edits[p.Filename] = m
	}
	m[p.Offset] = edit{off: p.Offset, end: p.Offset + oldLen, text: text}
}

func (c *collector) collect(pkg *packages.Package) {
	if pkg.TypesInfo == nil {
		return
	}
	for id, obj := range pkg.TypesInfo.Defs {
		c.ident(pkg, id, obj)
	}
	for id, obj := range pkg.TypesInfo.Uses {
		c.ident(pkg, id, obj)
	}
	for _, f := range pkg.Syntax {
		name := pkg.Fset.Position(f.Pos()).Filename
		if c.seen[name] {
			continue
		}
		c.seen[name] = true
		c.file(pkg.Fset, f)
	}
}

func (c *collector) ident(pkg *packages.Package, id *ast.Ident, obj types.Object) {
	if obj == nil || !needsRename(id.Name) || !ours(obj) {
		return
	}
	nn := newName(id.Name)
	c.add(pkg.Fset, id.Pos(), len(id.Name), nn)
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		return // not in lexical scope; a duplicate field fails the build gate
	}
	if fn, ok := obj.(*types.Func); ok && fn.Type().(*types.Signature).Recv() != nil {
		return
	}
	if s := pkg.Types.Scope().Innermost(id.Pos()); s != nil {
		if _, other := s.LookupParent(nn, id.Pos()); other != nil && other != obj {
			c.conflicts = append(c.conflicts, fmt.Sprintf("%s: %s -> %s collides with %s",
				pkg.Fset.Position(id.Pos()), id.Name, nn, other))
		}
	}
}

func (c *collector) file(fset *token.FileSet, f *ast.File) {
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if rest, ok := strings.CutPrefix(path, modulePath); ok && needsRename(rest) {
			c.add(fset, imp.Path.Pos(), len(imp.Path.Value), `"`+modulePath+renamePath(rest)+`"`)
		}
	}
	for _, cg := range f.Comments {
		if keepGroup(cg) {
			continue
		}
		for _, cm := range cg.List {
			if nt := rewriteComment(cm.Text); nt != cm.Text {
				c.add(fset, cm.Pos(), len(cm.Text), nt)
			}
		}
	}
}

const keepDirective = "//sensorrename:keep"

func keepGroup(cg *ast.CommentGroup) bool {
	for _, c := range cg.List {
		if strings.HasPrefix(c.Text, keepDirective) {
			return true
		}
	}
	return false
}

// ours reports whether obj is declared in this module. Objects from the
// standard library or dependencies are never touched.
func ours(obj types.Object) bool {
	if pn, ok := obj.(*types.PkgName); ok {
		return strings.HasPrefix(pn.Imported().Path(), modulePath)
	}
	if obj.Pkg() == nil {
		return false
	}
	p := obj.Pkg().Path()
	return p == modulePath || strings.HasPrefix(p, modulePath+"/") ||
		strings.HasPrefix(p, modulePath+".")
}

func renamePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = newName(s)
	}
	return strings.Join(parts, "/")
}

// Comment rewriting. Protected spans are left byte for byte:
//   - "user agent" in any spelling (the HTTP header);
//   - the repository / module path and released image name
//     (github.com/openctemio/agent, openctemio/agent:<tag>);
//   - protocol v1 vocabulary (/api/v1/agent/..., X-Agent-*, agent_id,
//     agent_preference);
//   - ALL-CAPS environment variable names (AGENT_ID, AGENT_KEY_TTL, ...):
//     comments that name them describe the old setting on purpose;
//   - flag names (-agent-id), the pre-rename config file and block
//     (agent.yaml, agent:) and credentials file (agent-credentials.json);
//   - sentences about the rename itself.
var protectRes = []*regexp.Regexp{
	userAgentRe,
	regexp.MustCompile(`openctemio/agent\b[:A-Za-z0-9_./-]*`),
	regexp.MustCompile(`/api/v1/agent(/[A-Za-z0-9_{}./-]*)?\b`),
	regexp.MustCompile(`(?i)\bx-agent-[a-z-]+`),
	regexp.MustCompile(`\bagent_(id|preference)\b`),
	regexp.MustCompile(`\b[A-Z0-9_]*AGENT[A-Z0-9_]*\b`),
	regexp.MustCompile(`--?agent-[a-z-]+`),
	regexp.MustCompile(`agent(-credentials)?\.(yaml|json)`),
	regexp.MustCompile(`\bagent ?(→|->) ?sensor\b`),
	regexp.MustCompile("[\"'`]agents?[A-Za-z0-9_.:*-]*[\"'`]"),
}

var articleRe = regexp.MustCompile(`\b([Aa])n( [Ss]ensor)`)

var identRe = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\b`)

func rewriteComment(text string) string {
	var protected []string
	for _, re := range protectRes {
		text = re.ReplaceAllStringFunc(text, func(m string) string {
			protected = append(protected, m)
			return fmt.Sprintf("\x00%d\x00", len(protected)-1)
		})
	}
	text = identRe.ReplaceAllStringFunc(text, func(w string) string {
		if !strings.Contains(strings.ToLower(w), "agent") {
			return w
		}
		return newName(w)
	})
	text = articleRe.ReplaceAllString(text, "$1$2")
	for i := len(protected) - 1; i >= 0; i-- {
		text = strings.Replace(text, fmt.Sprintf("\x00%d\x00", i), protected[i], 1)
	}
	return text
}

func applyEdits(file string, m map[int]edit) error {
	src, err := os.ReadFile(file) //nolint:gosec // files of this module
	if err != nil {
		return err
	}
	list := make([]edit, 0, len(m))
	for _, e := range m {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].off > list[j].off })
	for _, e := range list {
		src = append(src[:e.off:e.off], append([]byte(e.text), src[e.end:]...)...)
	}
	if out, ferr := format.Source(src); ferr == nil {
		src = out
	}
	return os.WriteFile(file, src, 0o644) //nolint:gosec // source files are world-readable
}

// movePaths renames tracked .go files with "agent" in their name (git mv).
func movePaths(root string) error {
	out, err := exec.Command("git", "-C", root, "ls-files", "*.go").Output()
	if err != nil {
		return err
	}
	var srcs []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f == "" || strings.HasPrefix(f, "scripts/rename/") || strings.Contains(f, "/testdata/") {
			continue
		}
		if to := renamePath(f); to != f {
			srcs = append(srcs, f)
		}
	}
	sort.Strings(srcs)
	for _, from := range srcs {
		to := renamePath(from)
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(to)), 0o755); err != nil { //nolint:gosec // repo dirs
			return err
		}
		cmd := exec.Command("git", "-C", root, "mv", from, to) //nolint:gosec // paths from git ls-files
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git mv %s %s: %w: %s", from, to, err, stderr.String())
		}
	}
	fmt.Printf("sensorrename: moved %d files\n", len(srcs))
	return nil
}

// skipFile excludes the rename tooling and anything outside the module.
func skipFile(root, file string) bool {
	rel, err := filepath.Rel(root, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return true
	}
	rel = filepath.ToSlash(rel)
	return strings.HasPrefix(rel, "scripts/rename/")
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "sensorrename:", msg)
	os.Exit(1)
}
