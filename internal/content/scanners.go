package content

import (
	"context"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/scanners/semgrep"
	"github.com/openctemio/sensor/internal/scanners/trivy"
)

// WrapScanner makes a scanner run on the managed content: every scan takes
// the current version when it starts and runs a copy of the scanner set up
// for it, so the shared scanner is never modified and concurrent scans do
// not interfere. Without a managed version the scanner runs unchanged.
// Scanners without managed content are returned as they are.
func (m *Manager) WrapScanner(s core.Scanner) core.Scanner {
	if m == nil {
		return s
	}
	switch sc := s.(type) {
	case *trivy.Scanner:
		return &trivyScanner{Scanner: sc, m: m}
	case *nuclei.Scanner:
		return &nucleiScanner{Scanner: sc, m: m}
	case *semgrep.Scanner:
		return &semgrepScanner{Scanner: sc, m: m}
	default:
		return s
	}
}

// AcquireFor takes the current version of content name for a scan of tool
// and records it as the content that scan uses (for its results). nil: no
// managed version (nil manager included).
func (m *Manager) AcquireFor(tool, name string) *Handle {
	return m.acquire(tool, name)
}

// acquire takes the current version of name and records it as the content
// tool's scan uses.
func (m *Manager) acquire(tool, name string) *Handle {
	if m == nil {
		return nil
	}
	h := m.Acquire(name)
	if h == nil {
		return nil
	}
	info := []core.ContentInfo{h.Info()}
	for i := range h.Meta.Also {
		info = append(info, infoOf(&h.Meta.Also[i]))
	}
	m.NoteUsed(tool, info)
	return h
}

type trivyScanner struct {
	*trivy.Scanner
	m *Manager
}

func (w *trivyScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	h := w.m.acquire("trivy", core.ContentTrivyDB)
	if h == nil {
		return w.Scanner.Scan(ctx, target, opts)
	}
	defer h.Release()
	cp := *w.Scanner
	cp.CacheDir = h.Dir
	cp.SkipDBUpdate = true
	return cp.Scan(ctx, target, opts)
}

type nucleiScanner struct {
	*nuclei.Scanner
	m *Manager
}

func (w *nucleiScanner) configured(h *Handle) *nuclei.Scanner {
	cp := *w.Scanner
	cp.TemplateDir = h.Dir
	cp.TemplatesVersion = h.Meta.Version
	cp.DisableUpdateCheck = true
	cp.DisableUnsignedTemplates = true
	cp.AutoUpdateTemplates = false
	return &cp
}

func (w *nucleiScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	h := w.m.acquire("nuclei", core.ContentNucleiTemplates)
	if h == nil {
		return w.Scanner.Scan(ctx, target, opts)
	}
	defer h.Release()
	return w.configured(h).Scan(ctx, target, opts)
}

// ScanTargets implements core.MultiTargetScanner.
func (w *nucleiScanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	h := w.m.acquire("nuclei", core.ContentNucleiTemplates)
	if h == nil {
		return w.Scanner.ScanTargets(ctx, targets, opts)
	}
	defer h.Release()
	return w.configured(h).ScanTargets(ctx, targets, opts)
}

type semgrepScanner struct {
	*semgrep.Scanner
	m *Manager
}

func (w *semgrepScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	h := w.m.acquire("semgrep", core.ContentSemgrepRules)
	if h == nil {
		return w.Scanner.Scan(ctx, target, opts)
	}
	defer h.Release()
	cp := *w.Scanner
	cp.Configs = []string{h.Dir}
	return cp.Scan(ctx, target, opts)
}

// NucleiTemplates returns the managed templates directory for a nuclei
// re-verification, the release it holds and the func that releases it, or
// "", a zero release and a no-op.
func (m *Manager) NucleiTemplates() (string, core.ContentInfo, func()) {
	if m == nil {
		return "", core.ContentInfo{}, func() {}
	}
	h := m.acquire("nuclei", core.ContentNucleiTemplates)
	if h == nil {
		return "", core.ContentInfo{}, func() {}
	}
	return h.Dir, h.Info(), h.Release
}
