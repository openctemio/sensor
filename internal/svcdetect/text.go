package svcdetect

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Bounds of what a service record carries. A banner is what a hostile or
// broken server chose to send: it is cut, made valid UTF-8 and stripped of
// every control character before it leaves the tool, so it cannot inject a
// log line, a terminal escape or an oversized value anywhere downstream.
const (
	MaxBanner      = 512
	MaxDetails     = 16
	MaxDetailValue = 256
	maxKey         = 64
	maxProduct     = 128
	maxVersion     = 128
	maxCPE         = 256
	// maxPreRead bounds what is read of a server's first bytes.
	maxPreRead = 2048
)

// cleanText returns v as valid UTF-8 of at most max bytes with every
// control character (C0 incl. NUL, CR, LF, TAB and ESC; DEL; C1) and every
// bidirectional override replaced by a space, runs of spaces collapsed and
// the ends trimmed. Invalid bytes are dropped.
func cleanText(v string, maxBytes int) string {
	var b strings.Builder
	space := true // drop leading spaces
	for _, r := range strings.ToValidUTF8(v, "") {
		if isControl(r) || r == ' ' {
			if space {
				continue
			}
			r, space = ' ', true
		} else {
			space = false
		}
		if b.Len()+utf8.RuneLen(r) > maxBytes {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimRight(b.String(), " ")
}

// isControl reports a control or bidirectional formatting character.
func isControl(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x200e && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// cleanKey is a details key: lower case letters, digits and underscores,
// at most maxKey bytes ("" when nothing is left).
func cleanKey(k string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == ' ':
			b.WriteByte('_')
		}
		if b.Len() >= maxKey {
			break
		}
	}
	return strings.Trim(b.String(), "_")
}

// secretWords are key fragments whose values never leave the tool, whatever
// a probe put under them.
var secretWords = []string{"password", "passwd", "secret", "token", "cookie", "credential", "session", "auth_data", "private"}

// detailsFrom turns a probe's metadata into bounded details: scalar values
// and lists of scalars, cleaned, at most MaxDetails keys in name order.
// skip names keys that are reported elsewhere (banner, cpes).
func detailsFrom(meta map[string]any, skip ...string) map[string]string {
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := map[string]string{}
	for _, raw := range keys {
		k := cleanKey(raw)
		if k == "" || slices.Contains(skip, k) || slices.ContainsFunc(secretWords, func(w string) bool { return strings.Contains(k, w) }) {
			continue
		}
		v := scalarText(meta[raw])
		if v == "" {
			continue
		}
		if _, dup := out[k]; dup {
			continue
		}
		out[k] = v
		if len(out) == MaxDetails {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// scalarText is a metadata value as clean text ("" for objects, empty
// values and false).
func scalarText(v any) string {
	switch x := v.(type) {
	case string:
		return cleanText(x, MaxDetailValue)
	case bool:
		if x {
			return "true"
		}
		return ""
	case float64:
		return cleanText(fmt.Sprintf("%g", x), MaxDetailValue)
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if s := scalarText(e); s != "" {
				parts = append(parts, s)
			}
			if len(parts) == 32 {
				break
			}
		}
		return cleanText(strings.Join(parts, ", "), MaxDetailValue)
	}
	return ""
}

// usableCPE returns a CPE 2.3 name worth matching on: well formed, of a
// product with a concrete version. A name with a wildcard or empty version
// would match every version of the product, so it is dropped; product is
// the CPE's product either way.
func usableCPE(v string) (cpe, product string) {
	v = strings.TrimSpace(v)
	if len(v) > maxCPE {
		return "", ""
	}
	c, err := ctis.CanonicalCPE(v)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(c, ":")
	if len(parts) < 6 {
		return "", ""
	}
	product = cleanText(strings.ReplaceAll(parts[4], "_", " "), maxProduct)
	if product == "*" || product == "-" {
		product = ""
	}
	switch parts[5] {
	case "*", "-", "":
		return "", product
	}
	return c, product
}
