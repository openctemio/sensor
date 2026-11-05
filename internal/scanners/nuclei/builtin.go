package nuclei

// The sensor's own checks, compiled into the binary: a template the platform
// may request by id (a retest or a verification step, ValidateOptions.
// TemplateID) that no nuclei-templates release carries. The set is read-only
// and part of the signed sensor release, so the platform needs no template
// delivery for it. At run time the sensor signs the copy it runs with a key
// made for that run alone (run_signer.go), after the same content check as a
// delivered template (core.CheckNucleiCustomTemplate), so nuclei keeps
// -disable-unsigned-templates on and loads nothing it did not vouch for.

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// BackupFileSignatureID checks that a guessed backup, archive or dump URL
// serves the bytes of a zip, gzip or tar archive or a SQL dump (GET only,
// 1 KiB of the body at most). The platform's path discovery maps its guessed
// backup endpoints to it.
const BackupFileSignatureID = "openctem-backup-file-signature"

// BuiltinTemplate returns the compiled-in template with this nuclei id.
func BuiltinTemplate(id string) ([]byte, bool) {
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, `/\.`) {
		return nil, false
	}
	raw, err := fs.ReadFile(builtinFS, "builtin/"+id+".yaml")
	if err != nil {
		return nil, false
	}
	return raw, true
}

// BuiltinTemplateIDs lists the compiled-in template ids.
func BuiltinTemplateIDs() []string {
	entries, err := fs.ReadDir(builtinFS, "builtin")
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())))
	}
	return ids
}

// signBuiltinTemplate signs a copy of the compiled-in template for one run
// (signCustomTemplates, which checks it first) and returns the signed set,
// the path of the signed file and the cleanup. The digest the set reports is
// the compiled-in content's.
func signBuiltinTemplate(id string) (*signedTemplates, string, func(), error) {
	raw, ok := BuiltinTemplate(id)
	if !ok {
		return nil, "", nil, fmt.Errorf("builtin template %q not found", id)
	}
	src, err := os.MkdirTemp("", "nuclei-builtin-*")
	if err != nil {
		return nil, "", nil, fmt.Errorf("builtin template: %w", err)
	}
	defer func() { _ = os.RemoveAll(src) }()
	name := id + ".yaml"
	if err := os.WriteFile(filepath.Join(src, name), raw, 0o600); err != nil {
		return nil, "", nil, fmt.Errorf("builtin template: %w", err)
	}
	signed, cleanup, err := signCustomTemplates(src)
	if err != nil {
		return nil, "", nil, err
	}
	return signed, filepath.Join(signed.dir, name), cleanup, nil
}
