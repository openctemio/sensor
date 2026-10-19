package nuclei

// One run for the platform's and the organization's templates (api RFC-118,
// rule sources "both"). The sensor's own template set runs with
// -disable-unsigned-templates: nuclei loads only templates signed by a key
// it trusts. The organization's templates are signed by the platform for
// this command (verified by the SDK) and then checked on the sensor
// (core.CheckCustomTemplate), but nuclei cannot verify those signatures.
// So, for one run, the sensor vouches for exactly the templates it checked:
// it signs copies of them with a key made for this run alone, and hands
// nuclei only that key's certificate (NUCLEI_USER_CERTIFICATE). The private
// key never leaves this process and is gone when the run ends; a template
// the sensor did not check carries no valid signature and is not loaded.
//
// The signature is nuclei's template signature: ECDSA P-256 over the
// SHA-256 of the template (trimmed, CRLF as LF), ASN.1, gob-encoded, as the
// last line "# digest: <hex>:<fragment>", fragment = MD5 of the public key's
// X coordinate.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // nuclei's signer fragment, an identifier, not a security hash
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// nucleiUserCertEnv is the environment variable nuclei reads an additional
// trusted signer certificate from (PEM content or a file path).
const nucleiUserCertEnv = "NUCLEI_USER_CERTIFICATE"

// signaturePrefix starts nuclei's signature line.
const signaturePrefix = "# digest: "

// runSigner signs one run's custom templates with a key made for that run.
type runSigner struct {
	key      *ecdsa.PrivateKey
	certPEM  []byte
	fragment string
}

// newRunSigner makes a P-256 key and a self-signed certificate valid for a
// day (nuclei requires a common name).
func newRunSigner() (*runSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("run signer key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, fmt.Errorf("run signer serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "openctem-sensor-run"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("run signer certificate: %w", err)
	}
	fragment, err := publicKeyFragment(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &runSigner{
		key:      key,
		certPEM:  pem.EncodeToMemory(&pem.Block{Type: "PD NUCLEI USER CERTIFICATE", Bytes: der}),
		fragment: fragment,
	}, nil
}

// publicKeyFragment is MD5 of the public key's X coordinate without leading
// zero bytes, hex-encoded (nuclei's signer fragment).
func publicKeyFragment(pub *ecdsa.PublicKey) (string, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return "", fmt.Errorf("run signer public key: %w", err)
	}
	if len(raw) < 3 || raw[0] != 4 || (len(raw)-1)%2 != 0 {
		return "", errors.New("run signer public key: not an uncompressed point")
	}
	x := bytes.TrimLeft(raw[1:1+(len(raw)-1)/2], "\x00")
	sum := md5.Sum(x) //nolint:gosec // identifier, see import
	return hex.EncodeToString(sum[:]), nil
}

// signableContent is the part of a template nuclei's signature covers: the
// file without a trailing signature line, trimmed, CRLF as LF.
func signableContent(raw []byte) []byte {
	if i := bytes.LastIndex(raw, []byte(signaturePrefix)); i >= 0 {
		raw = raw[:i]
	}
	return bytes.TrimSpace(bytes.ReplaceAll(bytes.TrimSpace(raw), []byte("\r\n"), []byte("\n")))
}

// sign returns content with this run's signature line.
func (r *runSigner) sign(content []byte) ([]byte, error) {
	sum := sha256.Sum256(content)
	sig, err := ecdsa.SignASN1(rand.Reader, r.key, sum[:])
	if err != nil {
		return nil, fmt.Errorf("sign template: %w", err)
	}
	var enc bytes.Buffer
	if err := gob.NewEncoder(&enc).Encode(sig); err != nil {
		return nil, fmt.Errorf("sign template: %w", err)
	}
	out := make([]byte, 0, len(content)+len(signaturePrefix)+2*enc.Len()+len(r.fragment)+3)
	out = append(out, content...)
	out = append(out, '\n')
	out = fmt.Appendf(out, "%s%x:%s\n", signaturePrefix, enc.Bytes(), r.fragment)
	return out, nil
}

// signedTemplates is a run's signed copy of the custom templates.
type signedTemplates struct {
	// dir holds the signed copies (removed by cleanup).
	dir string
	// certPEM is the run's certificate, for NUCLEI_USER_CERTIFICATE.
	certPEM []byte
	// digests maps each signed copy (its real path) to the digest of the
	// template as received ("sha256:<hex>"), so results name the content
	// the platform sent, not the copy with the run's signature.
	digests map[string]string
}

// signCustomTemplates checks every template in srcDir (CheckCustomTemplates)
// and writes signed copies into a new directory under the run's temporary
// directory. Only regular files directly in srcDir are copied; the source
// is never changed.
func signCustomTemplates(srcDir string) (*signedTemplates, func(), error) {
	if err := CheckCustomTemplates(srcDir); err != nil {
		return nil, nil, err
	}
	signer, err := newRunSigner()
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "nuclei-signed-*")
	if err != nil {
		return nil, nil, fmt.Errorf("signed templates: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("custom templates: %w", err)
	}
	out := &signedTemplates{dir: dir, certPEM: signer.certPEM, digests: map[string]string{}}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || strings.ContainsAny(name, `/\`) {
			cleanup()
			return nil, nil, fmt.Errorf("custom template %q is not a regular file", name)
		}
		raw, err := os.ReadFile(filepath.Join(srcDir, name)) //nolint:gosec // a file the executor wrote into its own temp dir, checked above
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("custom template %q: %w", name, err)
		}
		// What is signed is the received template without a trailing
		// signature line: check those exact bytes, so a cut at an earlier
		// "# digest: " cannot sign content the check above never saw.
		content := signableContent(raw)
		if err := checkCustomTemplate(content); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("custom template %q refused: %w", name, err)
		}
		signed, err := signer.sign(content)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		dst := filepath.Join(dir, name)
		if err := os.WriteFile(dst, signed, 0o600); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("signed template %q: %w", name, err)
		}
		real, err := filepath.EvalSymlinks(dst)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("signed template %q: %w", name, err)
		}
		sum := sha256.Sum256(raw)
		out.digests[real] = "sha256:" + hex.EncodeToString(sum[:])
	}
	return out, cleanup, nil
}
