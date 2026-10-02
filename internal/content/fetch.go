package content

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// Fetcher reads content over HTTPS or from local files (file:// URLs or
// plain paths, for air-gapped hosts).
//
// Outbound clients come from sdk-go httpsec (security-lint Rule 1):
//   - the default upstream sources (GitHub, the semgrep registry) are reached
//     with httpsec.SafeHTTPClient, which refuses private, loopback and
//     metadata addresses and re-checks every redirect;
//   - a mirror the host operator configured on the sensor (environment, an
//     internal web server that is often on a private address) is reached
//     with httpsec.NewAPIClient, the same trust as API_URL: private
//     addresses allowed, link-local/metadata refused, no redirects.
//
// Sources never come from the platform (api RFC-031 D2: the policy has no
// URL member), so nothing the platform sends can reach the trusted client.
type Fetcher struct {
	// Client overrides the client (tests).
	Client *http.Client
	// Trusted marks every URL this fetcher reads as host-operator
	// configuration (see above).
	Trusted bool
	// AllowHTTP permits plain http:// URLs (tests; an internal mirror the
	// host operator explicitly configured).
	AllowHTTP bool
}

func (f *Fetcher) client() *http.Client {
	if f != nil && f.Client != nil {
		return f.Client
	}
	if f != nil && f.Trusted {
		return httpsec.NewAPIClient(fetchTimeout)
	}
	return httpsec.SafeHTTPClient(fetchTimeout)
}

// fetchTimeout bounds one content download (a template archive or a rules
// bundle; the trivy DB is downloaded by trivy itself).
const fetchTimeout = 10 * time.Minute

// localPath returns the file path of a file:// URL or plain absolute path.
func localPath(u string) (string, bool) {
	if p, ok := strings.CutPrefix(u, "file://"); ok {
		return p, true
	}
	if filepath.IsAbs(u) {
		return u, true
	}
	return "", false
}

// open returns a reader for u, at most limit bytes.
func (f *Fetcher) open(ctx context.Context, u string, limit int64) (io.ReadCloser, error) {
	if p, ok := localPath(u); ok {
		fh, err := os.Open(p) //nolint:gosec // operator-configured local source
		if err != nil {
			return nil, err
		}
		return limitedCloser{Reader: io.LimitReader(fh, limit+1), c: fh}, nil
	}
	pu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	allowHTTP := f != nil && f.AllowHTTP
	if pu.Scheme != "https" && (pu.Scheme != "http" || !allowHTTP) {
		return nil, fmt.Errorf("refusing %s: only https:// and local files", pu.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "openctemio-sensor-content")
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", redactURL(u), resp.StatusCode)
	}
	return limitedCloser{Reader: io.LimitReader(resp.Body, limit+1), c: resp.Body}, nil
}

type limitedCloser struct {
	io.Reader
	c io.Closer
}

func (l limitedCloser) Close() error { return l.c.Close() }

// ErrTooLarge is returned when content exceeds its size limit.
var ErrTooLarge = errors.New("content exceeds its size limit")

// get reads u fully (small documents).
func (f *Fetcher) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	rc, err := f.open(ctx, u, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}

// download writes u to path and returns its sha256 (hex).
func (f *Fetcher) download(ctx context.Context, u, path string, limit int64) (string, error) {
	rc, err := f.open(ctx, u, limit)
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // path inside the staging dir
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), rc)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", ErrTooLarge
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// redactURL drops credentials and the query from a URL for messages.
func redactURL(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return "(url)"
	}
	pu.User = nil
	pu.RawQuery = ""
	return pu.String()
}

// Extraction limits for a template archive.
const (
	maxArchiveFiles     = 100000
	maxArchiveFileBytes = 64 << 20
	maxArchiveBytes     = 2 << 30
)

// extractTarGz extracts a .tar.gz into dir, dropping the archive's top
// directory (GitHub archives wrap everything in <repo>-<tag>/). Only regular
// files and directories are extracted; absolute paths, ".." and links are
// refused, and sizes are bounded.
func extractTarGz(archive, dir string) (int, error) {
	fh, err := os.Open(archive) //nolint:gosec // file in the staging dir
	if err != nil {
		return 0, err
	}
	defer func() { _ = fh.Close() }()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(gz)
	files := 0
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return files, err
		}
		name := hdr.Name
		if strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
			return files, fmt.Errorf("archive entry %q: absolute path", name)
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return files, fmt.Errorf("archive entry %q: path traversal", name)
			}
		}
		// Strip the top directory.
		_, rel, ok := strings.Cut(strings.TrimPrefix(name, "./"), "/")
		if !ok || rel == "" {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
			return files, fmt.Errorf("archive entry %q escapes the directory", name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return files, err
			}
		case tar.TypeReg:
			files++
			if files > maxArchiveFiles {
				return files, fmt.Errorf("%w: more than %d files", ErrTooLarge, maxArchiveFiles)
			}
			if hdr.Size > maxArchiveFileBytes {
				return files, fmt.Errorf("%w: %s is %d bytes", ErrTooLarge, rel, hdr.Size)
			}
			total += hdr.Size
			if total > maxArchiveBytes {
				return files, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, int64(maxArchiveBytes))
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return files, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) //nolint:gosec // checked above
			if err != nil {
				return files, err
			}
			_, err = io.Copy(out, io.LimitReader(tr, hdr.Size))
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return files, err
			}
		case tar.TypeSymlink, tar.TypeLink:
			return files, fmt.Errorf("archive entry %q: links are not allowed", name)
		case tar.TypeXGlobalHeader:
			continue
		default:
			// Devices, fifos: skip.
		}
	}
	return files, nil
}

// copyTree copies the regular files and directories of src into dst
// (symlinks are refused), returning the number of files.
func copyTree(src, dst string) (int, error) {
	files := 0
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.Type()&os.ModeSymlink != 0:
			return fmt.Errorf("%s: links are not allowed", rel)
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type().IsRegular():
			files++
			if files > maxArchiveFiles {
				return fmt.Errorf("%w: more than %d files", ErrTooLarge, maxArchiveFiles)
			}
			return copyFile(path, target)
		default:
			return nil
		}
	})
	return files, err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // operator-configured local source
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) //nolint:gosec // inside the staging dir
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
