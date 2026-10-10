package lookup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Cached is one public file a lookup keeps between tasks.
type Cached struct {
	// Name is the file name in the cache directory.
	Name string
	// URL is where it is fetched from (https).
	URL string
	// MaxAge: a copy younger than this is used without asking the source.
	MaxAge time.Duration
	// MaxStale: when the source cannot be reached, a copy younger than
	// this is still used.
	MaxStale time.Duration
	// MaxBytes bounds the download.
	MaxBytes int64
}

// now is the clock (tests).
var now = time.Now

// Fetch returns the path of a fresh copy of f in dir, downloading it when
// the cached copy is missing or older than MaxAge. The download goes to a
// temporary file first and replaces the copy only when complete, so a
// task that dies mid-download leaves the previous copy in place. When the
// download fails, a copy younger than MaxStale is returned with the error
// logged by the caller (stale == true).
func (c *Client) Fetch(ctx context.Context, dir string, f Cached) (path string, stale bool, err error) {
	path = filepath.Join(dir, f.Name)
	st, statErr := os.Stat(path)
	if statErr == nil && st.Mode().IsRegular() && now().Sub(st.ModTime()) < f.MaxAge {
		return path, false, nil
	}
	dlErr := c.download(ctx, path, f)
	if dlErr == nil {
		return path, false, nil
	}
	if statErr == nil && st.Mode().IsRegular() && now().Sub(st.ModTime()) < f.MaxStale {
		return path, true, dlErr
	}
	return "", false, dlErr
}

func (c *Client) download(ctx context.Context, path string, f Cached) error {
	body, err := c.Open(ctx, f.URL)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", hostOf(f.URL), err)
	}
	defer func() { _ = body.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+f.Name+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	n, err := io.Copy(tmp, io.LimitReader(body, f.MaxBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("fetch %s: %w", hostOf(f.URL), err)
	}
	if n > f.MaxBytes {
		return fmt.Errorf("fetch %s: larger than %d bytes", hostOf(f.URL), f.MaxBytes)
	}
	if n == 0 {
		return fmt.Errorf("fetch %s: empty answer", hostOf(f.URL))
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
