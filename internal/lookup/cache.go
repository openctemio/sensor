package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
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
	// this is still used. Ignored when AnyAge is set.
	MaxStale time.Duration
	// AnyAge: when the source cannot be reached, a valid copy is used
	// whatever its age (a stale routing table or registry list beats no
	// answer).
	AnyAge bool
	// MaxBytes bounds the download.
	MaxBytes int64
	// Validate checks a finished download before it replaces the copy; an
	// error keeps the previous copy and counts as a failed refresh.
	Validate func(path string) error
	// Attempts is how many times a download is tried when there is no
	// copy to fall back on (default 1). Attempts wait with exponential
	// back-off and full jitter, at most Bound in all (default 90 s),
	// honouring Retry-After within that bound.
	Attempts int
	Bound    time.Duration
}

const (
	defaultBound = 90 * time.Second
	backoffBase  = 2 * time.Second
	backoffMax   = 30 * time.Second
)

// now is the clock (tests). Sleep, the wait between attempts, and Jitter, the
// random part of it, are replaced by tests.
var (
	now = time.Now
	// Sleep waits d or until ctx ends.
	Sleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	Jitter = func(max time.Duration) time.Duration {
		if max <= 0 {
			return 0
		}
		return rand.N(max + 1) // #nosec G404 -- back-off spread, not a secret
	}
)

// Meta is the sidecar of a cached file: the validators of the copy and the
// outcome of the last refresh. It holds no URL, so it carries no credentials.
type Meta struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	LastAttempt  time.Time `json:"last_attempt,omitempty"`
	// LastResult is ok, not_modified or failed.
	LastResult string `json:"last_result,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

func metaPath(path string) string { return path + ".meta" }

// ReadMeta reads the sidecar of the cached file at path (zero when absent).
func ReadMeta(path string) Meta {
	var m Meta
	b, err := os.ReadFile(metaPath(path)) // #nosec G304 -- the sensor's own cache
	if err != nil || len(b) > 4096 {
		return Meta{}
	}
	if json.Unmarshal(b, &m) != nil {
		return Meta{}
	}
	return m
}

// writeMeta is best effort: the cache directory may be read-only.
func writeMeta(path string, m Meta) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".meta.*")
	if err != nil {
		return
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Chmod(name, 0o600) != nil || os.Rename(name, metaPath(path)) != nil {
		_ = os.Remove(name)
	}
}

// Age is how old the cached file at path is (false when there is none).
func Age(path string) (time.Duration, bool) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return 0, false
	}
	return now().Sub(st.ModTime()), true
}

// Fetch returns the path of a usable copy of f in dir. A copy younger than
// MaxAge is used as it is. Otherwise the source is asked (with the copy's
// ETag and Last-Modified when it has them: a 304 keeps the copy and renews
// its age). The download goes to a temporary file, is checked by
// f.Validate and replaces the copy only when it is complete and valid, so a
// task that dies mid-download, or a bad answer, leaves the previous copy in
// place.
//
// When the refresh fails and a copy exists (and is younger than MaxStale, or
// AnyAge is set) the copy is returned with stale == true and the refresh
// error, which the caller logs: a failed refresh never fails a task while a
// valid copy exists. With no copy, the download is retried (f.Attempts) and
// the error is returned with an empty path.
func (c *Client) Fetch(ctx context.Context, dir string, f Cached) (path string, stale bool, err error) {
	path = filepath.Join(dir, f.Name)
	st, statErr := os.Stat(path)
	have := statErr == nil && st.Mode().IsRegular()
	if have && now().Sub(st.ModTime()) < f.MaxAge {
		return path, false, nil
	}
	meta := Meta{}
	if have {
		meta = ReadMeta(path)
	}
	attempts := 1
	if !have && f.Attempts > 1 {
		attempts = f.Attempts
	}
	bound := f.Bound
	if bound <= 0 {
		bound = defaultBound
	}
	var waited time.Duration
	started := now()
	var dlErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			d := wait(i, dlErr)
			spent := max(waited, now().Sub(started))
			if left := bound - spent; d > left {
				d = left
			}
			if d <= 0 {
				break
			}
			if err := Sleep(ctx, d); err != nil {
				dlErr = err
				break
			}
			waited += d
		}
		var notModified bool
		notModified, dlErr = c.download(ctx, path, f, &meta, have)
		if dlErr == nil {
			meta.LastAttempt, meta.LastError = now(), ""
			meta.LastResult = "ok"
			if notModified {
				meta.LastResult = "not_modified"
				t := now()
				_ = os.Chtimes(path, t, t)
			}
			writeMeta(path, meta)
			return path, false, nil
		}
		if !retryable(dlErr) || ctx.Err() != nil {
			break
		}
	}
	if have {
		meta.LastAttempt, meta.LastResult, meta.LastError = now(), "failed", Describe(dlErr)
		writeMeta(path, meta)
		if f.AnyAge || now().Sub(st.ModTime()) < f.MaxStale {
			return path, true, dlErr
		}
	}
	return "", false, dlErr
}

// wait is the pause before attempt i (i >= 1): the server's Retry-After, else
// exponential back-off with full Jitter.
func wait(i int, err error) time.Duration {
	var se *StatusError
	if errors.As(err, &se) && se.RetryAfter > 0 {
		return se.RetryAfter
	}
	d := backoffBase << (i - 1)
	if d > backoffMax || d <= 0 {
		d = backoffMax
	}
	return Jitter(d)
}

// retryable: a network error, a timeout, a 5xx, 408 or 429, or a download
// that did not validate (it may have been cut short). A refusal (not https,
// a target host) or another 4xx is final.
func retryable(err error) bool {
	if errors.Is(err, ErrNotHTTPS) || errors.Is(err, ErrTargetHost) || errors.Is(err, context.Canceled) {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code >= 500 || se.Code == http.StatusRequestTimeout || se.Code == http.StatusTooManyRequests
	}
	var big *tooLargeError
	return !errors.As(err, &big)
}

type tooLargeError struct{ msg string }

func (e *tooLargeError) Error() string { return e.msg }

func (c *Client) download(ctx context.Context, path string, f Cached, meta *Meta, have bool) (notModified bool, err error) {
	var etag, lm string
	if have {
		etag, lm = meta.ETag, meta.LastModified
	}
	resp, err := c.openConditional(ctx, f.URL, etag, lm)
	if errors.Is(err, ErrNotModified) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("fetch %s: %w", hostOf(f.URL), err)
	}
	body := resp.Body
	defer func() { _ = body.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+f.Name+".*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	n, err := io.Copy(tmp, io.LimitReader(body, f.MaxBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, fmt.Errorf("fetch %s: %w", hostOf(f.URL), err)
	}
	if n > f.MaxBytes {
		return false, &tooLargeError{fmt.Sprintf("fetch %s: larger than %d bytes", hostOf(f.URL), f.MaxBytes)}
	}
	if n == 0 {
		return false, fmt.Errorf("fetch %s: empty answer", hostOf(f.URL))
	}
	if f.Validate != nil {
		if err := f.Validate(tmpName); err != nil {
			return false, fmt.Errorf("fetch %s: the download is not valid, the previous copy is kept: %w", hostOf(f.URL), err)
		}
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, err
	}
	meta.ETag, meta.LastModified = capHeader(resp.Header.Get("ETag")), capHeader(resp.Header.Get("Last-Modified"))
	return false, nil
}

func capHeader(v string) string {
	if len(v) > 256 {
		return ""
	}
	return v
}
