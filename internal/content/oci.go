package content

// A minimal OCI distribution client: resolve a tag to its manifest digest
// (HEAD /v2/<repo>/manifests/<tag>), with the anonymous bearer-token flow
// registries use for public repositories and optional basic credentials.
// The download itself is trivy's (it verifies every blob against the
// manifest); resolving first lets the sensor pin the exact digest, skip a
// download when nothing changed and report what it installed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// manifestAccept lists the manifest media types a DB artifact may use.
var manifestAccept = strings.Join([]string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}, ", ")

// OCIRef is a parsed "host/repo/path:tag" or "host/repo@sha256:..." reference.
type OCIRef struct {
	Host, Repo, Tag, Digest string
}

// ParseOCIRef parses an image reference with an explicit registry host.
func ParseOCIRef(s string) (OCIRef, error) {
	var r OCIRef
	s = strings.TrimSpace(s)
	host, rest, ok := strings.Cut(s, "/")
	if !ok || host == "" || rest == "" || (!strings.ContainsAny(host, ".:") && host != "localhost") {
		return r, fmt.Errorf("invalid repository %q (want registry/repository[:tag])", s)
	}
	r.Host = host
	if repo, dg, ok := strings.Cut(rest, "@"); ok {
		r.Repo, r.Digest = repo, dg
		if !digestRE.MatchString(dg) {
			return r, fmt.Errorf("invalid digest in %q", s)
		}
	} else if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "/") {
		r.Repo, r.Tag = rest[:i], rest[i+1:]
	} else {
		r.Repo = rest
	}
	if r.Repo == "" || strings.Contains(r.Repo, "..") || strings.HasPrefix(s, "-") {
		return r, fmt.Errorf("invalid repository %q", s)
	}
	return r, nil
}

// Name is host/repo without tag or digest.
func (r OCIRef) Name() string { return r.Host + "/" + r.Repo }

// String is the reference as written.
func (r OCIRef) String() string {
	switch {
	case r.Digest != "":
		return r.Name() + "@" + r.Digest
	case r.Tag != "":
		return r.Name() + ":" + r.Tag
	default:
		return r.Name()
	}
}

// OCIResolver resolves references against a registry.
type OCIResolver struct {
	// Client overrides the client (tests). Otherwise a registry the host
	// operator configured (Trusted) is reached with httpsec.NewAPIClient
	// (private addresses allowed: internal mirrors), and the default public
	// registries with httpsec.SafeHTTPClient. See Fetcher.
	Client *http.Client
	// Trusted marks the registries as host-operator configuration.
	Trusted bool
	// Scheme is "https" (default); tests use "http".
	Scheme string
	// Username and Password are optional basic credentials.
	Username, Password string
}

// ResolveDigest returns the manifest digest ref points at.
func (o *OCIResolver) ResolveDigest(ctx context.Context, ref OCIRef) (string, error) {
	if ref.Digest != "" {
		return ref.Digest, nil
	}
	tag := ref.Tag
	if tag == "" {
		tag = "latest"
	}
	client := o.Client
	if client == nil {
		if o.Trusted {
			client = httpsec.NewAPIClient(30 * time.Second)
		} else {
			client = httpsec.SafeHTTPClient(30 * time.Second)
		}
	}
	scheme := o.Scheme
	if scheme == "" {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, ref.Host, ref.Repo, url.PathEscape(tag))

	resp, err := o.head(ctx, client, u, "")
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		auth, err := o.authorize(ctx, client, resp.Header.Get("WWW-Authenticate"))
		if err != nil {
			return "", err
		}
		resp, err = o.head(ctx, client, u, auth)
		if err != nil {
			return "", err
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: manifest: HTTP %d", ref, resp.StatusCode)
	}
	dg := resp.Header.Get("Docker-Content-Digest")
	if !digestRE.MatchString(dg) {
		return "", fmt.Errorf("%s: registry sent no usable digest", ref)
	}
	return dg, nil
}

func (o *OCIResolver) head(ctx context.Context, client *http.Client, u, auth string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", manifestAccept)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
	return resp, nil
}

// authorize answers a WWW-Authenticate challenge: Basic with the
// credentials, or Bearer by fetching a token from the realm.
func (o *OCIResolver) authorize(ctx context.Context, client *http.Client, challenge string) (string, error) {
	scheme, params := parseChallenge(challenge)
	switch strings.ToLower(scheme) {
	case "basic":
		if o.Username == "" {
			return "", errors.New("registry wants credentials")
		}
		req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
		req.SetBasicAuth(o.Username, o.Password)
		return req.Header.Get("Authorization"), nil
	case "bearer":
		realm := params["realm"]
		ru, err := url.Parse(realm)
		if err != nil || (ru.Scheme != "https" && (ru.Scheme != "http" || o.Scheme != "http")) {
			return "", fmt.Errorf("registry token realm %q refused", realm)
		}
		q := ru.Query()
		if v := params["service"]; v != "" {
			q.Set("service", v)
		}
		if v := params["scope"]; v != "" {
			q.Set("scope", v)
		}
		ru.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ru.String(), nil)
		if err != nil {
			return "", err
		}
		if o.Username != "" {
			req.SetBasicAuth(o.Username, o.Password)
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("registry token: HTTP %d", resp.StatusCode)
		}
		var tok struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
			return "", fmt.Errorf("registry token: %w", err)
		}
		t := firstNonEmpty(tok.Token, tok.AccessToken)
		if t == "" {
			return "", errors.New("registry token: empty")
		}
		return "Bearer " + t, nil
	default:
		return "", fmt.Errorf("registry wants %q authentication", scheme)
	}
}

// parseChallenge parses `Bearer realm="...",service="...",scope="..."`.
func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		k, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		var v string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				break
			}
			v, rest = after[1:end+1], after[end+2:]
		} else {
			v, rest, _ = strings.Cut(after, ",")
		}
		params[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return scheme, params
}
