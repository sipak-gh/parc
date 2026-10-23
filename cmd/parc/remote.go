// Remote inspection: finding an encrypted name from a URL.
package main

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const remoteTimeout = 30 * time.Second

// isURL reports whether s looks like an http(s) URL rather than a local path.
func isURL(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// inspectURL decrypts the name found in the URL itself. With follow, and only
// if that fails, it requests the URL (following redirects) and also tries the
// Content-Disposition filename and the final URL's last path segment.
func inspectURL(km *keyMaterial, raw string, follow bool) (string, error) {
	base, berr := remoteBaseName(raw)
	if berr == nil {
		if name, err := decryptName(km, base); err == nil || !follow {
			return name, err
		}
	} else if !follow {
		return "", berr
	}

	candidates, err := fetchNameCandidates(raw)
	if err != nil {
		return "", err
	}
	for _, c := range candidates {
		if name, err := decryptName(km, c); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no parc-encrypted name found at %s (after redirects) or in its headers", raw)
}

// fetchNameCandidates requests rawURL (HEAD, falling back to GET) and returns
// the names it might hide: the Content-Disposition filename and the final
// URL's last segment after redirects.
func fetchNameCandidates(raw string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()

	resp, err := doRequest(ctx, http.MethodHead, raw)
	if err == nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		resp.Body.Close()
		resp, err = doRequest(ctx, http.MethodGet, raw)
	}
	if err != nil {
		return nil, err
	}
	// The body is never read; only headers and the final URL matter.
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("remote returned %s", resp.Status)
	}

	var out []string
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if fn := params["filename"]; fn != "" {
				out = append(out, path.Base(strings.ReplaceAll(fn, `\`, "/")))
			}
		}
	}
	if resp.Request != nil && resp.Request.URL != nil {
		if b, err := remoteBaseName(resp.Request.URL.String()); err == nil {
			out = append(out, b)
		}
	}
	return out, nil
}

var httpClient = &http.Client{CheckRedirect: func(_ *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	return nil
}}

func doRequest(ctx context.Context, method, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "parc")
	return httpClient.Do(req)
}

// remoteBaseName returns the last path segment of rawURL (query and fragment
// removed, percent-decoding applied).
func remoteBaseName(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(u.Path, "/") {
		return "", errors.New("URL has no file name")
	}
	b := path.Base(u.Path) // Path is already percent-decoded
	if b == "." || b == "/" || b == "" {
		return "", errors.New("URL has no file name")
	}
	return b, nil
}
