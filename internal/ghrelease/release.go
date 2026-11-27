// Package ghrelease reads GitHub release metadata and verifies asset downloads.
package ghrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/lalibi/git-sops/internal/ui"
)

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	APIURL string `json:"url"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type Release struct {
	Tag        string  `json:"tag_name"`
	Prerelease bool    `json:"prerelease"`
	Draft      bool    `json:"draft"`
	Assets     []Asset `json:"assets"`
}

func get(ctx context.Context, client *http.Client, url, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "git-sops")
	req.Header.Set("Accept", accept)
	if req.URL.Scheme == "https" && req.URL.Host == "api.github.com" {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("GitHub returned %s (check the API rate limit and GITHUB_TOKEN permissions)", resp.Status)
		}
		return nil, fmt.Errorf("GitHub returned %s for %s", resp.Status, url)
	}
	return resp, nil
}

func Lookup(ctx context.Context, client *http.Client, repo, selector string) (*Release, error) {
	resp, err := get(ctx, client, "https://api.github.com/repos/"+repo+"/releases/"+selector, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (a Asset) Download(ctx context.Context, client *http.Client, dest io.Writer, want []byte) error {
	if a.Size <= 0 {
		return fmt.Errorf("invalid release asset size for %s", a.Name)
	}
	url := a.APIURL
	if url == "" {
		url = a.URL
	}
	resp, err := get(ctx, client, url, "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bar := ui.NewProgress("Downloading "+a.Name, a.Size, true)
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(dest, hasher, bar), io.LimitReader(resp.Body, a.Size+1))
	if err != nil {
		bar.Abort()
		return err
	}
	if n != a.Size || !bytes.Equal(hasher.Sum(nil), want) {
		bar.Abort()
		return fmt.Errorf("size or SHA-256 verification failed for %s", a.Name)
	}
	bar.Finish("Verified %s", a.Name)
	return nil
}
