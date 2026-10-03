package sopsx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lalibi/git-sops/internal/ui"
)

const DefaultVersion = "3.13.3"

func assetName(version string) (string, error) {
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("unsupported architecture: %s", arch)
	}

	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf("sops-v%s.%s.exe", version, arch), nil
	case "linux", "darwin":
		return fmt.Sprintf("sops-v%s.%s.%s", version, runtime.GOOS, arch), nil
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

type release struct {
	Assets []struct {
		Name   string `json:"name"`
		URL    string `json:"browser_download_url"`
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	} `json:"assets"`
}

func fetchRelease(client *http.Client, version string) (*release, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/getsops/sops/releases/tags/v%s", version)

	req, _ := http.NewRequest(http.MethodGet, apiURL, nil)
	req.Header.Set("User-Agent", "git-sops")
	req.Header.Set("Accept", "application/vnd.github+json")
	// Unauthenticated API calls are rate-limited per IP, which shared CI runners exhaust.
	if token := firstEnv("GITHUB_TOKEN", "GH_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("sops v%s was not found on GitHub", version)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("release lookup failed: %s (likely GitHub API rate limit; set GITHUB_TOKEN and retry)", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release lookup failed: %s", resp.Status)
	}

	var r release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Install downloads the sops release into InstallDir and returns the executable path.
// The GitHub-published SHA256 digest is verified when present.
func Install(version string) (string, error) {
	name, err := assetName(version)
	if err != nil {
		return "", err
	}

	dir, err := InstallDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 5 * time.Minute}

	spin := ui.Spin(fmt.Sprintf("Looking up sops v%s", version))
	rel, err := fetchRelease(client, version)
	if err != nil {
		spin.Fail("Looking up sops v%s", version)
		return "", err
	}

	var url, digest string
	var size int64
	for _, a := range rel.Assets {
		if a.Name == name {
			url, digest, size = a.URL, a.Digest, a.Size
			break
		}
	}
	if url == "" {
		spin.Fail("Looking up sops v%s", version)
		return "", fmt.Errorf("release asset %q was not found in getsops/sops v%s", name, version)
	}
	spin.Done("Found %s", name)

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "git-sops")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: %s", resp.Status)
	}
	if resp.ContentLength > 0 {
		size = resp.ContentLength
	}

	// Write beside the destination so the final rename stays on one volume.
	tmp, err := os.CreateTemp(dir, "sops-download-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	bar := ui.NewProgress(fmt.Sprintf("Downloading sops v%s", version), size, true)
	hasher := sha256.New()

	if _, err := io.Copy(io.MultiWriter(tmp, hasher, bar), resp.Body); err != nil {
		bar.Abort()
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		bar.Abort()
		return "", err
	}
	bar.Finish("Downloaded sops v%s", version)

	if expected, ok := strings.CutPrefix(digest, "sha256:"); ok && expected != "" {
		if actual := hex.EncodeToString(hasher.Sum(nil)); !strings.EqualFold(actual, expected) {
			return "", fmt.Errorf("SHA256 verification failed for %s", name)
		}
		ui.Okf("SHA256 verified")
	} else {
		ui.Warnf("GitHub published no SHA256 digest for %s; HTTPS was used but the download could not be hash-checked.", name)
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return "", err
	}

	dest := filepath.Join(dir, exeName())
	if err := os.Rename(tmpName, dest); err != nil {
		// Windows cannot rename over an existing file that is in use.
		_ = os.Remove(dest)
		if err := os.Rename(tmpName, dest); err != nil {
			return "", err
		}
	}

	return dest, nil
}
