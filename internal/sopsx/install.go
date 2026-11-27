package sopsx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/lalibi/git-sops/internal/ghrelease"
	"github.com/lalibi/git-sops/internal/ui"
)

const DefaultVersion = "3.13.3"

// Pin the upstream sops-v3.13.3.checksums.txt, which covers all platforms.
// Update both constants together when reviewing a new default release.
const defaultManifestSHA256 = "91710ede6a3218e5b62286412543768a92d0c3449434951bd148d21043aad538"

var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

func assetName(version string) (string, error) {
	if !releaseVersion.MatchString(version) {
		return "", fmt.Errorf("invalid SOPS release version %q", version)
	}
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

type asset = ghrelease.Asset

// Install downloads the sops release into InstallDir and returns the executable path.
// It requires a SHA-256 from the release API or the upstream checksum manifest.
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
	rel, err := ghrelease.Lookup(context.Background(), client, "getsops/sops", "tags/v"+version)
	if err != nil {
		spin.Fail("Looking up sops v%s", version)
		return "", err
	}

	var binary, manifest asset
	for _, a := range rel.Assets {
		switch a.Name {
		case name:
			binary = a
		case "sops-v" + version + ".checksums.txt":
			manifest = a
		}
	}
	if binary.URL == "" {
		spin.Fail("Looking up sops v%s", version)
		return "", fmt.Errorf("release asset %q was not found in getsops/sops v%s", name, version)
	}
	spin.Done("Found %s", name)

	want, err := expectedDigest(client, version, binary, manifest)
	if err != nil {
		return "", err
	}
	return installAsset(client, dir, binary, want)
}

func expectedDigest(client *http.Client, version string, binary, manifest asset) ([]byte, error) {
	raw, ok := strings.CutPrefix(binary.Digest, "sha256:")
	if version == DefaultVersion || binary.Digest == "" {
		if manifest.URL == "" {
			return nil, fmt.Errorf("missing upstream checksum manifest for %s", binary.Name)
		}
		resp, err := client.Get(manifest.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("checksum manifest download failed: %s", resp.Status)
		}
		const limit = 1 << 20
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil || len(data) > limit {
			return nil, fmt.Errorf("could not read checksum manifest for %s", binary.Name)
		}
		if version == DefaultVersion && fmt.Sprintf("%x", sha256.Sum256(data)) != defaultManifestSHA256 {
			return nil, fmt.Errorf("SOPS checksum manifest differs from the pinned SHA-256 for v%s", version)
		}
		raw, ok = "", false
		for line := range strings.SplitSeq(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == binary.Name {
				if ok {
					return nil, fmt.Errorf("duplicate checksum for %s", binary.Name)
				}
				raw, ok = fields[0], true
			}
		}
	}
	sum, err := hex.DecodeString(raw)
	if !ok || err != nil || len(sum) != sha256.Size {
		return nil, fmt.Errorf("no valid upstream SHA-256 for %s; install this release manually after verifying it", binary.Name)
	}
	return sum, nil
}

func installAsset(client *http.Client, dir string, binary asset, want []byte) (string, error) {
	// Write beside the destination so the final rename stays on one volume.
	tmp, err := os.CreateTemp(dir, "sops-download-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := binary.Download(context.Background(), client, tmp, want); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return "", err
	}

	dest := filepath.Join(dir, exeName())
	if err := os.Rename(tmpName, dest); err != nil {
		return "", fmt.Errorf("could not replace %s with the verified download: %w", dest, err)
	}

	return dest, nil
}
