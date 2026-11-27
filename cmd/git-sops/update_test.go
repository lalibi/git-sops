package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lalibi/git-sops/internal/ghrelease"
)

func updateArchive(t *testing.T, zipFormat bool, entry string) []byte {
	t.Helper()
	const contents = "new executable"
	var buf bytes.Buffer
	if zipFormat {
		zw := zip.NewWriter(&buf)
		f, err := zw.Create(entry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, contents); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: entry, Mode: 0755, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, contents); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestExtractUpdate(t *testing.T) {
	for _, binary := range []string{"git-sops", "git-sops.exe"} {
		for _, entry := range []string{binary, "../" + binary, "README.md"} {
			data := updateArchive(t, strings.HasSuffix(binary, ".exe"), entry)
			var got bytes.Buffer
			err := extractUpdate(data, binary, &got)
			if entry == binary {
				if err != nil || got.String() != "new executable" {
					t.Fatalf("extract %s: %q, %v", entry, got.String(), err)
				}
			} else if err == nil || got.Len() != 0 {
				t.Fatalf("accepted unexpected archive entry %s", entry)
			}
		}
	}
}

func TestInstallUpdateLeavesOriginalOnFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "portable git-sops")
	write(t, target, "original")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := installUpdate(target, info, "git-sops", []byte("bad archive")); err == nil {
		t.Fatal("accepted an unreadable archive")
	}
	if runtime.GOOS == "windows" {
		backup := target + ".git-sops-old"
		write(t, backup, "unrelated file")
		if err := installUpdate(target, info, "git-sops.exe", updateArchive(t, true, "git-sops.exe")); err == nil {
			t.Fatal("overwrote an unrelated backup file")
		}
		if read(t, backup) != "unrelated file" {
			t.Fatal("backup changed during a failed update")
		}
	}
	if read(t, target) != "original" {
		t.Fatal("failed update altered the installed file")
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(target), ".git-sops-update-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("checking temporary downloads: %v, %v", leftovers, err)
	}
}

type updateTransport func(*http.Request) (*http.Response, error)

func (f updateTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestUpdateExecutable(t *testing.T) {
	const latest = "v0.10.0"
	entry, ext := "git-sops", ".tar.gz"
	if runtime.GOOS == "windows" {
		entry, ext = "git-sops.exe", ".zip"
	}
	archive := updateArchive(t, runtime.GOOS == "windows", entry)
	name := "git-sops_0.10.0_" + runtime.GOOS + "_" + runtime.GOARCH + ext
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(archive))

	for _, tc := range []struct {
		name, current, asset, digest string
		download, success, changed   bool
	}{
		{"upgrade", "v0.9.9", name, digest, true, true, true},
		{"upgrade prerelease", "v0.10.0-rc.1", name, digest, true, true, true},
		{"unversioned build", "(devel)", name, digest, true, true, true},
		{"current", latest, name, digest, false, true, false},
		{"newer", "v1.0.0", name, digest, false, true, false},
		{"missing platform", "v0.9.9", "other.zip", digest, false, false, false},
		{"missing digest", "v0.9.9", name, "", false, false, false},
		{"corrupt download", "v0.9.9", name, "sha256:" + strings.Repeat("0", 64), true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "custom name"+filepath.Ext(entry))
			if err := os.WriteFile(target, []byte("old executable"), 0750); err != nil {
				t.Fatal(err)
			}
			path := target
			if runtime.GOOS != "windows" {
				path = filepath.Join(t.TempDir(), "symlink")
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			downloaded := false
			client := &http.Client{Transport: updateTransport(func(req *http.Request) (*http.Response, error) {
				var body []byte
				switch req.URL.String() {
				case "https://api.github.com/repos/lalibi/git-sops/releases/latest":
					body, _ = json.Marshal(ghrelease.Release{Tag: latest, Assets: []ghrelease.Asset{{
						Name: tc.asset, URL: "https://example.test/archive", Size: int64(len(archive)), Digest: tc.digest,
					}}})
				case "https://example.test/archive":
					downloaded, body = true, archive
				default:
					return nil, fmt.Errorf("unexpected request %s", req.URL)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			err := updateExecutable(t.Context(), client, path, tc.current)
			if (err == nil) != tc.success || downloaded != tc.download {
				t.Fatalf("downloaded %v, error %v", downloaded, err)
			}
			want := "old executable"
			if tc.changed {
				want = "new executable"
			}
			if got := read(t, target); got != want {
				t.Fatalf("installed %q, want %q", got, want)
			}
			if path != target {
				if _, err := os.Readlink(path); err != nil {
					t.Fatalf("update replaced the symlink: %v", err)
				}
			}
		})
	}
}
