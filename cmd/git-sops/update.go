package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/lalibi/git-sops/internal/ghrelease"
	"github.com/lalibi/git-sops/internal/ui"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
)

const releaseRepo = "lalibi/git-sops"
const maxUpdateSize = 64 << 20

func newUpdateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update this git-sops executable to the latest stable GitHub release",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			current := "v" + strings.TrimPrefix(version, "v")
			if version == "dev" {
				// go install @version embeds the module version without our release ldflags.
				if info, ok := debug.ReadBuildInfo(); ok {
					current = info.Main.Version
				}
			}
			return updateExecutable(cmd.Context(), &http.Client{Timeout: 5 * time.Minute}, exe, current)
		},
	}
}

func updateExecutable(ctx context.Context, client *http.Client, exe, current string) error {
	target, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	original, err := os.Stat(target)
	if err != nil {
		return err
	}
	release, err := ghrelease.Lookup(ctx, client, releaseRepo, "latest")
	if err != nil {
		return err
	}
	tag := release.Tag
	if release.Draft || release.Prerelease || !semver.IsValid(tag) || semver.Prerelease(tag) != "" {
		return fmt.Errorf("expected a stable git-sops release, got %q", tag)
	}
	if semver.IsValid(current) && semver.Compare(current, tag) >= 0 {
		ui.Okf("No update needed (installed %s, latest release %s).", current, tag)
		return nil
	}

	name := fmt.Sprintf("git-sops_%s_%s_%s", strings.TrimPrefix(tag, "v"), runtime.GOOS, runtime.GOARCH)
	binaryName := "git-sops"
	if runtime.GOOS == "windows" {
		name += ".zip"
		binaryName += ".exe"
	} else {
		name += ".tar.gz"
	}
	for _, asset := range release.Assets {
		if asset.Name != name {
			continue
		}
		raw, ok := strings.CutPrefix(asset.Digest, "sha256:")
		sum, err := hex.DecodeString(raw)
		if !ok || err != nil || len(sum) != sha256.Size {
			return fmt.Errorf("missing valid GitHub SHA-256 for %s", name)
		}
		if asset.Size > maxUpdateSize {
			return fmt.Errorf("release archive %s exceeds %d bytes", name, maxUpdateSize)
		}
		var archive bytes.Buffer
		if err := asset.Download(ctx, client, &archive, sum); err != nil {
			return err
		}
		if err := installUpdate(target, original, binaryName, archive.Bytes()); err != nil {
			return err
		}
		ui.Okf("Updated git-sops to %s at %s", tag, target)
		return nil
	}
	return fmt.Errorf("release %s has no archive %s", tag, name)
}

func installUpdate(target string, original os.FileInfo, binaryName string, archive []byte) error {
	staged, err := os.CreateTemp(filepath.Dir(target), ".git-sops-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	err = extractUpdate(archive, binaryName, staged)
	if err == nil {
		err = staged.Chmod(original.Mode().Perm())
	}
	closeErr := staged.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	if !os.SameFile(original, info) {
		return fmt.Errorf("%s changed during the download, rerun update", target)
	}
	if runtime.GOOS != "windows" {
		return os.Rename(staged.Name(), target)
	}
	// Windows permits renaming a running executable but keeps its image
	// locked until exit. Rotate one backup beside the active executable.
	backup := target + ".git-sops-old"
	if _, err := os.Lstat(backup); err == nil {
		old, err := buildinfo.ReadFile(backup)
		if err != nil || old.Path != "github.com/"+releaseRepo+"/cmd/git-sops" {
			return fmt.Errorf("move the existing file %s before updating", backup)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	if err := os.Rename(staged.Name(), target); err != nil {
		if restoreErr := os.Rename(backup, target); restoreErr != nil {
			return fmt.Errorf("install failed (%v), restore %s manually: %w", err, backup, restoreErr)
		}
		return err
	}
	return nil
}

func extractUpdate(data []byte, binaryName string, dest io.Writer) error {
	var src io.Reader
	var size int64
	if strings.HasSuffix(binaryName, ".exe") {
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
		for _, file := range archive.File {
			if file.Name == binaryName && file.Mode().IsRegular() {
				r, err := file.Open()
				if err != nil {
					return err
				}
				defer r.Close()
				src, size = r, int64(file.UncompressedSize64)
				break
			}
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer gz.Close()
		archive := tar.NewReader(io.LimitReader(gz, maxUpdateSize))
		for {
			header, err := archive.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if header.Name == binaryName && header.Typeflag == tar.TypeReg {
				src, size = archive, header.Size
				break
			}
		}
	}
	if src == nil || size <= 0 || size > maxUpdateSize {
		return fmt.Errorf("archive lacks a valid %s executable", binaryName)
	}
	n, err := io.Copy(dest, io.LimitReader(src, size+1))
	if err == nil && n != size {
		return fmt.Errorf("incorrect size for archived executable %s", binaryName)
	}
	return err
}
