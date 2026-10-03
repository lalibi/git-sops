package filter

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/sopsx"
)

// TextConv renders a blob for `git diff`. Content that cannot be decrypted is returned
// unchanged, so a missing key degrades to a ciphertext diff instead of failing.
func TextConv(s *sopsx.Client, path string, input []byte) []byte {
	if plain, err := s.Decrypt(path, input); err == nil {
		return plain
	}
	return input
}

// Merge three-way merges SOPS ciphertext by merging the plaintext and encrypting the result.
// On a clean merge out is ciphertext. On a conflict out is plaintext with conflict markers,
// which Smudge passes through to the working tree.
func Merge(g *gitx.Git, s *sopsx.Client, path string, base, ours, theirs []byte, markerSize string) (out []byte, conflicted bool, err error) {
	basePlain, err := plaintextOf(s, path, "base", base)
	if err != nil {
		return nil, false, err
	}
	oursPlain, err := plaintextOf(s, path, "ours", ours)
	if err != nil {
		return nil, false, err
	}
	theirsPlain, err := plaintextOf(s, path, "theirs", theirs)
	if err != nil {
		return nil, false, err
	}

	dir, err := os.MkdirTemp("", "git-sops-merge-*")
	if err != nil {
		return nil, false, err
	}
	defer os.RemoveAll(dir)

	files := map[string][]byte{"base": basePlain, "ours": oursPlain, "theirs": theirsPlain}
	paths := map[string]string{}
	for name, content := range files {
		paths[name] = filepath.Join(dir, name)
		if err := os.WriteFile(paths[name], content, 0o600); err != nil {
			return nil, false, err
		}
	}

	args := []string{"merge-file", "-p", "-L", "ours", "-L", "base", "-L", "theirs"}
	if markerSize != "" {
		args = append(args, "--marker-size="+markerSize)
	}
	args = append(args, paths["ours"], paths["base"], paths["theirs"])

	merged, runErr := g.Run(nil, args...)
	if runErr != nil {
		var exitErr *gitx.ExitError
		// merge-file exits with the number of conflicts, capped at 127; anything else is a failure.
		if !errors.As(runErr, &exitErr) || exitErr.Code < 1 || exitErr.Code > 127 {
			return nil, false, runErr
		}
		return merged, true, nil
	}

	// Reusing a side's ciphertext avoids new blobs when the merge resolved to one side.
	// A side that was stored as plaintext is never reused.
	switch {
	case len(ours) > 0 && !bytes.Equal(oursPlain, ours) && bytes.Equal(merged, oursPlain):
		return ours, false, nil
	case len(theirs) > 0 && !bytes.Equal(theirsPlain, theirs) && bytes.Equal(merged, theirsPlain):
		return theirs, false, nil
	}

	encrypted, err := s.Encrypt(path, merged)
	if err != nil {
		return nil, false, fmt.Errorf("SOPS encrypt failed for '%s': %w", path, err)
	}
	return encrypted, false, nil
}

// plaintextOf decrypts one side of a merge. Content that is not ciphertext (for example a
// file committed before protection was enabled) is used as is.
func plaintextOf(s *sopsx.Client, path, side string, blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	plain, err := s.Decrypt(path, blob)
	if err == nil {
		return plain, nil
	}
	if !s.IsEncrypted(path, blob) {
		return blob, nil
	}
	return nil, fmt.Errorf("could not decrypt the %s version of '%s': %w", side, path, err)
}
