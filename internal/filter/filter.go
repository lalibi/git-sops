// Package filter implements the Git clean/smudge filters and the pre-commit index validator.
package filter

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/sopsx"
)

// Smudge decrypts repository ciphertext into the working-tree plaintext.
func Smudge(s *sopsx.Client, path string, input []byte) ([]byte, error) {
	out, err := s.Decrypt(path, input)
	if err != nil {
		// A merge conflict leaves plaintext with conflict markers; real ciphertext must still fail loudly.
		if !s.IsEncrypted(path, input) {
			return input, nil
		}
		return nil, fmt.Errorf("SOPS decrypt failed for '%s': %w", path, err)
	}
	return out, nil
}

// Clean turns working-tree plaintext into repository ciphertext.
func Clean(g *gitx.Git, s *sopsx.Client, path string, input []byte) ([]byte, error) {
	var indexBlob, current []byte
	haveCurrent := false

	if blob, err := g.Run(nil, "cat-file", "blob", ":"+path); err == nil {
		// Decrypting tells ciphertext apart from plaintext that was committed
		// before protection was enabled; both look identical to Git.
		if plain, err := s.Decrypt(path, blob); err == nil {
			indexBlob, current, haveCurrent = blob, plain, true

			// Git fed the existing ciphertext back through clean.
			if bytes.Equal(input, indexBlob) {
				return indexBlob, nil
			}

			// SOPS output is randomized; reusing the ciphertext for unchanged
			// plaintext keeps `git add` from reporting a change every time.
			if bytes.Equal(input, current) {
				return indexBlob, nil
			}
		}
	}

	out, err := s.Encrypt(path, input)
	if err != nil {
		return nil, fmt.Errorf("SOPS encrypt failed for '%s': %w", path, err)
	}

	// Structured formats are re-serialized by SOPS, so plaintext that differs only in
	// formatting must still map to the existing ciphertext.
	if haveCurrent {
		if canonical, err := s.Decrypt(path, out); err == nil && bytes.Equal(canonical, current) {
			return indexBlob, nil
		}
	}

	return out, nil
}

// VerifyIndex checks every tracked file carrying filter=sops and returns how many it checked
// plus those whose index blob is not SOPS ciphertext.
func VerifyIndex(g *gitx.Git, s *sopsx.Client) (checked int, failures []string, err error) {
	files, err := g.ZList("ls-files", "-z")
	if err != nil {
		return 0, nil, err
	}
	if len(files) == 0 {
		return 0, nil, nil
	}

	// Attributes are read from the index so a staged .gitattributes change cannot weaken validation.
	protected, err := protectedFromIndex(g, files)
	if err != nil {
		return 0, nil, err
	}

	for _, path := range protected {
		blob, err := g.Run(nil, "cat-file", "blob", ":"+path)
		if err != nil || !s.IsEncrypted(path, blob) {
			failures = append(failures, path)
		}
	}
	return len(protected), failures, nil
}

func protectedFromIndex(g *gitx.Git, files []string) ([]string, error) {
	input := strings.Join(files, "\x00") + "\x00"

	out, err := g.Run([]byte(input), "check-attr", "--cached", "-z", "--stdin", "filter")
	if err != nil {
		return nil, err
	}

	// Output is a repeating triple: path, attribute, value.
	fields := strings.Split(string(out), "\x00")
	var protected []string
	for i := 0; i+2 < len(fields); i += 3 {
		if fields[i+2] == "sops" {
			protected = append(protected, fields[i])
		}
	}
	return protected, nil
}
