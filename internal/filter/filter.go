// Package filter implements the Git clean/smudge filters and the pre-commit index validator.
package filter

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/lalibi/git-sops/internal/agekey"
	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/sopsx"
)

// Locked reports paths intentionally excluded from the local identity's groups.
func Locked(s *sopsx.Client, path string, blob []byte) (bool, error) {
	m, err := config.ReadManaged(filepath.Join(s.Dir, ".sops.yaml"))
	if err != nil || m == nil || m.Groups == nil {
		return false, err
	}
	keys, err := sopsx.CipherRecipients(path, blob)
	if err != nil {
		return false, err
	}
	local, err := agekey.LocalRecipients()
	if err != nil {
		return false, err
	}
	for _, k := range local {
		if slices.Contains(keys, k) {
			return false, nil
		}
	}
	return true, nil
}

// Smudge decrypts repository ciphertext into the working-tree plaintext.
func Smudge(s *sopsx.Client, path string, input []byte) ([]byte, error) {
	out, err := s.Decrypt(path, input)
	if err != nil {
		// A merge conflict leaves plaintext with conflict markers; real ciphertext must still fail loudly.
		if !s.IsEncrypted(path, input) {
			return input, nil
		}
		if locked, policyErr := Locked(s, path, input); policyErr != nil {
			return nil, policyErr
		} else if locked {
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
		indexBlob = blob
		// Decrypting tells ciphertext apart from plaintext that was committed
		// before protection was enabled; both look identical to Git.
		if plain, err := s.Decrypt(path, blob); err == nil {
			current, haveCurrent = plain, true

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

	if !haveCurrent {
		// A fresh index entry can contain a locked blob (for example after
		// removing and re-adding it). Preserve its envelope only for the same audience.
		policy, err := config.ReadManaged(filepath.Join(s.Dir, ".sops.yaml"))
		if err != nil {
			return nil, err
		}
		if policy != nil && policy.Groups != nil {
			if indexBlob != nil && s.IsEncrypted(path, indexBlob) {
				if bytes.Equal(input, indexBlob) {
					return indexBlob, nil
				}
				return nil, fmt.Errorf("cannot replace encrypted %q without decrypting its staged version", path)
			}
			if s.IsEncrypted(path, input) {
				if err := sopsx.CheckRecipients(path, input, policy.KeysFor(filepath.ToSlash(path))); err != nil {
					return nil, fmt.Errorf("%q: %w", path, err)
				}
				return input, nil
			}
		}
	}
	out, err := s.Encrypt(path, input)
	if err != nil {
		return nil, fmt.Errorf("SOPS encrypt failed for '%s': %w", path, err)
	}

	// Structured formats are re-serialized by SOPS, so plaintext that differs only in
	// formatting must still map to the existing ciphertext.
	if haveCurrent && sopsx.TypesFor(path).Plain != "binary" {
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
	attrs, err := g.FilterAttributes(files, true)
	if err != nil {
		return 0, nil, err
	}
	var policy *config.Managed
	if _, tracked := attrs[".sops.yaml"]; tracked {
		data, err := g.Run(nil, "cat-file", "blob", ":.sops.yaml")
		if err != nil {
			return 0, nil, err
		}
		policy, err = config.ParseManaged(data)
		if err != nil {
			return 0, nil, err
		}
		// The PowerShell generator could omit the directory's trailing slash.
		// Resolve those directories against this index, also in bare CI mirrors.
		if policy != nil && bytes.HasPrefix(data, []byte(config.LegacySopsMarker)) {
			dirs := make(map[string]bool)
			for _, path := range files {
				for parent := filepath.ToSlash(filepath.Dir(path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
					dirs[parent] = true
				}
			}
			for i, path := range policy.ProtectedPaths {
				if dirs[path] {
					policy.ProtectedPaths[i] += "/"
				}
			}
		}
	}
	for _, path := range files {
		if attrs[path] != "sops" {
			if policy != nil && policy.RuleFor(path) != "" {
				return checked, failures, fmt.Errorf("attributes do not protect %q in the index as required by the staged .sops.yaml", path)
			}
			continue
		}
		checked++
		blob, err := g.Run(nil, "cat-file", "blob", ":"+path)
		if err != nil || !s.IsEncrypted(path, blob) {
			failures = append(failures, path)
		} else if policy != nil && policy.Groups != nil {
			if err := sopsx.CheckRecipients(path, blob, policy.KeysFor(path)); err != nil {
				return checked, failures, fmt.Errorf("%q: %w", path, err)
			}
		}
	}
	return checked, failures, nil
}
