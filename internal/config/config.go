// Package config generates and reads the managed .gitattributes block and .sops.yaml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SopsMarker       = "# Managed by git-sops"
	LegacySopsMarker = "# Managed by Initialize-SopsGit.ps1"
	AttributesBegin  = "# BEGIN SOPS TRANSPARENT ENCRYPTION"
	AttributesEnd    = "# END SOPS TRANSPARENT ENCRYPTION"
)

var (
	recipientPattern = regexp.MustCompile(`^age1[0-9a-z]+$`)
	recipientLine    = regexp.MustCompile(`^\s*-\s+(age1[0-9a-z]+)\s*$`)
	protectedLine    = regexp.MustCompile(`^#\s*protected-path:\s*(.+)$`)
	globChars        = regexp.MustCompile(`[*?\[]`)
	dotDot           = regexp.MustCompile(`(^|/)\.\.($|/)`)
)

type Spec struct {
	RelativePath     string
	IsDirectory      bool
	AttributePattern string
	RegexPart        string
}

func IsRecipient(s string) bool { return recipientPattern.MatchString(s) }

func NormalizePath(p string) (string, error) {
	if strings.ContainsAny(p, "\r\n\x00") || strings.Contains(p, ":") || strings.HasPrefix(p, `\\`) {
		return "", fmt.Errorf("invalid repository-relative path %q", p)
	}
	n := strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	n = strings.Trim(n, "/")

	if n == "" {
		return "", fmt.Errorf("invalid protected path %q", p)
	}
	if dotDot.MatchString(n) || globChars.MatchString(n) {
		return "", fmt.Errorf("protected paths accept exact files or directories only, not '..' or glob patterns: %q", p)
	}
	n = path.Clean(n)
	if n == "." {
		return "", errors.New("the repository root cannot be protected; select its files or subdirectories")
	}
	return n, nil
}

func pathToRegex(path string, isDir bool) string {
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = regexp.QuoteMeta(s)
	}

	joined := strings.Join(segments, `[\\/]`)
	if isDir {
		return joined + `[\\/].*`
	}
	return joined
}

func BuildSpecs(root string, paths []string) ([]Spec, error) {
	specs := make([]Spec, 0, len(paths))

	for _, raw := range paths {
		rel, err := NormalizePath(raw)
		if err != nil {
			return nil, err
		}
		for _, part := range strings.Split(rel, "/") {
			if strings.EqualFold(part, ".git") {
				return nil, fmt.Errorf("Git metadata cannot be protected: %q", raw)
			}
		}
		if filepath.Base(rel) == ".gitattributes" || rel == ".sops.yaml" {
			return nil, fmt.Errorf("encryption configuration must remain plaintext: %q", raw)
		}

		isDir := strings.HasSuffix(raw, "/") || strings.HasSuffix(raw, `\`)
		if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err == nil && st.IsDir() {
			isDir = true
		}

		pattern := "/" + rel
		if isDir {
			pattern = "/" + rel + "/**"
		}
		// Git attributes require C-style quoting for spaces and special characters.
		if strings.ContainsAny(pattern, " \t\"\\") {
			pattern = strconv.Quote(pattern)
		}

		specs = append(specs, Spec{
			RelativePath:     rel,
			IsDirectory:      isDir,
			AttributePattern: pattern,
			RegexPart:        pathToRegex(rel, isDir),
		})
	}

	return specs, nil
}

func Matches(s Spec, path string) bool {
	return path == s.RelativePath && !s.IsDirectory || s.IsDirectory && strings.HasPrefix(path, s.RelativePath+"/")
}

func Protected(specs []Spec, path string) bool {
	for _, s := range specs {
		if Matches(s, path) {
			return true
		}
	}
	return false
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

func writeLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

var (
	gitCryptFilter = regexp.MustCompile(`filter=git-crypt(?:-\S+)?`)
	gitCryptDiff   = regexp.MustCompile(`\s+diff=git-crypt(?:-\S+)?`)
	hasNoText      = regexp.MustCompile(`(^|\s)-text(\s|$)`)
)

// UpdateAttributes rewrites the managed block in .gitattributes, leaving other lines untouched.
func UpdateAttributes(root string, specs []Spec, migrateGitCrypt bool) error {
	path := filepath.Join(root, ".gitattributes")
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, err := RenderAttributes(data, specs, migrateGitCrypt)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// RenderAttributes preserves unmanaged attributes while replacing the managed block.
func RenderAttributes(data []byte, specs []Spec, migrateGitCrypt bool) ([]byte, error) {
	var lines []string
	text := strings.TrimSuffix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if text != "" {
		lines = strings.Split(text, "\n")
	}

	if migrateGitCrypt {
		for i, line := range lines {
			if !gitCryptFilter.MatchString(line) {
				continue
			}
			line = gitCryptFilter.ReplaceAllString(line, "filter=sops merge=sops")
			line = gitCryptDiff.ReplaceAllString(line, " diff=sops")
			if !hasNoText.MatchString(line) {
				line += " -text"
			}
			lines[i] = line
		}
	}

	begin, end := -1, -1
	for i, line := range lines {
		switch {
		case line == AttributesBegin && begin < 0:
			begin = i
		case line == AttributesEnd && end < 0:
			end = i
		}
	}

	if (begin >= 0) != (end >= 0) || (begin >= 0 && end < begin) {
		return nil, errors.New("the managed .gitattributes block is malformed")
	}

	block := []string{AttributesBegin}
	for _, s := range specs {
		block = append(block, s.AttributePattern+" filter=sops diff=sops merge=sops -text")
	}
	block = append(block, AttributesEnd)

	var out []string
	if begin >= 0 {
		out = append(out, lines[:begin]...)
		out = append(out, block...)
		out = append(out, lines[end+1:]...)
	} else {
		out = append(out, lines...)
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
		out = append(out, block...)
	}

	return []byte(strings.Join(out, "\n") + "\n"), nil
}

type Managed struct {
	ProtectedPaths []string
	Recipients     []string
}

// ReadManaged returns the data of a generated .sops.yaml, or nil when the file is absent or hand-written.
func ReadManaged(path string) (*Managed, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 || (lines[0] != SopsMarker && lines[0] != LegacySopsMarker) {
		return nil, nil
	}

	m := &Managed{}
	for _, line := range lines {
		if g := protectedLine.FindStringSubmatch(line); g != nil {
			m.ProtectedPaths = append(m.ProtectedPaths, strings.TrimSpace(g[1]))
		} else if g := recipientLine.FindStringSubmatch(line); g != nil {
			m.Recipients = append(m.Recipients, g[1])
		}
	}
	return m, nil
}

// WriteSopsConfig writes the managed .sops.yaml. A hand-written file is only replaced with force, after a backup.
func WriteSopsConfig(root string, specs []Spec, recipients []string, force bool, warnf func(string, ...any)) error {
	path := filepath.Join(root, ".sops.yaml")

	if _, err := os.Stat(path); err == nil {
		managed, err := ReadManaged(path)
		if err != nil {
			return err
		}

		if managed == nil {
			if !force {
				return errors.New(".sops.yaml already exists and was not generated by git-sops; merge the creation_rules manually or rerun with --force after taking a backup")
			}

			backup := path + ".bak." + time.Now().Format("20060102150405")
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.WriteFile(backup, data, 0o644); err != nil {
				return err
			}
			warnf("Backed up the existing .sops.yaml to '%s'.", backup)
		}
	}

	parts := make([]string, len(specs))
	for i, s := range specs {
		parts[i] = s.RegexPart
	}

	lines := []string{SopsMarker}
	for _, s := range specs {
		comment := s.RelativePath
		if s.IsDirectory {
			comment += "/"
		}
		lines = append(lines, "# protected-path: "+comment)
	}
	lines = append(lines,
		"creation_rules:",
		"  - path_regex: '^(?:"+strings.ReplaceAll(strings.Join(parts, "|"), "'", "''")+")$'",
		"    age:")
	for _, r := range UniqueRecipients(recipients) {
		lines = append(lines, "      - "+r)
	}

	return writeLines(path, lines)
}

// UniqueRecipients drops invalid entries and duplicates, returning a sorted list.
func UniqueRecipients(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		if IsRecipient(r) && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}
