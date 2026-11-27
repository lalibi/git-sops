// Package config generates and reads the managed .gitattributes block and .sops.yaml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/lalibi/git-sops/internal/worktree"
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
	if dotDot.MatchString(n) || strings.ContainsAny(n, "?[") {
		return "", fmt.Errorf("protected paths cannot contain '..', '?' or '[': %q", p)
	}
	n = path.Clean(n)
	if n == "." {
		return "", errors.New("the repository root cannot be protected; select its files or subdirectories")
	}
	if strings.Contains(n, "*") {
		dir, base := path.Split(n)
		prefix, recursive := strings.CutSuffix(dir, "**/")
		if strings.Contains(prefix, "*") || (recursive && prefix != "" && !strings.HasSuffix(prefix, "/")) ||
			strings.Contains(base, "**") || strings.HasSuffix(p, "/") || strings.HasSuffix(p, `\`) {
			return "", fmt.Errorf("use '*' in a filename and an optional '**/' directory before it: %q", p)
		}
		if match, _ := path.Match(strings.ToLower(base), ".gitattributes"); match || globMatches(strings.ToLower(n), ".sops.yaml") {
			return "", fmt.Errorf("encryption configuration must remain plaintext: %q", p)
		}
	}
	return n, nil
}

// A file glob has a literal directory prefix, optionally ending in **/.
func globMatches(pattern, file string) bool {
	dir, base := path.Split(pattern)
	prefix, recursive := strings.CutSuffix(dir, "**/")
	rest, ok := strings.CutPrefix(file, prefix)
	if !ok || (!recursive && strings.Contains(rest, "/")) || rest == "" || strings.HasSuffix(rest, "/") {
		return false
	}
	matched, _ := path.Match(base, path.Base(rest))
	return matched
}

func pathToRegex(path string, isDir bool) string {
	segments := strings.Split(path, "/")
	var pattern strings.Builder
	for i, s := range segments {
		if s == "**" {
			pattern.WriteString(`([^\\/]+[\\/])*`)
			continue
		}
		pattern.WriteString(strings.ReplaceAll(regexp.QuoteMeta(s), `\*`, `[^\\/]*`))
		if i < len(segments)-1 {
			pattern.WriteString(`[\\/]`)
		}
	}
	if isDir {
		pattern.WriteString(`[\\/].*`)
	}
	return pattern.String()
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
				return nil, fmt.Errorf("cannot protect Git metadata: %q", raw)
			}
		}
		if filepath.Base(rel) == ".gitattributes" || rel == ".sops.yaml" {
			return nil, fmt.Errorf("encryption configuration must remain plaintext: %q", raw)
		}

		isDir := strings.HasSuffix(raw, "/") || strings.HasSuffix(raw, `\`)
		if !strings.Contains(rel, "*") {
			if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err == nil && st.IsDir() {
				isDir = true
			}
		}

		specs = append(specs, Spec{
			RelativePath:     rel,
			IsDirectory:      isDir,
			AttributePattern: AttributePattern(rel, isDir),
			RegexPart:        pathToRegex(rel, isDir),
		})
	}

	return specs, nil
}

func AttributePattern(rel string, isDir bool) string {
	pattern := "/" + rel
	if isDir {
		pattern += "/**"
	}
	if strings.ContainsAny(pattern, " \t\"\\") {
		return strconv.Quote(pattern)
	}
	return pattern
}

func Matches(s Spec, path string) bool {
	if s.IsGlob() {
		return globMatches(s.RelativePath, path)
	}
	return path == s.RelativePath && !s.IsDirectory || s.IsDirectory && strings.HasPrefix(path, s.RelativePath+"/")
}

func (s Spec) IsGlob() bool { return strings.Contains(s.RelativePath, "*") }

func Protected(specs []Spec, path string) bool {
	for _, s := range specs {
		if Matches(s, path) {
			return true
		}
	}
	return false
}

func writeLines(path string, lines []string) error {
	return worktree.WriteFile(filepath.Dir(path), filepath.Base(path), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

var (
	gitCryptFilter = regexp.MustCompile(`filter=git-crypt(?:-\S+)?`)
	gitCryptDiff   = regexp.MustCompile(`\s+diff=git-crypt(?:-\S+)?`)
	hasNoText      = regexp.MustCompile(`(^|\s)-text(\s|$)`)
)

// UpdateAttributes rewrites the managed block in .gitattributes, leaving other lines untouched.
func UpdateAttributes(root string, specs []Spec, migrateGitCrypt bool) error {
	data, err := worktree.ReadFile(root, ".gitattributes")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, err := RenderAttributes(data, specs, migrateGitCrypt)
	if err != nil {
		return err
	}
	return worktree.WriteFile(root, ".gitattributes", out, 0o644)
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

	before := lines
	if begin >= 0 {
		before = lines[:begin]
	}
	var rules []string
	for _, s := range specs {
		if !coveredByAttributes(before, s) {
			rules = append(rules, s.AttributePattern+" filter=sops diff=sops merge=sops -text")
		}
	}

	out := append([]string(nil), before...)
	// Retain the insertion point when later rules have higher precedence.
	if len(rules) > 0 || (end >= 0 && end+1 < len(lines)) {
		if begin < 0 && len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
		out = append(out, AttributesBegin)
		out = append(out, rules...)
		out = append(out, AttributesEnd)
	} else if begin > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	if end >= 0 {
		out = append(out, lines[end+1:]...)
	}

	return []byte(strings.Join(out, "\n") + "\n"), nil
}

type Managed struct {
	ProtectedPaths []string
	Recipients     []string
	RecipientNames map[string]string
	Groups         map[string][]string
	Assignments    map[string]string
}

func ValidateRecipientName(name string) error {
	if strings.TrimSpace(name) == "" || strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) != -1 {
		return errors.New("recipient name must be nonempty, printable text on one line")
	}
	return nil
}

func (m *Managed) SetRecipientName(key, name string) {
	if m.RecipientNames == nil {
		m.RecipientNames = map[string]string{}
	}
	m.RecipientNames[key] = name
}

// ReadManaged returns the data of a generated .sops.yaml, or nil when the file is absent or hand-written.
func ReadManaged(path string) (*Managed, error) {
	data, err := worktree.ReadFile(filepath.Dir(path), filepath.Base(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseManaged(data)
}

// ParseManaged reads git-sops metadata only from policies bearing a generated header.
func ParseManaged(data []byte) (*Managed, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	m := &Managed{}
	switch lines[0] {
	case GroupMarker:
		var err error
		m, err = parseGroupPolicy(data, lines)
		if err != nil {
			return nil, err
		}
	case SopsMarker, LegacySopsMarker:
		for _, line := range lines {
			if g := protectedLine.FindStringSubmatch(line); g != nil {
				m.ProtectedPaths = append(m.ProtectedPaths, strings.TrimSpace(g[1]))
			} else if g := recipientLine.FindStringSubmatch(line); g != nil {
				m.Recipients = append(m.Recipients, g[1])
			}
		}
	default:
		return nil, nil
	}
	for _, line := range lines {
		value, ok := strings.CutPrefix(line, "# recipient-name: ")
		if !ok {
			continue
		}
		key, name, ok := strings.Cut(value, " ")
		if !ok || !IsRecipient(key) || ValidateRecipientName(name) != nil || m.RecipientNames[key] != "" {
			return nil, errors.New("invalid or duplicate recipient-name comment")
		}
		m.SetRecipientName(key, strings.TrimSpace(name))
	}
	return m, nil
}

// WriteSopsConfig writes the managed .sops.yaml. A hand-written file is only replaced with force, after a backup.
func WriteSopsConfig(root string, specs []Spec, recipients []string, force bool, warnf func(string, ...any)) error {
	return WriteManagedConfig(root, specs, &Managed{Recipients: recipients}, force, warnf)
}

func WriteManagedConfig(root string, specs []Spec, m *Managed, force bool, warnf func(string, ...any)) error {
	path := filepath.Join(root, ".sops.yaml")
	names := m.RecipientNames

	if _, err := os.Lstat(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err == nil {
		managed, err := ReadManaged(path)
		if err != nil {
			return err
		}

		if managed != nil && managed.Groups != nil && m.Groups == nil {
			return errors.New("cannot replace a recipient group policy with a repository-wide recipient list")
		}
		if managed != nil && names == nil {
			names = managed.RecipientNames
		}
		if managed == nil {
			if !force {
				return errors.New(".sops.yaml already exists and was not generated by git-sops; merge the creation_rules manually or rerun with --force after taking a backup")
			}

			data, err := worktree.ReadFile(root, ".sops.yaml")
			if err != nil {
				return err
			}
			backup, err := os.CreateTemp(root, ".sops.yaml.bak.*")
			if err != nil {
				return err
			}
			_, err = backup.Write(data)
			if err := errors.Join(err, backup.Close()); err != nil {
				return err
			}
			warnf("Backed up the existing .sops.yaml to '%s'.", backup.Name())
		}
	}

	marker := SopsMarker
	if m.Groups != nil {
		marker = GroupMarker
		specs = orderedSpecs(specs)
	}
	lines := []string{marker}
	// Keep names separate from the bare age entries read by older versions.
	keys := slices.Clone(m.Recipients)
	for _, members := range m.Groups {
		keys = append(keys, members...)
	}
	for _, key := range UniqueRecipients(keys) {
		if name, ok := names[key]; ok {
			if err := ValidateRecipientName(name); err != nil {
				return err
			}
			lines = append(lines, "# recipient-name: "+key+" "+name)
		}
	}
	for _, s := range specs {
		comment := s.RelativePath
		if s.IsDirectory {
			comment += "/"
		}
		lines = append(lines, "# protected-path: "+comment)
	}
	if m.Groups == nil {
		lines = append(lines, "", "recipients: &recipients")
		for _, r := range UniqueRecipients(m.Recipients) {
			lines = append(lines, "  - "+r)
		}
	} else {
		lines = append(lines, "", "recipient_groups:")
		for _, group := range m.GroupNames() {
			lines = append(lines, "  "+group+": &"+group)
			for _, r := range m.Groups[group] {
				lines = append(lines, "    - "+r)
			}
		}
	}
	if len(specs) == 0 {
		return writeLines(path, append(lines, "", "creation_rules: []"))
	}
	lines = append(lines, "", "creation_rules:")
	for i, s := range specs {
		if i > 0 {
			lines = append(lines, "")
		}
		alias := "recipients"
		if m.Groups != nil {
			alias = m.GroupForRule(s.RelativePath)
		}
		lines = append(lines, "  - path_regex: '^"+strings.ReplaceAll(s.RegexPart, "'", "''")+"$'", "    age: *"+alias)
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
