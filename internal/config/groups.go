package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"filippo.io/age"
	"go.yaml.in/yaml/v3"
)

const GroupMarker = "# Managed by git-sops (recipient groups v1)"
const DefaultGroup = "default"

var groupName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func ValidateGroup(name string, keys []string) error {
	if !groupName.MatchString(name) {
		return fmt.Errorf("invalid group name %q (use lowercase letters, digits, underscores or hyphens)", name)
	}
	if len(keys) == 0 {
		return fmt.Errorf("group %q needs at least one recipient", name)
	}
	for _, key := range keys {
		if parsed, err := age.ParseX25519Recipient(key); err != nil || parsed.String() != key {
			return fmt.Errorf("group %q needs valid public age recipients", name)
		}
	}
	return nil
}

func (m *Managed) GroupNames() []string { return slices.Sorted(maps.Keys(m.Groups)) }

func (m *Managed) GroupForRule(path string) string {
	if group := m.Assignments[strings.TrimSuffix(path, "/")]; group != "" {
		return group
	}
	return DefaultGroup
}

// Use the same precedence as the generated SOPS policy, including its stable
// declaration order for equally specific patterns.
func (m *Managed) RuleFor(path string) string {
	var best string
	for _, rule := range m.ProtectedPaths {
		if rule == path && !strings.Contains(rule, "*") {
			return rule
		}
		match := strings.HasSuffix(rule, "/") && strings.HasPrefix(path, rule)
		if strings.Contains(rule, "*") {
			match = globMatches(rule, path)
		}
		if match && (best == "" || rulePrecedes(rule, best)) {
			best = rule
		}
	}
	return best
}

func rulePrecedes(a, b string) bool {
	aGlob, bGlob := strings.Contains(a, "*"), strings.Contains(b, "*")
	if aGlob != bGlob {
		return !aGlob
	}
	if aGlob {
		dirA, nameA := path.Split(a)
		dirB, nameB := path.Split(b)
		prefixA, recursiveA := strings.CutSuffix(dirA, "**/")
		prefixB, recursiveB := strings.CutSuffix(dirB, "**/")
		if len(prefixA) != len(prefixB) {
			return len(prefixA) > len(prefixB)
		}
		if recursiveA != recursiveB {
			return !recursiveA
		}
		return len(nameA)-strings.Count(nameA, "*") > len(nameB)-strings.Count(nameB, "*")
	}
	return len(strings.TrimSuffix(a, "/")) > len(strings.TrimSuffix(b, "/"))
}

func (m *Managed) KeysFor(path string) []string {
	rule := m.RuleFor(path)
	if rule == "" {
		return nil
	}
	return m.KeysForRule(rule)
}

func (m *Managed) KeysForRule(rule string) []string {
	if m.Groups == nil {
		return m.Recipients
	}
	return m.Groups[m.GroupForRule(rule)]
}

// SOPS selects the first match. Children must precede their enclosing directories.
func orderedSpecs(in []Spec) []Spec {
	out := slices.Clone(in)
	sort.SliceStable(out, func(i, j int) bool { return rulePrecedes(out[i].RelativePath, out[j].RelativePath) })
	return out
}

func parseGroupPolicy(data []byte, lines []string) (*Managed, error) {
	var doc struct {
		Groups map[string]yaml.Node `yaml:"recipient_groups"`
		Rules  []struct {
			Regex string    `yaml:"path_regex"`
			Age   yaml.Node `yaml:"age"`
		} `yaml:"creation_rules"`
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid recipient group policy: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("expected one SOPS policy document")
	}
	m := &Managed{Groups: map[string][]string{}, Assignments: map[string]string{}}
	for name, node := range doc.Groups {
		var keys []string
		if node.Kind != yaml.SequenceNode || node.Anchor != name || node.Decode(&keys) != nil {
			return nil, fmt.Errorf("group %q must be a recipient list anchored with its name", name)
		}
		if err := ValidateGroup(name, keys); err != nil {
			return nil, err
		}
		m.Groups[name] = UniqueRecipients(keys)
	}
	m.Recipients = m.Groups[DefaultGroup]
	if len(m.Recipients) == 0 {
		return nil, errors.New("missing default recipient group")
	}
	byRegex := map[string]string{}
	for _, line := range lines {
		if match := protectedLine.FindStringSubmatch(line); match != nil {
			path := match[1]
			rel, err := NormalizePath(path)
			if err != nil || rel != strings.TrimSuffix(path, "/") {
				return nil, fmt.Errorf("invalid protected path %q", path)
			}
			pattern := "^" + pathToRegex(rel, strings.HasSuffix(path, "/")) + "$"
			if _, duplicate := byRegex[pattern]; duplicate {
				return nil, fmt.Errorf("duplicate protected path %q", path)
			}
			byRegex[pattern] = path
		}
	}
	for _, rule := range doc.Rules {
		path, ok := byRegex[rule.Regex]
		group := rule.Age.Value
		if !ok || rule.Age.Kind != yaml.AliasNode || m.Groups[group] == nil || rule.Age.Alias.Line != doc.Groups[group].Line {
			return nil, fmt.Errorf("invalid protected path or group in rule %q", rule.Regex)
		}
		for _, prior := range m.ProtectedPaths {
			if strings.Contains(prior, "*") {
				if rulePrecedes(path, prior) {
					return nil, fmt.Errorf("place %q before pattern %q", path, prior)
				}
			} else if strings.TrimSuffix(prior, "/") == strings.TrimSuffix(path, "/") ||
				(!strings.Contains(path, "*") && strings.HasSuffix(prior, "/") && strings.HasPrefix(path, prior)) {
				return nil, fmt.Errorf("place %q before overlapping rule %q", path, prior)
			}
		}
		m.ProtectedPaths = append(m.ProtectedPaths, path)
		m.Assignments[strings.TrimSuffix(path, "/")] = group
		delete(byRegex, rule.Regex)
	}
	if len(byRegex) != 0 {
		return nil, errors.New("protected paths are missing creation rules")
	}
	return m, nil
}
