package config

import (
	"path"
	"slices"
	"strconv"
	"strings"
)

// Omit a generated rule only when a preceding rule supplies all four attributes
// over its entire scope. A later exception or unfamiliar pattern keeps it explicit.
func coveredByAttributes(lines []string, spec Spec) bool {
	target := spec.AttributePattern
	if strings.HasPrefix(target, `"`) {
		target, _ = strconv.Unquote(target) // BuildSpecs quotes paths containing spaces.
	}
	target = strings.TrimPrefix(strings.TrimSuffix(target, "/**"), "/")
	if target == "" {
		return false
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimLeft(lines[i], " \t")
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		possible, covers := attributeScope(fields[0], target, spec.IsDirectory)
		if !possible {
			continue
		}
		if len(fields) != 5 {
			return false
		}
		attrs := fields[1:]
		for _, attr := range []string{"filter=sops", "diff=sops", "merge=sops", "-text"} {
			if !slices.Contains(attrs, attr) {
				return false
			}
		}
		if covers {
			return true
		}
	}
	return false
}

// Recognize literal directory prefixes, recursive directory rules and basename
// wildcards. Uncertainty counts as overlap, never as proof of coverage.
func attributeScope(pattern, target string, directory bool) (possible, covers bool) {
	if strings.ContainsAny(pattern, `"\[]?!`) || strings.Contains(pattern, "//") {
		return true, false
	}
	if strings.Contains(target, "*") {
		// Overlapping globs need an explicit rule unless their scopes agree.
		// Incompatible literal filename suffixes prove the scopes disjoint.
		suffix := func(p string) string {
			base := strings.ToLower(path.Base(p))
			return base[strings.LastIndexByte(base, '*')+1:]
		}
		a, b := suffix(pattern), suffix(target)
		return strings.HasSuffix(a, b) || strings.HasSuffix(b, a),
			pattern == "/"+target || (strings.Contains(target, "/") && pattern == target)
	}
	anchored := strings.HasPrefix(pattern, "/")
	pattern = strings.TrimPrefix(pattern, "/")
	if rest, ok := strings.CutPrefix(pattern, "**/"); ok {
		if strings.Contains(rest, "/") {
			return true, false
		}
		pattern, anchored = rest, false
	}
	prefix, base := path.Split(pattern)
	if strings.Contains(prefix, "*") {
		return true, false
	}
	anywhere := prefix == "" && !anchored
	prefix = strings.TrimSuffix(prefix, "/")
	inside := func(p, dir string) bool {
		return dir == "" || strings.HasPrefix(p, dir+"/")
	}
	match := func(pattern, name string) bool {
		ok, _ := path.Match(pattern, name) // Only literal characters and '*' remain.
		return ok
	}

	// To omit a rule it must be redundant on case-sensitive clones too. To
	// dismiss a possible override it must be disjoint on case-insensitive clones.
	foldTarget, foldPrefix := strings.ToLower(target), strings.ToLower(prefix)
	if directory {
		overlap := anywhere || foldPrefix == foldTarget || inside(foldTarget, foldPrefix) || inside(foldPrefix, foldTarget)
		return overlap, base == "**" && (prefix == target || inside(target, prefix))
	}
	if base == "**" {
		return inside(foldTarget, foldPrefix), inside(target, prefix)
	}
	targetDir, name := path.Split(target)
	targetDir = strings.TrimSuffix(targetDir, "/")
	return (anywhere || strings.EqualFold(targetDir, prefix)) && match(strings.ToLower(base), strings.ToLower(name)),
		(anywhere || targetDir == prefix) && match(base, name)
}
