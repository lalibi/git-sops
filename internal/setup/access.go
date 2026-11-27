package setup

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/lalibi/git-sops/internal/ui"
)

func ShowAccess(o Options, recipient ...string) error {
	var key string
	if len(recipient) > 0 {
		if err := config.ValidateGroup(config.DefaultGroup, recipient); err != nil {
			return err
		}
		key = recipient[0]
	}
	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	m, err := config.ReadManaged(filepath.Join(e.Root, ".sops.yaml"))
	if err != nil {
		return err
	}
	if m == nil {
		ui.Infof("No managed policy found. Showing age recipients from staged filter=sops files only.")
	} else if m.Groups == nil {
		specs, err := config.BuildSpecs(e.Root, m.ProtectedPaths)
		if err != nil {
			return err
		}
		m.ProtectedPaths = specPaths(specs)
		m.Groups = map[string][]string{config.DefaultGroup: m.Recipients}
	}
	files, err := e.Git.TrackedFilterPaths(func(value string) bool { return value == "sops" })
	if err != nil {
		return err
	}
	counts := map[string]int{}
	var accessible []string
	for _, file := range files {
		blob, err := e.Git.Run(nil, "cat-file", "blob", ":"+file)
		if err != nil {
			return err
		}
		keys, err := sopsx.CipherRecipients(file, blob)
		if err != nil {
			return fmt.Errorf("read recipients for %q: %w", file, err)
		}
		if m != nil && !slices.Equal(keys, config.UniqueRecipients(m.KeysFor(file))) {
			ui.Warnf("%s: staged recipients differ from the working policy", file)
		}
		for _, k := range slices.Compact(keys) {
			counts[k]++
			if k == key {
				accessible = append(accessible, file)
			}
		}
	}
	groups := map[string][]string{}
	if m != nil {
		for _, group := range m.GroupNames() {
			for _, k := range config.UniqueRecipients(m.Groups[group]) {
				groups[k] = append(groups[k], group)
				if _, seen := counts[k]; !seen {
					counts[k] = 0
				}
			}
		}
	}
	if key == "" {
		ui.Section("Age recipient / staged files / policy groups")
		for _, k := range slices.Sorted(maps.Keys(counts)) {
			label := strings.Join(groups[k], ", ")
			if label == "" {
				label = "(index only)"
			}
			ui.Printf("  %s  %d  %s", k, counts[k], label)
		}
		ui.Infof("%d recipient(s) across %d protected tracked file(s)", len(counts), len(files))
		return nil
	}
	if m != nil {
		ui.Section("Groups")
		for _, group := range groups[key] {
			ui.Printf("  %s", group)
		}
		ui.Section("Configured rules (more specific paths take precedence)")
		for _, rule := range m.ProtectedPaths {
			group := m.GroupForRule(rule)
			if slices.Contains(m.Groups[group], key) {
				ui.Printf("  %s  [%s]", rule, group)
			}
		}
	}
	ui.Section("Effective tracked files in the index")
	for _, file := range accessible {
		ui.Printf("  %s", file)
	}
	ui.Infof("%d accessible tracked file(s)", len(accessible))
	return nil
}
