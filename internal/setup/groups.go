package setup

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/filter"
	"github.com/lalibi/git-sops/internal/ui"
)

func EditAccess(o Options, action string) error {
	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	return editAccess(e, o, action)
}

func editAccess(e *Env, o Options, action string) error {
	if o.NoStage {
		return errors.New("group access changes must stage the policy and affected ciphertext together")
	}
	if !o.DryRun {
		path, err := e.Git.Output("rev-parse", "--path-format=absolute", "--git-path", "git-sops-access.lock")
		if err != nil {
			return err
		}
		lock, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("lock recipient policy for editing: %w", err)
		}
		defer func() { lock.Close(); os.Remove(path) }()
	}
	if err := assertCleanTrackedTree(e); err != nil {
		return err
	}
	old, err := managedPolicy(e)
	if err != nil {
		return err
	}
	oldSpecs, err := config.BuildSpecs(e.Root, old.ProtectedPaths)
	if err != nil {
		return err
	}
	old.ProtectedPaths = specPaths(oldSpecs)
	next := *old
	next.Groups = maps.Clone(old.Groups)
	if next.Groups == nil {
		next.Groups = map[string][]string{config.DefaultGroup: old.Recipients}
	}
	next.Assignments = maps.Clone(old.Assignments)
	if next.Assignments == nil {
		next.Assignments = map[string]string{}
	}
	group := o.Group
	if group == "" {
		group = config.DefaultGroup
	}
	var requested []config.Spec
	switch action {
	case "protect":
		if next.Groups[group] == nil {
			return fmt.Errorf("unknown group %q; create it with git-sops group set", group)
		}
		requested, err = config.BuildSpecs(e.Root, o.Protect)
		if err != nil {
			return err
		}
		next.ProtectedPaths = slices.Clone(old.ProtectedPaths)
		for _, rule := range specPaths(requested) {
			if !slices.Contains(next.ProtectedPaths, rule) {
				next.ProtectedPaths = append(next.ProtectedPaths, rule)
				assigned := group
				if o.Group == "" {
					assigned = old.GroupForRule(old.RuleFor(rule))
				}
				next.Assignments[strings.TrimSuffix(rule, "/")] = assigned
			} else if o.Group != "" {
				next.Assignments[strings.TrimSuffix(rule, "/")] = group
			}
		}
	case "group-set", "add-recipient", "remove-recipient":
		if action == "remove-recipient" && len(o.Recipients) == 0 && ui.Interactive() {
			keys := next.Groups[group]
			if o.Everywhere {
				keys = nil
				for _, g := range next.GroupNames() {
					keys = append(keys, next.Groups[g]...)
				}
				keys = config.UniqueRecipients(keys)
			}
			key, err := ui.Input("Which age public recipient should lose access?", "Recipients: "+strings.Join(keys, ", "), "age1...", "", nil)
			if err != nil {
				return err
			}
			o.Recipients = []string{strings.TrimSpace(key)}
		}
		if err := editMembership(&next, group, o, action); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown access operation %q", action)
	}
	next.Recipients = next.Groups[config.DefaultGroup]
	if o.RecipientName != "" && old.RecipientNames[o.Recipients[0]] != o.RecipientName {
		next.RecipientNames = maps.Clone(old.RecipientNames)
		next.SetRecipientName(o.Recipients[0], o.RecipientName)
		ui.Infof("Recipient %s: %s", o.Recipients[0], o.RecipientName)
	}
	specs, err := config.BuildSpecs(e.Root, next.ProtectedPaths)
	if err != nil {
		return err
	}
	files, err := e.Git.ZList("ls-files", "-z")
	if err != nil {
		return err
	}
	var reencrypt []string
	for _, p := range files {
		before := old.KeysFor(p)
		if len(before) > 0 && !slices.Equal(config.UniqueRecipients(before), next.KeysFor(p)) {
			reencrypt = append(reencrypt, p)
		}
	}
	ui.Section("Affected policy rules")
	var affected []config.Spec
	for i, p := range next.ProtectedPaths {
		g := next.GroupForRule(p)
		if !slices.Contains(old.ProtectedPaths, p) || g != old.GroupForRule(p) || !slices.Equal(config.UniqueRecipients(old.KeysForRule(p)), next.KeysForRule(p)) {
			ui.Printf("  %s  [%s]", p, g)
			affected = append(affected, specs[i])
		}
	}
	if action != "protect" {
		names := next.GroupNames()
		for _, g := range old.GroupNames() {
			if next.Groups[g] == nil {
				names = append(names, g)
			}
		}
		for _, g := range names {
			before := old.Groups[g]
			if old.Groups == nil && g == config.DefaultGroup {
				before = old.Recipients
			}
			if !slices.Equal(config.UniqueRecipients(before), next.Groups[g]) {
				ui.Infof("Group %s: %s -> %s", g, strings.Join(before, ", "), strings.Join(next.Groups[g], ", "))
			}
		}
	}
	for _, p := range reencrypt {
		ui.Printf("  Re-encrypt %s", p)
	}
	var newFiles []string
	if len(requested) > 0 {
		candidates, err := e.Git.ZList("ls-files", "-z", "--cached", "--others", "--exclude-standard")
		if err != nil {
			return err
		}
		for _, p := range candidates {
			if old.RuleFor(p) == "" && config.Protected(requested, p) {
				ui.Printf("  Encrypt %s", p)
				newFiles = append(newFiles, p)
			}
		}
	}
	for _, g := range next.GroupNames() {
		if len(next.Groups[g]) == 1 {
			ui.Warnf("Group %s has one recipient; consider a second maintainer or an offline recovery key.", g)
		}
	}
	if o.DryRun {
		ui.Infof("Preview complete")
		return nil
	}
	// Roll back the policy, index, and working copies together on a decryption,
	// filter or hook failure. Re-key from the encrypted index, never from a locked working copy.
	touched := append(slices.Clone(reencrypt), newFiles...)
	for _, p := range touched {
		st, err := os.Lstat(filepath.Join(e.Root, filepath.FromSlash(p)))
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("cannot update access for non-regular file %q", p)
		}
	}
	err = pathTransaction(e, func() error {
		policy := &next
		// Naming the shared default explicitly still uses a single recipient list.
		if old.Groups == nil && len(next.Groups) == 1 {
			policy = &config.Managed{Recipients: next.Recipients, RecipientNames: next.RecipientNames}
		}
		if err := writeConfig(e, specs, policy, false, o); err != nil {
			return err
		}
		for _, p := range reencrypt {
			if err := rekey(e, p); err != nil {
				return err
			}
		}
		if err := ConfigureLocal(e); err != nil {
			return err
		}
		if err := Stage(e, requested); err != nil {
			return err
		}
		if err := validateSelectedAttributes(e.Git, specs); err != nil {
			return err
		}
		for _, p := range newFiles {
			cipher, err := e.Git.Run(nil, "cat-file", "blob", ":"+p)
			if err != nil {
				return err
			}
			if locked, err := filter.Locked(e.Sops, p, cipher); err != nil {
				return err
			} else if locked {
				if _, err := e.Sops.Decrypt(p, cipher); err != nil {
					if err := e.writeWorkFile(p, cipher, 0o600); err != nil {
						return err
					}
				}
			}
		}
		return ValidateIndex(e)
	})
	if err != nil {
		return err
	}
	if action == "remove-recipient" {
		ui.Warnf("Earlier commits and previously decrypted copies remain accessible to former recipients.")
	}
	return commitChanges(e, o, action, affected, o.Recipients)
}

func editMembership(m *config.Managed, group string, o Options, action string) error {
	if err := config.ValidateGroup(group, o.Recipients); err != nil {
		return err
	}
	current := m.Groups[group]
	switch action {
	case "group-set":
		m.Groups[group] = config.UniqueRecipients(o.Recipients)
	case "add-recipient":
		if current == nil {
			return fmt.Errorf("unknown group %q", group)
		}
		m.Groups[group] = config.UniqueRecipients(append(slices.Clone(current), o.Recipients...))
	case "remove-recipient":
		names := []string{group}
		if o.Everywhere {
			names = m.GroupNames()
		}
		for _, key := range o.Recipients {
			found := false
			for _, name := range names {
				if slices.Contains(m.Groups[name], key) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("%q is not a recipient in the selected groups", key)
			}
		}
		for _, name := range names {
			kept := recipientDifference(m.Groups[name], o.Recipients)
			if len(kept) == 0 {
				if name == config.DefaultGroup || slices.Contains(slices.Collect(maps.Values(m.Assignments)), name) {
					return fmt.Errorf("group %q would have no recipients; add a replacement or recovery recipient first", name)
				}
				delete(m.Groups, name)
			} else {
				m.Groups[name] = kept
			}
		}
	}
	return nil
}
