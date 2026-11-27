package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/ui"
	"github.com/lalibi/git-sops/internal/worktree"
)

func managedPolicy(e *Env) (*config.Managed, error) {
	m, err := config.ReadManaged(filepath.Join(e.Root, ".sops.yaml"))
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("a managed .sops.yaml is required; run git-sops init first")
	}
	return m, nil
}

func specPaths(specs []config.Spec) []string {
	var paths []string
	seen := map[string]bool{}
	for _, s := range specs {
		p := s.RelativePath
		if s.IsDirectory {
			p += "/"
		}
		if !seen[p] {
			paths = append(paths, p)
			seen[p] = true
		}
	}
	return paths
}

// Protect adds paths without replacing any existing protection or recipients.
func Protect(o Options) error {
	if len(o.Protect) == 0 {
		return errors.New("specify at least one path to protect")
	}
	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	if err := assertCleanTrackedTree(e); err != nil {
		return err
	}
	m, err := managedPolicy(e)
	if err != nil {
		return err
	}
	if m.Groups != nil || o.Group != "" || o.DryRun {
		return editAccess(e, o, "protect")
	}
	requested, err := config.BuildSpecs(e.Root, o.Protect)
	if err != nil {
		return err
	}
	specs, err := config.BuildSpecs(e.Root, append(m.ProtectedPaths, o.Protect...))
	if err != nil {
		return err
	}
	// Adding paths must not implicitly generate or authorize a new identity.
	paths := specPaths(specs)
	specs, err = config.BuildSpecs(e.Root, paths)
	if err != nil {
		return err
	}
	err = pathTransaction(e, func() error {
		if err := writeConfig(e, specs, m, false, o); err != nil {
			return err
		}
		if err := ConfigureLocal(e); err != nil {
			return err
		}
		if err := Stage(e, specs); err != nil {
			return err
		}
		if err := ValidateIndex(e); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := commitChanges(e, o, "protect", requested, nil); err != nil {
		return err
	}
	ui.Okf("Protected path set updated. %s", reviewChanges(o))
	return nil
}

// Unprotect only removes complete, explicitly configured rules. It never creates exclusions.
func Unprotect(o Options) error {
	if len(o.Protect) == 0 {
		return errors.New("specify at least one complete protection rule to remove")
	}
	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	m, err := managedPolicy(e)
	if err != nil {
		return err
	}
	old, err := config.BuildSpecs(e.Root, m.ProtectedPaths)
	if err != nil {
		return err
	}
	remove := map[string]bool{}
	for _, p := range o.Protect {
		n, err := config.NormalizePath(p)
		if err != nil {
			return err
		}
		found := false
		for _, s := range old {
			if s.RelativePath == n {
				found = true
			}
		}
		if !found {
			covered := false
			for _, s := range old {
				if config.Matches(s, n) {
					ui.Warnf("Skipping %q: it remains protected by rule %q. Remove the complete rule to unprotect it.", p, s.RelativePath)
					covered = true
					break
				}
			}
			if covered {
				continue
			}
			return fmt.Errorf("%q is not a complete protection rule; remove the enclosing rule instead", p)
		}
		remove[n] = true
	}
	// An explicit child rule can also remain covered by an enclosing folder.
	for _, s := range old {
		if !remove[s.RelativePath] {
			continue
		}
		for _, r := range old {
			if !remove[r.RelativePath] && (r.IsDirectory || !s.IsGlob() && !s.IsDirectory) && config.Matches(r, s.RelativePath) {
				ui.Warnf("Skipping %q: it remains protected by rule %q. Remove the complete rule to unprotect it.", s.RelativePath, r.RelativePath)
				delete(remove, s.RelativePath)
				break
			}
		}
	}
	if len(remove) == 0 {
		return nil
	}
	if err := assertCleanTrackedTree(e); err != nil {
		return err
	}
	var remaining, removed []config.Spec
	for _, s := range old {
		if remove[s.RelativePath] {
			removed = append(removed, s)
		} else {
			remaining = append(remaining, s)
		}
	}
	files, err := e.Git.ZList("ls-files", "-z")
	if err != nil {
		return err
	}
	var selected []string
	for _, p := range files {
		if !config.Protected(removed, p) || config.Protected(remaining, p) {
			continue
		}
		st, err := os.Lstat(filepath.Join(e.Root, filepath.FromSlash(p)))
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("cannot unprotect non-regular file %q", p)
		}
		selected = append(selected, p)
	}
	ui.Warnf("Removing protection stages current contents as PLAINTEXT. Review before committing. Earlier commits remain encrypted.")
	err = pathTransaction(e, func() error {
		if err := writeConfig(e, remaining, m, false, o); err != nil {
			return err
		}
		// Even staging just the policy can refresh index entries and run clean filters.
		// Check every removed path against the new working attributes first.
		attrs, err := e.Git.FilterAttributes(selected, false)
		if err != nil {
			return err
		}
		for _, p := range selected {
			if attrs[p] == "sops" {
				return fmt.Errorf("%q is still protected by another .gitattributes rule", p)
			}
		}
		if _, err := e.Git.Run(nil, "add", "--", ".gitattributes", ".sops.yaml"); err != nil {
			return err
		}
		for _, p := range selected {
			data, err := worktree.ReadFile(e.Root, p)
			if err != nil {
				return err
			}
			if e.Sops.IsEncrypted(p, data) {
				plain, err := e.Sops.Decrypt(p, data)
				if err != nil {
					return fmt.Errorf("decrypt %q before unprotecting: %w", p, err)
				}
				if err := e.writeWorkFile(p, plain, 0o600); err != nil {
					return err
				}
			}
			if _, err := e.Git.Run(nil, "--literal-pathspecs", "add", "--renormalize", "--", p); err != nil {
				return err
			}
		}
		return ValidateIndex(e)
	})
	if err != nil {
		return err
	}
	return commitChanges(e, o, "unprotect", removed, nil)
}
