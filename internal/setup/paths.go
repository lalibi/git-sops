package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/ui"
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
	files, err := e.Git.ZList("ls-files", "-z")
	if err != nil {
		return err
	}
	var touched []string
	for _, p := range files {
		if config.Protected(specs, p) {
			touched = append(touched, p)
		}
	}
	return pathTransaction(e, touched, func() error {
		if err := writeConfig(e, specs, m.Recipients, false, o); err != nil {
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
		ui.Okf("Protected path set updated. Review staged changes before committing.")
		return nil
	})
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
					ui.Warnf("Skipping %q: it is inside protected folder %q and remains protected. Remove the complete folder rule to unprotect it.", p, s.RelativePath+"/")
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
			if !remove[r.RelativePath] && config.Matches(r, s.RelativePath) {
				ui.Warnf("Skipping %q: it remains protected by folder %q. Remove the complete folder rule to unprotect it.", s.RelativePath, r.RelativePath+"/")
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
	// Decrypt before changing policy. A missing key must leave configuration and index untouched.
	plain := map[string][]byte{}
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
		b, err := os.ReadFile(filepath.Join(e.Root, filepath.FromSlash(p)))
		if err != nil {
			return err
		}
		if e.Sops.IsEncrypted(p, b) {
			b, err = e.Sops.Decrypt(p, b)
			if err != nil {
				return fmt.Errorf("decrypt %q before unprotecting: %w", p, err)
			}
		}
		plain[p] = b
	}
	ui.Warnf("Removing protection stages current contents as PLAINTEXT. Review before committing. Earlier commits remain encrypted.")
	return pathTransaction(e, filesToChange(plain), func() error {
		if err := writeConfig(e, remaining, m.Recipients, false, o); err != nil {
			return err
		}
		for p, b := range plain {
			abs := filepath.Join(e.Root, filepath.FromSlash(p))
			st, err := os.Stat(abs)
			if err != nil {
				return err
			}
			if err := os.WriteFile(abs, b, st.Mode().Perm()); err != nil {
				return err
			}
		}
		if _, err := e.Git.Run(nil, "add", "--", ".gitattributes", ".sops.yaml"); err != nil {
			return err
		}
		for p := range plain {
			attr, err := e.Git.Output("check-attr", "filter", "--", p)
			if err != nil {
				return err
			}
			if strings.HasSuffix(attr, ": sops") {
				return fmt.Errorf("%q is still protected by another .gitattributes rule", p)
			}
			if _, err := e.Git.Run(nil, "--literal-pathspecs", "add", "--renormalize", "--", p); err != nil {
				return err
			}
		}
		return ValidateIndex(e)
	})
}

func filesToChange(files map[string][]byte) []string {
	var out []string
	for p := range files {
		out = append(out, p)
	}
	return out
}

// pathTransaction restores policy, index and touched files if staging or validation fails.
func pathTransaction(e *Env, paths []string, work func() error) error {
	index, err := e.Git.Output("rev-parse", "--path-format=absolute", "--git-path", "index")
	if err != nil {
		return err
	}
	paths = append(paths, ".gitattributes", ".sops.yaml")
	paths = append(paths, index)
	type saved struct {
		path string
		data []byte
		mode os.FileMode
	}
	var backups []saved
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			p = filepath.Join(e.Root, filepath.FromSlash(p))
		}
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		backups = append(backups, saved{p, b, st.Mode().Perm()})
	}
	if err := work(); err != nil {
		for _, b := range backups {
			err = errors.Join(err, os.WriteFile(b.path, b.data, b.mode))
		}
		return err
	}
	return nil
}
