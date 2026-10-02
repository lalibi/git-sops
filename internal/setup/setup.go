// Package setup implements the repository-level workflows behind init, join, add-recipient and migrate-git-crypt.
package setup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/lalibi/git-sops/internal/ui"
)

type Env struct {
	Root    string
	Git     *gitx.Git
	Sops    *sopsx.Client
	NoStage bool
	Force   bool
}

// ExitCodeError makes the process exit with a specific code after printing Message.
type ExitCodeError struct {
	Code    int
	Message string
}

func (e *ExitCodeError) Error() string { return e.Message }

// selfCommand is how Git config refers to this binary: by name when it is on PATH, else by absolute path.
func selfCommand() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	if p, err := exec.LookPath("git-sops"); err == nil {
		a, errA := os.Stat(p)
		b, errB := os.Stat(self)
		if errA == nil && errB == nil && os.SameFile(a, b) {
			return "git-sops", nil
		}
	}

	if strings.Contains(self, "'") {
		return "", fmt.Errorf("the git-sops path contains a single quote and cannot be used in Git config: %s", self)
	}

	// Git runs filter commands through sh, which treats backslashes as escapes.
	return "'" + filepath.ToSlash(self) + "'", nil
}

// ConfigureLocal writes the repository-local filter and hook config and decrypts protected files that are still ciphertext.
func ConfigureLocal(e *Env) error {
	for _, f := range []string{".gitattributes", ".sops.yaml"} {
		if _, err := os.Stat(filepath.Join(e.Root, f)); err != nil {
			return fmt.Errorf("required file '%s' was not found", f)
		}
	}

	self, err := selfCommand()
	if err != nil {
		return err
	}

	var toSmudge []string
	err = ui.Task("Configuring Git filter and pre-commit hook", func() error {
		protected, err := e.Git.ZList("ls-files", "-z", ":(attr:filter=sops)")
		if err != nil {
			return err
		}

		toSmudge, err = e.pendingDecryption(protected)
		if err != nil {
			return err
		}

		settings := [][]string{
			{"filter.sops.clean", self + " clean %f"},
			{"filter.sops.smudge", self + " smudge %f"},
			{"filter.sops.required", "true"},
			{"hook.sops-index.command", self + " verify"},
		}
		for _, kv := range settings {
			if _, err := e.Git.Run(nil, "config", "--local", kv[0], kv[1]); err != nil {
				return err
			}
		}

		// Exit code 5 just means the key was not set yet.
		_, _ = e.Git.Run(nil, "config", "--local", "--unset-all", "hook.sops-index.event")
		if _, err := e.Git.Run(nil, "config", "--local", "--add", "hook.sops-index.event", "pre-commit"); err != nil {
			return err
		}

		hooks, err := e.Git.Output("hook", "list", "--show-scope", "pre-commit")
		if err != nil || !hasHook(hooks, "sops-index") {
			return errors.New("Git did not expose the configured pre-commit hook; Git 2.55 or newer is required")
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(toSmudge) > 0 {
		total := int64(len(toSmudge))
		bar := ui.NewProgress("Decrypting working tree", total, false)

		for i, path := range toSmudge {
			bar.Set(int64(i), path)
			if err := e.decryptToWorkingTree(path); err != nil {
				bar.Abort()
				return err
			}
		}

		bar.Set(total, "")
		bar.Finish("Decrypted %d protected file(s)", len(toSmudge))
	}

	return nil
}

func hasHook(list, name string) bool {
	for _, line := range strings.Split(list, "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), name) {
			return true
		}
	}
	return false
}

// pendingDecryption selects protected files whose working copy still holds the ciphertext
// (or is missing) while the index blob really is SOPS ciphertext.
func (e *Env) pendingDecryption(protected []string) ([]string, error) {
	var pending []string

	for _, path := range protected {
		abs := filepath.Join(e.Root, filepath.FromSlash(path))

		if _, err := os.Stat(abs); err == nil {
			indexHash, err := e.Git.Output("rev-parse", ":"+path)
			if err != nil {
				return nil, err
			}
			workHash, err := e.Git.Output("hash-object", "--no-filters", "--", path)
			if err != nil {
				return nil, err
			}
			if indexHash != workHash {
				continue
			}
		}

		blob, err := e.Git.Run(nil, "cat-file", "blob", ":"+path)
		if err != nil {
			return nil, err
		}
		// Plaintext that was tracked before protection was enabled must be left alone.
		if e.Sops.IsEncrypted(path, blob) {
			pending = append(pending, path)
		}
	}

	return pending, nil
}

func (e *Env) decryptToWorkingTree(path string) error {
	blob, err := e.Git.Run(nil, "cat-file", "blob", ":"+path)
	if err != nil {
		return fmt.Errorf("could not read the encrypted index blob for '%s': %w", path, err)
	}

	plain, err := e.Sops.Decrypt(path, blob)
	if err != nil {
		return fmt.Errorf("could not decrypt '%s': %w", path, err)
	}

	abs := filepath.Join(e.Root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(abs, plain, 0o644); err != nil {
		return err
	}

	before, err := e.Git.Output("rev-parse", ":"+path)
	if err != nil {
		return err
	}
	if _, err := e.Git.Run(nil, "add", "--", path); err != nil {
		return fmt.Errorf("could not refresh '%s' through the clean filter: %w", path, err)
	}
	after, err := e.Git.Output("rev-parse", ":"+path)
	if err != nil {
		return err
	}
	if before != after {
		return fmt.Errorf("unexpected index change while refreshing '%s'; aborting", path)
	}

	return nil
}

// ValidateIndex runs the pre-commit hook so setup ends with the same check commits will face.
func ValidateIndex(e *Env) error {
	s := ui.Spin("Validating SOPS-protected index")

	if _, err := e.Git.Run(nil, "hook", "run", "pre-commit"); err != nil {
		s.Fail("SOPS index validation failed")

		var exitErr *gitx.ExitError
		if errors.As(err, &exitErr) && strings.TrimSpace(exitErr.Stderr) != "" {
			return errors.New(strings.TrimSpace(exitErr.Stderr))
		}
		return errors.New("SOPS index validation failed")
	}

	s.Done("SOPS index validation passed")
	return nil
}

// Stage adds the generated config and pushes every protected path through the clean filter.
func Stage(e *Env, specs []config.Spec) error {
	if e.NoStage {
		return nil
	}

	if _, err := e.Git.Run(nil, "add", "--", ".gitattributes", ".sops.yaml"); err != nil {
		return fmt.Errorf("could not stage the SOPS configuration: %w", err)
	}

	bar := ui.NewProgress("Encrypting and staging", int64(len(specs)), false)
	staged := 0

	for i, spec := range specs {
		bar.Set(int64(i), spec.RelativePath)

		abs := filepath.Join(e.Root, filepath.FromSlash(spec.RelativePath))
		if _, err := os.Stat(abs); err != nil {
			ui.Warnf("Protected path '%s' does not exist yet; the rule was configured but no file was staged.", spec.RelativePath)
			continue
		}

		if err := e.stagePath(spec); err != nil {
			bar.Abort()
			return err
		}
		staged++
	}

	bar.Set(int64(len(specs)), "")
	bar.Finish("Staged %d protected path(s)", staged)
	return nil
}

func (e *Env) stagePath(spec config.Spec) error {
	tracked, err := e.trackedFiles(spec)
	if err != nil {
		return err
	}

	renormalize := false
	for _, f := range tracked {
		blob, err := e.Git.Run(nil, "cat-file", "blob", ":"+f)
		if err != nil || !e.Sops.IsEncrypted(f, blob) {
			renormalize = true
			break
		}
	}

	// Files tracked as plaintext have to be rewritten through the clean filter.
	if renormalize {
		if _, err := e.Git.Run(nil, "add", "--renormalize", "--", spec.RelativePath); err != nil {
			return fmt.Errorf("could not renormalize '%s': %w", spec.RelativePath, err)
		}
	}

	// Stages new files and refreshes tracked ones; existing ciphertext stays stable through clean.
	if _, err := e.Git.Run(nil, "add", "--", spec.RelativePath); err != nil {
		return fmt.Errorf("could not stage protected path '%s': %w", spec.RelativePath, err)
	}
	return nil
}

func (e *Env) trackedFiles(spec config.Spec) ([]string, error) {
	pathspec := spec.RelativePath
	if spec.IsDirectory {
		pathspec += "/"
	}
	return e.Git.ZList("ls-files", "-z", "--", pathspec)
}

// legacyTooling lists files the PowerShell-based implementation copied into every repository.
var legacyTooling = []string{
	".githooks/git-sops-filter.ps1",
	".githooks/Test-SopsIndex.ps1",
	".githooks/Setup-SopsGit.ps1",
	".githooks/Initialize-SopsGit.ps1",
}

// RemoveLegacyTooling deletes the repository-local PowerShell scripts left by the old initializer.
func RemoveLegacyTooling(e *Env) error {
	var found []string
	for _, f := range legacyTooling {
		if _, err := os.Stat(filepath.Join(e.Root, filepath.FromSlash(f))); err == nil {
			found = append(found, f)
		}
	}
	if len(found) == 0 {
		return nil
	}

	ui.Infof("Removing legacy PowerShell tooling: %s", strings.Join(found, ", "))

	for _, f := range found {
		if !e.NoStage {
			if _, err := e.Git.Run(nil, "rm", "-f", "--ignore-unmatch", "--quiet", "--", f); err != nil {
				return err
			}
		}
		if err := os.Remove(filepath.Join(e.Root, filepath.FromSlash(f))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	// Succeeds only when the directory is empty, which is the case we want.
	_ = os.Remove(filepath.Join(e.Root, ".githooks"))
	return nil
}
