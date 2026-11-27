package setup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/ui"
	"github.com/lalibi/git-sops/internal/worktree"
)

func MigrateGitCrypt(o Options) error {
	if err := validateRecipients(o.Recipients); err != nil {
		return err
	}

	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	ui.Header("migrate-git-crypt", e.Root)

	if err := assertCleanTrackedTree(e); err != nil {
		return err
	}

	gitCrypt, err := exec.LookPath("git-crypt")
	if err != nil {
		return errors.New("git-crypt must be installed and the repository must be unlocked before migration")
	}

	ui.Section("git-crypt encrypted files")
	cmd := exec.Command(gitCrypt, "status", "-e")
	cmd.Dir = e.Root
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.New("git-crypt status failed; ensure the repository is unlocked and healthy before migration")
	}
	ui.Printf("")

	if !o.Yes && ui.Interactive() {
		yes, err := ui.Confirm(
			"Migrate this repository from git-crypt to SOPS?",
			"This rewrites .gitattributes and stages the current plaintext files through SOPS. A commit is created only with --commit.",
			true)
		if err != nil {
			return err
		}
		if !yes {
			return ui.ErrCancelled
		}
	}

	protect := o.Protect
	if len(protect) == 0 {
		protect = []string{defaultProtectedPath}
	}
	specs, err := config.BuildSpecs(e.Root, protect)
	if err != nil {
		return err
	}
	// Capture the effective git-crypt filters before rewriting .gitattributes.
	files, err := e.Git.TrackedFilterPaths(func(driver string) bool {
		return driver == "git-crypt" || strings.HasPrefix(driver, "git-crypt-")
	})
	if err != nil {
		return err
	}
	var uncovered []string
	for _, path := range files {
		f, err := worktree.Open(e.Root, path)
		if err != nil {
			return err
		}
		var header [10]byte
		_, err = io.ReadFull(f, header[:])
		f.Close()
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("read git-crypt working file %q: %w", path, err)
		}
		if string(header[:]) == "\x00GITCRYPT\x00" && err == nil {
			return fmt.Errorf("working file %q is still git-crypt ciphertext; unlock the repository before migrating", path)
		}
		if !config.Protected(specs, path) {
			uncovered = append(uncovered, path)
		}
	}
	discovered, err := config.BuildSpecs(e.Root, uncovered)
	if err != nil {
		return err
	}
	for i, spec := range discovered {
		if spec.RelativePath != uncovered[i] || spec.IsDirectory || spec.IsGlob() {
			return fmt.Errorf("cannot represent git-crypt file %q as an exact protected path", uncovered[i])
		}
	}
	specs = append(specs, discovered...)

	if err := confirmReplaceSopsConfig(e, &o); err != nil {
		return err
	}

	id, err := ensureIdentity(o.AgeKeySource, true)
	if err != nil {
		return err
	}

	recipients := append([]string{id.Recipient}, o.Recipients...)

	if existing, err := config.ReadManaged(filepath.Join(e.Root, ".sops.yaml")); err != nil {
		return err
	} else if existing != nil && existing.Groups != nil {
		return errors.New("repository already uses a grouped SOPS policy")
	}
	if err := writeConfig(e, specs, &config.Managed{Recipients: recipients}, true, o); err != nil {
		return err
	}
	if err := RemoveLegacyTooling(e); err != nil {
		return err
	}
	if err := ConfigureLocal(e); err != nil {
		return err
	}

	if o.RemoveGitCryptMetadata {
		tracked, err := e.Git.ZList("ls-files", "-z", ".git-crypt")
		if err != nil {
			return err
		}
		if len(tracked) > 0 {
			if _, err := e.Git.Run(nil, "rm", "-r", "--", ".git-crypt"); err != nil {
				return fmt.Errorf("could not remove tracked .git-crypt metadata: %w", err)
			}
			ui.Okf("Removed tracked .git-crypt metadata")
		}
	}

	if err := Stage(e, specs); err != nil {
		return err
	}
	if err := ValidateIndex(e); err != nil {
		return err
	}
	if err := commitChanges(e, o, "migrate-git-crypt", specs, nil); err != nil {
		return err
	}

	ui.Box("git-crypt -> SOPS migration prepared",
		"Do NOT delete your old git-crypt keys yet: historical commits remain git-crypt encrypted.",
		reviewChanges(o))
	return nil
}
