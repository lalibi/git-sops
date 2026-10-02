package setup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lalibi/git-sops/internal/agekey"
	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/lalibi/git-sops/internal/ui"
)

type Options struct {
	RepoPath               string
	Protect                []string
	Recipients             []string
	AgeKeySource           string
	NoStage                bool
	Force                  bool
	Yes                    bool
	RemoveGitCryptMetadata bool
}

const defaultProtectedPath = "secrets/"

// NewEnv resolves git, the repository root and sops. It never downloads anything.
func NewEnv(o Options) (*Env, error) {
	g, err := gitx.New("")
	if err != nil {
		return nil, err
	}

	version, err := g.Version()
	if err != nil {
		return nil, err
	}
	if !gitx.VersionAtLeast(version, gitx.MinimumVersion) {
		return nil, fmt.Errorf("Git %s or newer is required (found %s)",
			gitx.FormatVersion(gitx.MinimumVersion), gitx.FormatVersion(version))
	}

	path := o.RepoPath
	if path == "" {
		path = "."
	}
	root, err := gitx.ToplevelOf(g.Exe, path)
	if err != nil {
		return nil, err
	}
	g.Dir = root

	sopsExe, err := sopsx.Find()
	if err != nil {
		return nil, err
	}

	keyFile, _ := agekey.KeyFile()

	return &Env{
		Root:    root,
		Git:     g,
		Sops:    &sopsx.Client{Exe: sopsExe, Dir: root, KeyFile: keyFile},
		NoStage: o.NoStage,
		Force:   o.Force,
	}, nil
}

func validateRecipients(in []string) error {
	for _, r := range in {
		if !config.IsRecipient(r) {
			return fmt.Errorf("'%s' is not an age public recipient (expected age1...)", r)
		}
	}
	return nil
}

func ensureIdentity(importSource string, generate bool) (*agekey.Identity, error) {
	if importSource != "" {
		if err := agekey.Import(importSource); err != nil {
			return nil, err
		}
		ui.Okf("Imported age identity from %s", importSource)
	}

	id, err := agekey.Load()
	if err != nil || id != nil || !generate {
		return id, err
	}

	id, err = agekey.Generate()
	if err != nil {
		return nil, err
	}
	ui.Okf("Generated a new age identity at %s", id.KeyFile)
	return id, nil
}

func assertCleanTrackedTree(e *Env) error {
	out, err := e.Git.Output("status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	if out != "" {
		return errors.New("tracked files have uncommitted changes; commit or stash them before running this operation")
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func promptProtectedPaths() ([]string, error) {
	answer, err := ui.Input(
		"Which files or directories should be encrypted?",
		"Comma-separated, relative to the repository root. End directories with a slash.",
		"secrets/, appsettings.json",
		defaultProtectedPath,
		func(s string) error {
			paths := splitList(s)
			if len(paths) == 0 {
				return errors.New("enter at least one path")
			}
			for _, p := range paths {
				if _, err := config.NormalizePath(p); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return splitList(answer), nil
}

// confirmReplaceSopsConfig lets an interactive user opt into replacing a hand-written .sops.yaml.
func confirmReplaceSopsConfig(e *Env, o *Options) error {
	path := filepath.Join(e.Root, ".sops.yaml")
	if _, err := os.Stat(path); err != nil || o.Force {
		return nil
	}

	managed, err := config.ReadManaged(path)
	if err != nil || managed != nil || !ui.Interactive() {
		return err
	}

	yes, err := ui.Confirm(
		"A .sops.yaml already exists and was not created by git-sops.",
		"Replace it? A timestamped backup is kept next to it.",
		false)
	if err != nil {
		return err
	}
	if !yes {
		return ui.ErrCancelled
	}

	o.Force = true
	return nil
}

func writeConfig(e *Env, specs []config.Spec, recipients []string, migrateGitCrypt bool, o Options) error {
	return ui.Task("Writing .gitattributes and .sops.yaml", func() error {
		if err := config.UpdateAttributes(e.Root, specs, migrateGitCrypt); err != nil {
			return err
		}
		return config.WriteSopsConfig(e.Root, specs, recipients, o.Force, ui.Warnf)
	})
}

func Init(o Options) error {
	if err := validateRecipients(o.Recipients); err != nil {
		return err
	}

	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	ui.Header("init", e.Root)

	existing, err := config.ReadManaged(filepath.Join(e.Root, ".sops.yaml"))
	if err != nil {
		return err
	}

	protect := o.Protect
	if len(protect) == 0 {
		switch {
		case existing != nil && len(existing.ProtectedPaths) > 0:
			protect = existing.ProtectedPaths
		case ui.Interactive():
			if protect, err = promptProtectedPaths(); err != nil {
				return err
			}
		default:
			protect = []string{defaultProtectedPath}
		}
	}

	specs, err := config.BuildSpecs(e.Root, protect)
	if err != nil {
		return err
	}

	if err := confirmReplaceSopsConfig(e, &o); err != nil {
		return err
	}

	id, err := ensureIdentity(o.AgeKeySource, true)
	if err != nil {
		return err
	}

	// The current identity must stay authorized, and earlier add-recipient results are preserved.
	recipients := append([]string{id.Recipient}, o.Recipients...)
	if existing != nil {
		recipients = append(recipients, existing.Recipients...)
	}

	if err := writeConfig(e, specs, recipients, false, o); err != nil {
		return err
	}
	if err := RemoveLegacyTooling(e); err != nil {
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

	paths := make([]string, len(specs))
	for i, s := range specs {
		paths[i] = s.RelativePath
		if s.IsDirectory {
			paths[i] += "/"
		}
	}

	ui.Box("Repository initialized for transparent SOPS encryption",
		"Protected  "+strings.Join(paths, ", "),
		"Recipient  "+id.Recipient,
		"",
		"Review with "+ui.Code("git status")+" and "+ui.Code("git diff --cached")+", then commit.")
	return nil
}

func Join(o Options) error {
	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	ui.Header("join", e.Root)

	id, err := ensureIdentity(o.AgeKeySource, false)
	if err != nil {
		return err
	}

	if id == nil {
		// Generate an identity so a collaborator can hand a public recipient to a maintainer,
		// without pretending it can already decrypt this repository.
		id, err = agekey.Generate()
		if err != nil {
			return err
		}

		ui.Warnf("A new age identity was generated, but this repository is not yet encrypted for it.")
		ui.Printf("")
		ui.Printf("Your public recipient (safe to share):")
		ui.Printf("")
		ui.Printf("  %s", id.Recipient)
		ui.Box("Next steps",
			"1. Send the public recipient above to a maintainer.",
			"2. The maintainer runs "+ui.Code("git-sops add-recipient <recipient>")+", commits and pushes.",
			"3. Pull, then run "+ui.Code("git-sops join")+" again.")
		return &ExitCodeError{Code: 2}
	}

	if err := ConfigureLocal(e); err != nil {
		return err
	}
	if err := ValidateIndex(e); err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(e.Root, ".githooks", "Setup-SopsGit.ps1")); err == nil {
		ui.Warnf("This repository still carries the legacy PowerShell tooling in .githooks/. A maintainer can remove it with 'git-sops init'.")
	}

	ui.Okf("Fresh-clone/new-machine setup completed.")
	return nil
}

var indexLine = regexp.MustCompile(`^(\d+)\s+[0-9a-f]+\s+0\t`)

func AddRecipient(o Options) error {
	if len(o.Recipients) == 0 && ui.Interactive() {
		answer, err := ui.Input(
			"Which age public recipient should get access?",
			"Paste the age1... value the collaborator sent you. Never paste an AGE-SECRET-KEY.",
			"age1...",
			"",
			func(s string) error {
				if !config.IsRecipient(strings.TrimSpace(s)) {
					return errors.New("not an age public recipient (expected age1...)")
				}
				return nil
			})
		if err != nil {
			return err
		}
		o.Recipients = []string{strings.TrimSpace(answer)}
	}

	if len(o.Recipients) == 0 {
		return errors.New("add-recipient requires at least one age public recipient (age1...)")
	}
	if err := validateRecipients(o.Recipients); err != nil {
		return err
	}

	e, err := NewEnv(o)
	if err != nil {
		return err
	}
	ui.Header("add-recipient", e.Root)

	if err := assertCleanTrackedTree(e); err != nil {
		return err
	}

	managed, err := config.ReadManaged(filepath.Join(e.Root, ".sops.yaml"))
	if err != nil {
		return err
	}
	if managed == nil {
		return errors.New("add-recipient requires a .sops.yaml generated by git-sops")
	}

	specs, err := config.BuildSpecs(e.Root, managed.ProtectedPaths)
	if err != nil {
		return err
	}

	all := append(append([]string{}, managed.Recipients...), o.Recipients...)
	err = ui.Task("Updating .sops.yaml", func() error {
		return config.WriteSopsConfig(e.Root, specs, all, false, ui.Warnf)
	})
	if err != nil {
		return err
	}

	if err := ConfigureLocal(e); err != nil {
		return err
	}

	files, err := e.Git.ZList("ls-files", "-z", ":(attr:filter=sops)")
	if err != nil {
		return err
	}

	bar := ui.NewProgress("Re-encrypting", int64(len(files)), false)
	for i, path := range files {
		bar.Set(int64(i), path)
		if err := rekey(e, path); err != nil {
			bar.Abort()
			return err
		}
	}
	bar.Set(int64(len(files)), "")
	bar.Finish("Re-encrypted %d file(s) for %d recipient(s)", len(files), len(config.UniqueRecipients(all)))

	if !o.NoStage {
		if _, err := e.Git.Run(nil, "add", "--", ".sops.yaml"); err != nil {
			return fmt.Errorf("could not stage .sops.yaml: %w", err)
		}
	}

	if err := ValidateIndex(e); err != nil {
		return err
	}

	ui.Box("Recipients updated",
		"Review the staged ciphertext with "+ui.Code("git diff --cached")+", then commit and push.",
		"The new recipient can pull and run "+ui.Code("git-sops join")+".")
	return nil
}

func rekey(e *Env, path string) error {
	plain, err := os.ReadFile(filepath.Join(e.Root, filepath.FromSlash(path)))
	if err != nil {
		return fmt.Errorf("protected file '%s' is missing from the working tree", path)
	}

	encrypted, err := e.Sops.Encrypt(path, plain)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt '%s': %w", path, err)
	}

	hashOut, err := e.Git.Run(encrypted, "hash-object", "-w", "--no-filters", "--stdin")
	if err != nil {
		return err
	}
	hash := strings.TrimSpace(string(hashOut))

	stage, err := e.Git.Output("ls-files", "--stage", "--", path)
	if err != nil {
		return err
	}
	m := indexLine.FindStringSubmatch(strings.SplitN(stage, "\n", 2)[0])
	if m == nil {
		return fmt.Errorf("could not determine the index mode for '%s'", path)
	}

	if _, err := e.Git.Run(nil, "update-index", "--cacheinfo", m[1]+","+hash+","+path); err != nil {
		return err
	}

	// Refreshes stat data through the clean filter, which must keep the new ciphertext.
	if _, err := e.Git.Run(nil, "add", "--", path); err != nil {
		return err
	}
	after, err := e.Git.Output("rev-parse", ":"+path)
	if err != nil {
		return err
	}
	if after != hash {
		return fmt.Errorf("unexpected ciphertext change after rekeying '%s'", path)
	}

	return nil
}

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
			"This rewrites .gitattributes and stages the current plaintext files through SOPS. Nothing is committed.",
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

	if err := confirmReplaceSopsConfig(e, &o); err != nil {
		return err
	}

	id, err := ensureIdentity(o.AgeKeySource, true)
	if err != nil {
		return err
	}

	recipients := append([]string{id.Recipient}, o.Recipients...)

	if err := writeConfig(e, specs, recipients, true, o); err != nil {
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

	ui.Box("git-crypt -> SOPS migration staged",
		"Do NOT delete your old git-crypt keys yet: historical commits remain git-crypt encrypted.",
		"Review the staged blobs, then commit.")
	return nil
}
