package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/lalibi/git-sops/internal/check"
	"github.com/lalibi/git-sops/internal/setup"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/lalibi/git-sops/internal/ui"
	"github.com/spf13/cobra"
)

// Set by the release build.
var version = "dev"

func main() {
	err := newRootCommand().Execute()
	if err == nil {
		return
	}

	var exitErr *setup.ExitCodeError
	switch {
	case errors.As(err, &exitErr):
		if exitErr.Message != "" {
			fmt.Fprintln(os.Stderr, exitErr.Message)
		}
		os.Exit(exitErr.Code)
	case errors.Is(err, ui.ErrCancelled):
		fmt.Fprintln(os.Stderr, "Cancelled.")
		os.Exit(130)
	default:
		ui.Fail(err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var opts setup.Options

	root := &cobra.Command{
		Use:           "git-sops",
		Short:         "Transparent SOPS + age encryption for Git repositories",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.PersistentFlags().StringVarP(&opts.RepoPath, "repo", "C", ".", "path inside the target repository")

	root.AddCommand(
		newInitCommand(&opts),
		newPathCommand(&opts, false),
		newPathCommand(&opts, true),
		newHistoryCommand(&opts),
		newJoinCommand(&opts),
		newAddRecipientCommand(&opts),
		newRemoveRecipientCommand(&opts),
		newGroupCommand(&opts),
		newAccessCommand(&opts),
		newMigrateCommand(&opts),
		newCheckCommand(&opts),
		newStatusCommand(&opts),
		newInstallSopsCommand(),
		newUpdateCommand(),
		newDecryptCommand(),
		newFilterCommand("clean"),
		newFilterCommand("smudge"),
		newTextconvCommand(),
		newMergeCommand(),
		newVerifyCommand(&opts),
	)
	return root
}

func newInitCommand(o *setup.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Configure a repository for transparent SOPS encryption (also upgrades legacy setups)",
		Example: `  git-sops init                                 # asks which paths to protect
  git-sops init --protect secrets/ --protect appsettings.json`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return setup.Init(*o) },
	}
	cmd.Flags().StringSliceVar(&o.Protect, "protect", nil, "complete protected path set (comma-separated or repeatable); defaults to the existing set, else asks")
	cmd.Flags().StringSliceVar(&o.Recipients, "recipient", nil, "additional age public recipient (repeatable)")
	cmd.Flags().StringVar(&o.AgeKeySource, "age-key", "", "import an age identity file before initializing")
	cmd.Flags().BoolVar(&o.NoStage, "no-stage", false, "do not stage the generated changes")
	cmd.Flags().BoolVar(&o.Force, "force", false, "replace a hand-written .sops.yaml after backing it up")
	addCommitFlags(cmd, o)
	return cmd
}

func addCommitFlags(cmd *cobra.Command, o *setup.Options) {
	cmd.Flags().BoolVar(&o.Commit, "commit", false, "commit validated staged changes using normal Git hooks and signing")
	cmd.Flags().StringVar(&o.Message, "message", "", "override the generated commit message (requires --commit)")
	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("message") {
			if !o.Commit {
				return errors.New("--message requires --commit")
			}
			if strings.TrimSpace(o.Message) == "" {
				return errors.New("--message must not be empty")
			}
		}
		return nil
	}
}

func newPathCommand(base *setup.Options, remove bool) *cobra.Command {
	var paths []string
	name, short := "protect", "Add files or directories to the existing protected path set"
	if remove {
		name, short = "unprotect", "Remove complete protection rules and stage current contents as plaintext"
	}
	cmd := &cobra.Command{
		Use: name + " [paths...]", Short: short,
		RunE: func(_ *cobra.Command, args []string) error {
			o := *base
			o.Protect = append(append([]string{}, paths...), args...)
			if remove {
				return setup.Unprotect(o)
			}
			return setup.Protect(o)
		},
	}
	cmd.Flags().StringSliceVar(&paths, "protect", nil, "paths (comma-separated or repeatable); positional paths are also accepted")
	if !remove {
		cmd.Flags().StringVar(&base.Group, "group", "", "assign these paths to a named recipient group")
		cmd.Flags().BoolVar(&base.DryRun, "dry-run", false, "preview the paths affected by the assignment")
	}
	addCommitFlags(cmd, base)
	return cmd
}

func newHistoryCommand(base *setup.Options) *cobra.Command {
	var paths []string
	var approved bool
	cmd := &cobra.Command{
		Use: "encrypt-history", Short: "Encrypt historical versions in place across all refs (requires explicit approval)",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			o := *base
			o.Protect = paths
			return setup.EncryptHistory(o, approved)
		},
	}
	cmd.Flags().StringSliceVar(&paths, "protect", nil, "additional historical paths, including former names (comma-separated or repeatable)")
	cmd.Flags().BoolVar(&approved, "confirm-rewrite", false, "explicitly approve the warned in-place history rewrite (for noninteractive use)")
	return cmd
}

func newJoinCommand(o *setup.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Set up a fresh clone or new machine and decrypt the working tree",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return setup.Join(*o) },
	}
	cmd.Flags().StringVar(&o.AgeKeySource, "age-key", "", "import an age identity file first")
	return cmd
}

func newAddRecipientCommand(o *setup.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "add-recipient [age1...]",
		Short:   "Authorize additional age recipients and re-encrypt protected files",
		Example: "  git-sops add-recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		RunE: func(_ *cobra.Command, args []string) error {
			o.Recipients = append(o.Recipients, args...)
			return setup.AddRecipient(*o)
		},
	}
	cmd.Flags().StringSliceVar(&o.Recipients, "recipient", nil, "age public recipient (repeatable)")
	cmd.Flags().StringVar(&o.Group, "group", "", "recipient group (defaults to default)")
	cmd.Flags().BoolVar(&o.DryRun, "dry-run", false, "show affected rules and files without applying")
	cmd.Flags().BoolVar(&o.NoStage, "no-stage", false, "do not stage .sops.yaml")
	addCommitFlags(cmd, o)
	return cmd
}

func newRemoveRecipientCommand(o *setup.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove-recipient [age1...]",
		Short:   "Revoke age recipients and re-encrypt protected files without them",
		Example: "  git-sops remove-recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		RunE: func(_ *cobra.Command, args []string) error {
			o.Recipients = append(o.Recipients, args...)
			return setup.RemoveRecipient(*o)
		},
	}
	cmd.Flags().StringSliceVar(&o.Recipients, "recipient", nil, "age public recipient to remove (repeatable)")
	cmd.Flags().StringVar(&o.Group, "group", "", "recipient group (defaults to default)")
	cmd.Flags().BoolVar(&o.Everywhere, "everywhere", false, "revoke the recipient from every group")
	cmd.MarkFlagsMutuallyExclusive("group", "everywhere")
	cmd.Flags().BoolVar(&o.DryRun, "dry-run", false, "show affected rules and files without applying")
	cmd.Flags().BoolVar(&o.NoStage, "no-stage", false, "do not stage .sops.yaml")
	addCommitFlags(cmd, o)
	return cmd
}

func newMigrateCommand(o *setup.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate-git-crypt",
		Short: "Replace git-crypt attributes with SOPS and stage the plaintext files",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return setup.MigrateGitCrypt(*o) },
	}
	cmd.Flags().StringSliceVar(&o.Protect, "protect", nil, "file or directory to protect in addition to tracked git-crypt files (comma-separated or repeatable); defaults to secrets/")
	cmd.Flags().StringSliceVar(&o.Recipients, "recipient", nil, "additional age public recipient (repeatable)")
	cmd.Flags().StringVar(&o.AgeKeySource, "age-key", "", "import an age identity file first")
	cmd.Flags().BoolVar(&o.NoStage, "no-stage", false, "do not stage the generated changes")
	cmd.Flags().BoolVar(&o.Force, "force", false, "replace a hand-written .sops.yaml after backing it up")
	cmd.Flags().BoolVar(&o.RemoveGitCryptMetadata, "remove-git-crypt-metadata", false, "git rm the tracked .git-crypt directory")
	cmd.Flags().BoolVarP(&o.Yes, "yes", "y", false, "skip the confirmation prompt")
	addCommitFlags(cmd, o)
	return cmd
}

func newCheckCommand(o *setup.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check Git, SOPS, your age key and (inside a repository) the git-sops setup",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return check.Run(o.RepoPath) },
	}
}

func newInstallSopsCommand() *cobra.Command {
	var sopsVersion string
	var force bool

	cmd := &cobra.Command{
		Use:   "install-sops",
		Short: "Download and verify a SOPS release for git-sops to use",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			ui.Header("install-sops", "")

			if existing, err := sopsx.Find(); err == nil && !force {
				v, _ := (&sopsx.Client{Exe: existing}).Version()
				ui.Okf("SOPS is already installed: %s", v)
				ui.Printf("  %s", ui.Dim(existing))
				ui.Printf("")
				ui.Printf("Use --force to download v%s anyway.", sopsVersion)
				return nil
			}

			path, err := sopsx.Install(sopsVersion)
			if err != nil {
				return err
			}
			ui.Okf("Installed SOPS to %s", path)

			if onPath, err := exec.LookPath("sops"); err == nil {
				ui.Warnf("Another sops is on your PATH and is used instead: %s", onPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sopsVersion, "sops-version", sopsx.DefaultVersion, "SOPS release to install")
	cmd.Flags().BoolVar(&force, "force", false, "download even when SOPS is already available")
	return cmd
}
