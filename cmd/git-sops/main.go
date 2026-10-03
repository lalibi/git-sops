package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/lalibi/git-sops/internal/agekey"
	"github.com/lalibi/git-sops/internal/check"
	"github.com/lalibi/git-sops/internal/filter"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/setup"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/lalibi/git-sops/internal/ui"
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
		newJoinCommand(&opts),
		newAddRecipientCommand(&opts),
		newRemoveRecipientCommand(&opts),
		newMigrateCommand(&opts),
		newCheckCommand(&opts),
		newInstallSopsCommand(),
		newDecryptCommand(),
		newFilterCommand("clean"),
		newFilterCommand("smudge"),
		newTextconvCommand(),
		newMergeCommand(),
		newVerifyCommand(),
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
	cmd.Flags().StringSliceVar(&o.Protect, "protect", nil, "file or directory to protect (repeatable); defaults to the existing set, else asks")
	cmd.Flags().StringSliceVar(&o.Recipients, "recipient", nil, "additional age public recipient (repeatable)")
	cmd.Flags().StringVar(&o.AgeKeySource, "age-key", "", "import an age identity file before initializing")
	cmd.Flags().BoolVar(&o.NoStage, "no-stage", false, "do not stage the generated changes")
	cmd.Flags().BoolVar(&o.Force, "force", false, "replace a hand-written .sops.yaml after backing it up")
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
	cmd.Flags().BoolVar(&o.NoStage, "no-stage", false, "do not stage .sops.yaml")
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
	cmd.Flags().BoolVar(&o.NoStage, "no-stage", false, "do not stage .sops.yaml")
	return cmd
}

func newMigrateCommand(o *setup.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate-git-crypt",
		Short: "Replace git-crypt attributes with SOPS and stage the plaintext files",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return setup.MigrateGitCrypt(*o) },
	}
	cmd.Flags().StringSliceVar(&o.Protect, "protect", nil, "file or directory to protect (repeatable); defaults to secrets/")
	cmd.Flags().StringSliceVar(&o.Recipients, "recipient", nil, "additional age public recipient (repeatable)")
	cmd.Flags().StringVar(&o.AgeKeySource, "age-key", "", "import an age identity file first")
	cmd.Flags().BoolVar(&o.NoStage, "no-stage", false, "do not stage the generated changes")
	cmd.Flags().BoolVar(&o.Force, "force", false, "replace a hand-written .sops.yaml after backing it up")
	cmd.Flags().BoolVar(&o.RemoveGitCryptMetadata, "remove-git-crypt-metadata", false, "git rm the tracked .git-crypt directory")
	cmd.Flags().BoolVarP(&o.Yes, "yes", "y", false, "skip the confirmation prompt")
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

func newFilterCommand(mode string) *cobra.Command {
	return &cobra.Command{
		Use:    mode + " <path>",
		Short:  "Git " + mode + " filter (invoked by Git)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return runFilter(mode, args[0])
		},
	}
}

func runFilter(mode, path string) error {
	sopsExe, err := sopsx.Find()
	if err != nil {
		return err
	}
	keyFile, _ := agekey.KeyFile()
	client := &sopsx.Client{Exe: sopsExe, KeyFile: keyFile}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	var out []byte
	if mode == "smudge" {
		out, err = filter.Smudge(client, path, input)
	} else {
		g, gerr := gitx.New("")
		if gerr != nil {
			return gerr
		}
		out, err = filter.Clean(g, client, path, input)
	}
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(out)
	return err
}

func sopsClient() (*sopsx.Client, error) {
	sopsExe, err := sopsx.Find()
	if err != nil {
		return nil, err
	}
	keyFile, _ := agekey.KeyFile()
	return &sopsx.Client{Exe: sopsExe, KeyFile: keyFile}, nil
}

func newTextconvCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "textconv <file>",
		Short:  "Git diff textconv driver: print the decrypted content of a blob (invoked by Git)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := sopsClient()
			if err != nil {
				return err
			}

			// Git passes a temporary file named <random>_<original name>, so the extension is kept.
			input, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(filter.TextConv(client, args[0], input))
			return err
		},
	}
}

func newMergeCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "merge <base> <ours> <theirs> <path> [marker-size]",
		Short:  "Git merge driver: three-way merge of encrypted files (invoked by Git)",
		Args:   cobra.RangeArgs(4, 5),
		Hidden: true,
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := sopsClient()
			if err != nil {
				return err
			}
			g, err := gitx.New("")
			if err != nil {
				return err
			}

			basePath, oursPath, theirsPath, path := args[0], args[1], args[2], args[3]
			markerSize := ""
			if len(args) == 5 {
				markerSize = args[4]
			}

			var blobs [3][]byte
			for i, p := range []string{basePath, oursPath, theirsPath} {
				if blobs[i], err = os.ReadFile(p); err != nil {
					return err
				}
			}

			out, conflicted, err := filter.Merge(g, client, path, blobs[0], blobs[1], blobs[2], markerSize)
			if err != nil {
				return err
			}

			// Git takes the result from the 'ours' file; a non-zero exit marks it as conflicted.
			if err := os.WriteFile(oursPath, out, 0o600); err != nil {
				return err
			}
			if conflicted {
				return &setup.ExitCodeError{Code: 1, Message: "git-sops: merge conflict in " + path + "; resolve the markers in the working tree, then git add it"}
			}
			return nil
		},
	}
}

func newVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Fail when a protected file in the Git index is not SOPS ciphertext (pre-commit)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			g, err := gitx.New("")
			if err != nil {
				return err
			}
			sopsExe, err := sopsx.Find()
			if err != nil {
				return err
			}
			keyFile, _ := agekey.KeyFile()

			_, failures, err := filter.VerifyIndex(g, &sopsx.Client{Exe: sopsExe, KeyFile: keyFile})
			if err != nil {
				return err
			}

			if len(failures) > 0 {
				msg := "\nERROR: plaintext or invalid SOPS data found in the Git index:\n"
				for _, f := range failures {
					msg += "  - " + f + "\n"
				}
				msg += "\nCommit aborted to prevent plaintext secrets from being committed."
				return &setup.ExitCodeError{Code: 1, Message: msg}
			}

			fmt.Println("SOPS index validation passed.")
			return nil
		},
	}
}
