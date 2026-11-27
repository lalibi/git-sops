package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lalibi/git-sops/internal/agekey"
	"github.com/lalibi/git-sops/internal/filter"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/setup"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/spf13/cobra"
)

func newFilterCommand(mode string) *cobra.Command {
	return &cobra.Command{
		DisableFlagParsing: true, // Git supplies a literal filename, including leading dashes.
		Use:                mode + " <path>",
		Short:              "Git " + mode + " filter (invoked by Git)",
		Args:               cobra.ExactArgs(1),
		Hidden:             true,
		RunE: func(_ *cobra.Command, args []string) error {
			return runFilter(mode, args[0])
		},
	}
}

func runFilter(mode, path string) error {
	client, err := sopsClient()
	if err != nil {
		return err
	}

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
		DisableFlagParsing: true,
		Use:                "textconv <file>",
		Short:              "Git diff textconv driver: print the decrypted content of a blob (invoked by Git)",
		Args:               cobra.ExactArgs(1),
		Hidden:             true,
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
		DisableFlagParsing: true,
		Use:                "merge <base> <ours> <theirs> <path> [marker-size]",
		Short:              "Git merge driver: three-way merge of encrypted files (invoked by Git)",
		Args:               cobra.RangeArgs(4, 5),
		Hidden:             true,
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

func newVerifyCommand(o *setup.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check staged filter coverage and SOPS metadata for protected files (pre-commit)",
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
			g.Dir, err = gitx.ToplevelOf(g.Exe, o.RepoPath)
			if err != nil {
				return err
			}
			keyFile, _ := agekey.KeyFile()

			_, failures, err := filter.VerifyIndex(g, &sopsx.Client{Exe: sopsExe, KeyFile: keyFile})
			if err != nil {
				return err
			}

			if len(failures) > 0 {
				var msg strings.Builder
				msg.WriteString("\nERROR: plaintext or invalid SOPS data found in the Git index:\n")
				for _, f := range failures {
					fmt.Fprintf(&msg, "  - %s\n", f)
				}
				msg.WriteString("\nCommit aborted to prevent plaintext secrets from being committed.")
				return &setup.ExitCodeError{Code: 1, Message: msg.String()}
			}

			fmt.Println("SOPS index validation passed.")
			return nil
		},
	}
}
