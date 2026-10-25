package main

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/setup"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/spf13/cobra"
)

func newStatusCommand(o *setup.Options) *cobra.Command {
	var onlyProtected, onlyUnprotected bool
	cmd := &cobra.Command{
		Use: "status", Short: "List tracked files, protection rules and encryption in the index",
		Long: "List tracked files using staged attributes and index blobs. Working-tree plaintext is normal; repository history is not inspected. No private key is required.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			g, err := gitx.New(o.RepoPath)
			if err != nil {
				return err
			}
			root, err := gitx.ToplevelOf(g.Exe, o.RepoPath)
			if err != nil {
				return err
			}
			g.Dir = root
			entries, err := g.ZList("ls-files", "--stage", "-z")
			if err != nil {
				return err
			}
			files := []string{}
			unmerged := map[string]bool{}
			submodules := map[string]bool{}
			seen := map[string]bool{}
			for _, entry := range entries {
				meta, path, ok := strings.Cut(entry, "\t")
				fields := strings.Fields(meta)
				if !ok || len(fields) != 3 {
					return fmt.Errorf("invalid index entry")
				}
				if !seen[path] {
					files = append(files, path)
					seen[path] = true
				}
				if fields[2] != "0" {
					unmerged[path] = true
				}
				submodules[path] = fields[0] == "160000"
			}
			if len(files) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No tracked files in the index.")
				return nil
			}
			attrs, err := g.Run([]byte(strings.Join(files, "\x00")+"\x00"), "check-attr", "--cached", "-z", "--stdin", "filter")
			if err != nil {
				return err
			}
			protected := map[string]bool{}
			fields := strings.Split(string(attrs), "\x00")
			for i := 0; i+2 < len(fields); i += 3 {
				protected[fields[i]] = fields[i+2] == "sops"
			}
			exe, err := sopsx.Find()
			if err != nil {
				return err
			}
			s := &sopsx.Client{Exe: exe, Dir: root}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "PATH\tPROTECTION\tINDEX")
			failed := false
			for _, path := range files {
				protection, state := "unprotected", "unmerged (!)"
				if protected[path] {
					protection = "protected"
				}
				if unmerged[path] {
					failed = true
				} else if submodules[path] {
					state = "submodule"
					if protected[path] {
						state = "submodule (!)"
						failed = true
					}
				} else {
					blob, err := g.Run(nil, "cat-file", "blob", ":"+path)
					if err != nil {
						return err
					}
					encrypted := s.IsEncrypted(path, blob)
					state = "plaintext"
					if encrypted {
						state = "encrypted"
					} else if protected[path] {
						state = "plaintext (!)"
						failed = true
					}
				}
				if onlyProtected && !protected[path] || onlyUnprotected && protected[path] {
					continue
				}
				label := path
				if strings.ContainsAny(path, "\t\r\n") {
					label = strconv.Quote(path)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", label, protection, state)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\nIndex only; protected working-tree files normally contain plaintext.")
			if failed {
				return &setup.ExitCodeError{Code: 1, Message: "Index contains protected entries without SOPS encryption or unresolved conflicts."}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&onlyProtected, "protected", false, "show only files with staged filter=sops")
	cmd.Flags().BoolVar(&onlyUnprotected, "unprotected", false, "show only files without staged filter=sops")
	cmd.MarkFlagsMutuallyExclusive("protected", "unprotected")
	return cmd
}
