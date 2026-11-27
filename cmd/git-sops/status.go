package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/setup"
	"github.com/lalibi/git-sops/internal/sopsx"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newStatusCommand(o *setup.Options) *cobra.Command {
	var onlyProtected, onlyUnprotected bool
	cmd := &cobra.Command{
		Use: "status [path or glob]...", Short: "List tracked files, protection rules and encryption in the index",
		Long:    "Inspect staged attributes and index blobs without a private key. Optional repository-root-relative files, directories and quoted globs limit the check to matching tracked paths.",
		Example: "  git-sops status secrets/ README.md\n  git-sops status --protected '**/*.env'",
		RunE: func(cmd *cobra.Command, paths []string) error {
			g, err := gitx.New(o.RepoPath)
			if err != nil {
				return err
			}
			root, err := gitx.ToplevelOf(g.Exe, o.RepoPath)
			if err != nil {
				return err
			}
			g.Dir = root
			listArgs := []string{"ls-files", "--stage", "-z"}
			if len(paths) > 0 {
				listArgs = append([]string{"--glob-pathspecs"}, listArgs...)
				listArgs = append(listArgs, "--")
				for _, p := range paths {
					listArgs = append(listArgs, filepath.ToSlash(p))
				}
			}
			entries, err := g.ZList(listArgs...)
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
				if len(paths) > 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "No tracked files match the selected paths.")
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "No tracked files in the index.")
				}
				return nil
			}
			attrs, err := g.FilterAttributes(files, true)
			if err != nil {
				return err
			}
			exe, err := sopsx.Find()
			if err != nil {
				return err
			}
			s := &sopsx.Client{Exe: exe, Dir: root}
			var rows []statusRow
			protectedCount, issues := 0, 0
			for _, path := range files {
				protection, state := "unprotected", "unmerged (!)"
				protected := attrs[path] == "sops"
				if protected {
					protection = "protected"
					protectedCount++
				}
				problem := false
				if unmerged[path] {
					problem = true
				} else if submodules[path] {
					state = "submodule"
					if protected {
						state = "submodule (!)"
						problem = true
					}
				} else if protected || !onlyProtected {
					blob, err := g.Run(nil, "cat-file", "blob", ":"+path)
					if err != nil {
						return err
					}
					encrypted := s.IsEncrypted(path, blob)
					state = "plaintext"
					if encrypted {
						state = "encrypted"
					} else if protected {
						state = "plaintext (!)"
						problem = true
					}
				}
				if problem {
					issues++
				}
				if onlyProtected && !protected || onlyUnprotected && protected {
					continue
				}
				label := path
				if strings.ContainsAny(path, "\t\r\n") {
					label = strconv.Quote(path)
				}
				rows = append(rows, statusRow{label, protection, state})
			}
			if err := renderStatus(cmd.OutOrStdout(), root, rows, len(files), protectedCount, issues, len(paths) > 0); err != nil {
				return err
			}
			if issues > 0 {
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

type statusRow struct{ path, protection, state string }

func renderStatus(out io.Writer, root string, rows []statusRow, tracked, protected, issues int, scoped bool) error {
	// Format before coloring so ANSI escapes never affect column alignment.
	var table bytes.Buffer
	w := tabwriter.NewWriter(&table, 0, 4, 3, ' ', 0)
	fmt.Fprintln(w, "  PATH\tPROTECTION\tINDEX")
	fmt.Fprintln(w, "  ----\t----------\t-----")
	for _, row := range rows {
		fmt.Fprintf(w, "  %s\t%s\t%s\n", row.path, row.protection, row.state)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	r := lipgloss.NewRenderer(out)
	color := out == os.Stdout && term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""
	style := func(s, shade string, bold bool) string {
		if !color {
			return s
		}
		return r.NewStyle().Foreground(lipgloss.Color(shade)).Bold(bold).Render(s)
	}
	var report bytes.Buffer
	fmt.Fprintln(&report, style("git-sops status", "6", true))
	fmt.Fprintln(&report, style(root, "8", false))
	if scoped {
		fmt.Fprintln(&report, "Checking selected paths only.")
	}
	fmt.Fprintf(&report, "\n%d tracked  |  %d protected  |  %d unprotected  |  %d issues\n\n", tracked, protected, tracked-protected, issues)
	lines := strings.Split(strings.TrimSuffix(table.String(), "\n"), "\n")
	for i, line := range lines {
		shade := "8"
		if i >= 2 {
			row := rows[i-2]
			if strings.Contains(row.state, "(!)") {
				shade = "1"
			} else if row.state == "encrypted" {
				shade = "2"
			}
		}
		fmt.Fprintln(&report, style(line, shade, i == 0))
	}
	if len(rows) == 0 {
		fmt.Fprintln(&report, "  No files match this filter.")
	}
	if len(rows) != tracked {
		fmt.Fprintf(&report, "\nShowing %d of %d tracked files; issue count includes hidden files.\n", len(rows), tracked)
	}
	if issues == 0 {
		scope := "the index"
		if scoped {
			scope = "the selected paths"
		}
		if protected == 0 {
			fmt.Fprintln(&report, style("\nNo protected entries in "+scope+".", "8", false))
		} else {
			fmt.Fprintln(&report, style("\nAll protected entries in "+scope+" are encrypted.", "2", false))
		}
	}
	fmt.Fprintln(&report, style("\nIndex only; protected working-tree files normally contain plaintext.", "8", false))
	_, err := out.Write(report.Bytes())
	return err
}
