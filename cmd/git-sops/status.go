package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
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
			var rows []statusRow
			protectedCount, issues := 0, 0
			for _, path := range files {
				protection, state := "unprotected", "unmerged (!)"
				if protected[path] {
					protection = "protected"
					protectedCount++
				}
				problem := false
				if unmerged[path] {
					problem = true
				} else if submodules[path] {
					state = "submodule"
					if protected[path] {
						state = "submodule (!)"
						problem = true
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
						problem = true
					}
				}
				if problem {
					issues++
				}
				if onlyProtected && !protected[path] || onlyUnprotected && protected[path] {
					continue
				}
				label := path
				if strings.ContainsAny(path, "\t\r\n") {
					label = strconv.Quote(path)
				}
				rows = append(rows, statusRow{label, protection, state})
			}
			if err := renderStatus(cmd.OutOrStdout(), root, rows, len(files), protectedCount, issues); err != nil {
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

func renderStatus(out io.Writer, root string, rows []statusRow, tracked, protected, issues int) error {
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
	if protected == 0 && issues == 0 {
		fmt.Fprintln(&report, style("\nNo protected entries in the index.", "8", false))
	} else if issues == 0 {
		fmt.Fprintln(&report, style("\nAll protected index entries are encrypted.", "2", false))
	}
	fmt.Fprintln(&report, style("\nIndex only; protected working-tree files normally contain plaintext.", "8", false))
	_, err := out.Write(report.Bytes())
	return err
}
