package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/spf13/cobra"
)

func newCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "completion", Short: "Generate shell completion code"}
	var show bool
	var profile string
	ps := &cobra.Command{
		Use: "powershell", Short: "Print PowerShell completion code or install it in a profile",
		Args:    cobra.NoArgs,
		Example: "  git-sops completion powershell --show\n  git-sops completion powershell --install $PROFILE",
		RunE: func(cmd *cobra.Command, _ []string) error {
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if show || cmd.Flags().Changed("install") {
				block := profileBlock(exe)
				if show {
					_, err := fmt.Fprintln(out, block)
					return err
				}
				if profile == "" {
					return fmt.Errorf("--install requires a profile path (use --install $PROFILE)")
				}
				added, err := installProfileBlock(profile, block)
				if err != nil {
					return err
				}
				if added {
					_, err = fmt.Fprintf(out, "Installed PowerShell completion in %s. Reload the profile or open a new session.\n", profile)
				} else {
					_, err = fmt.Fprintf(out, "PowerShell completion is already installed in %s.\n", profile)
				}
				return err
			}
			if err := cmd.Root().GenPowerShellCompletionWithDesc(out); err != nil {
				return err
			}
			// Windows PowerShell 5.1 treats Cobra's stderr diagnostics as errors
			// when the caller uses Stop. Limit the override to each tab request.
			_, err = fmt.Fprintf(out, `
Set-Alias -Name gs -Value %[1]s -Scope Global
Register-ArgumentCompleter -Native -CommandName 'gs','git-sops',%[2]s,%[1]s -ScriptBlock {
    $ErrorActionPreference = 'Continue'
    & ${__git_sopsCompleterBlock} @args
}
`,
				psLiteral(exe), psLiteral(filepath.Base(exe)))
			return err
		},
	}
	ps.Flags().BoolVar(&show, "show", false, "print the marked block to add to your profile")
	ps.Flags().StringVar(&profile, "install", "", "add the marked block once to this PowerShell profile (pass $PROFILE)")
	ps.MarkFlagsMutuallyExclusive("show", "install")
	cmd.AddCommand(ps)
	return cmd
}

// Only policy-valued arguments need custom candidates. Cobra discovers the
// commands and flags from the live tree and the shell completes ordinary paths.
func policyCompletion(choices func(*config.Managed) []string) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		repo, err := cmd.Flags().GetString("repo")
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		g, err := gitx.New(repo)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		root, err := gitx.ToplevelOf(g.Exe, repo)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		policy, err := config.ReadManaged(filepath.Join(root, ".sops.yaml"))
		if err != nil || policy == nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var matches []string
		for _, choice := range choices(policy) {
			if strings.HasPrefix(choice, prefix) {
				matches = append(matches, choice)
			}
		}
		return matches, cobra.ShellCompDirectiveNoFileComp
	}
}

var completeGroups = policyCompletion(func(m *config.Managed) []string {
	if m.Groups == nil {
		return []string{config.DefaultGroup}
	}
	return m.GroupNames()
})

var completeProtectedRules = policyCompletion(func(m *config.Managed) []string {
	var rules []string
	for _, rule := range m.ProtectedPaths {
		if strings.IndexFunc(rule, unicode.IsControl) == -1 {
			rules = append(rules, rule)
		}
	}
	return rules
})

var completeRecipients = policyCompletion(func(m *config.Managed) []string {
	keys := append([]string(nil), m.Recipients...)
	for _, members := range m.Groups {
		keys = append(keys, members...)
	}
	keys = config.UniqueRecipients(keys)
	for i, key := range keys {
		if name := m.RecipientNames[key]; name != "" {
			keys[i] = cobra.CompletionWithDesc(key, name)
		}
	}
	return keys
})
