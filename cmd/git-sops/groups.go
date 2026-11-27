package main

import (
	"github.com/lalibi/git-sops/internal/setup"
	"github.com/spf13/cobra"
)

func newGroupCommand(base *setup.Options) *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "Manage named recipient lists"}
	set := &cobra.Command{Use: "set <name> <age1...>...", Short: "Create or replace a group's complete recipient list", Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			o := *base
			o.Group, o.Recipients = args[0], args[1:]
			return setup.EditAccess(o, "group-set")
		},
	}
	set.Flags().BoolVar(&base.DryRun, "dry-run", false, "show affected rules and files without applying")
	addCommitFlags(set, base)
	cmd.AddCommand(set)
	return cmd
}

func newAccessCommand(base *setup.Options) *cobra.Command {
	return &cobra.Command{Use: "access [age1...]", Short: "List all age recipients or inspect one recipient's access", Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error { return setup.ShowAccess(*base, args...) },
	}
}
