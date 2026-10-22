package setup

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/lalibi/git-sops/internal/config"
	"github.com/lalibi/git-sops/internal/gitx"
	"github.com/lalibi/git-sops/internal/ui"
)

func validateCommitOptions(o Options) error {
	if o.Commit && o.NoStage {
		return errors.New("--commit cannot be combined with --no-stage")
	}
	if o.Message != "" {
		if !o.Commit {
			return errors.New("--message requires --commit")
		}
		if strings.TrimSpace(o.Message) == "" {
			return errors.New("--message must not be empty")
		}
	}
	return nil
}

func recipientDifference(a, b []string) []string {
	var out []string
	for _, r := range a {
		if !slices.Contains(b, r) {
			out = append(out, r)
		}
	}
	return out
}

func generatedCommitMessage(command string, specs []config.Spec, recipients []string) string {
	titles := map[string]string{
		"init":              "🔐 Configure transparent file encryption",
		"protect":           "🔐 Protect additional paths",
		"unprotect":         "🔓 Remove file protection",
		"add-recipient":     "🔑 Add encryption recipients",
		"remove-recipient":  "🔑 Remove encryption recipients",
		"migrate-git-crypt": "🔐 Migrate git-crypt protection to SOPS",
	}
	var body strings.Builder
	fmt.Fprintf(&body, "chore(git-sops): %s\n\n", titles[command])
	pathsLabel := "Protect the following paths:"
	switch command {
	case "unprotect":
		pathsLabel = "Remove protection from the following paths:"
	case "add-recipient", "remove-recipient":
		label := "Add the following public age recipients:"
		if command == "remove-recipient" {
			label = "Remove the following public age recipients:"
		}
		body.WriteString(label + "\n")
		for _, r := range recipients {
			fmt.Fprintf(&body, "- %s\n", r)
		}
		body.WriteString("\n")
		pathsLabel = "Re-encrypt the following protected paths:"
	}
	paths := specPaths(specs)
	if len(paths) == 0 {
		body.WriteString("No paths are protected.\n")
	} else {
		body.WriteString(pathsLabel + "\n")
		for _, path := range paths {
			fmt.Fprintf(&body, "- %s\n", path)
		}
	}
	return body.String()
}

// Commit outside staging transactions: failed hooks or signing leave the prepared
// changes available for review and a normal retry of git commit.
func commitChanges(e *Env, o Options, command string, specs []config.Spec, recipients []string) error {
	if !o.Commit {
		return nil
	}
	_, err := e.Git.Run(nil, "diff", "--cached", "--quiet", "--exit-code")
	if err == nil {
		ui.Okf("No staged changes; nothing to commit.")
		return nil
	}
	var gitErr *gitx.ExitError
	if !errors.As(err, &gitErr) || gitErr.Code != 1 {
		return err
	}
	message := o.Message
	if message == "" {
		message = generatedCommitMessage(command, specs, recipients)
	}
	file, err := os.CreateTemp("", "git-sops-commit-*.txt")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.WriteString(message)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := e.Git.Passthrough("commit", "--file", file.Name()); err != nil {
		return fmt.Errorf("Git commit failed; prepared changes remain staged for review and retry: %w", err)
	}
	return nil
}

func reviewChanges(o Options) string {
	if o.Commit {
		return "Review with " + ui.Code("git show") + " and " + ui.Code("git status") + " before pushing."
	}
	return "Review with " + ui.Code("git status") + " and " + ui.Code("git diff --cached") + ", then commit."
}
