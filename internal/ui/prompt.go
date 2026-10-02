package ui

import (
	"errors"
	"os"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"
)

// ErrCancelled is returned when the user aborts a prompt (Ctrl+C / Esc).
var ErrCancelled = errors.New("cancelled")

// Interactive reports whether prompts can be shown: both stdin and stdout must be terminals.
func Interactive() bool {
	return outTTY && term.IsTerminal(int(os.Stdin.Fd()))
}

func run(field huh.Field) error {
	err := huh.NewForm(huh.NewGroup(field)).WithTheme(huh.ThemeCharm()).Run()
	if errors.Is(err, huh.ErrUserAborted) {
		return ErrCancelled
	}
	return err
}

// Input asks for a line of text. The caller must check Interactive first.
func Input(title, description, placeholder, initial string, validate func(string) error) (string, error) {
	value := initial

	field := huh.NewInput().
		Title(title).
		Description(description).
		Placeholder(placeholder).
		Value(&value)
	if validate != nil {
		field = field.Validate(validate)
	}

	if err := run(field); err != nil {
		return "", err
	}
	return value, nil
}

// Confirm asks a yes/no question. The caller must check Interactive first.
func Confirm(title, description string, defaultYes bool) (bool, error) {
	answer := defaultYes

	field := huh.NewConfirm().
		Title(title).
		Description(description).
		Affirmative("Yes").
		Negative("No").
		Value(&answer)

	if err := run(field); err != nil {
		return false, err
	}
	return answer, nil
}
