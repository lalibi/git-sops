// Package ui renders git-sops terminal output: colors, status lines, spinners, progress bars and prompts.
// Everything degrades to plain, greppable text when stdout is not a terminal or NO_COLOR is set.
package ui

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

var (
	outRenderer = lipgloss.NewRenderer(os.Stdout)
	errRenderer = lipgloss.NewRenderer(os.Stderr)

	outTTY = term.IsTerminal(int(os.Stdout.Fd()))
	errTTY = term.IsTerminal(int(os.Stderr.Fd()))

	// Guards writes so a live spinner or progress line is never interleaved with other output.
	mu  sync.Mutex
	cur *live

	lastBlank bool
)

// ANSI palette indexes follow the user's terminal theme.
const (
	colorRed    = "1"
	colorGreen  = "2"
	colorYellow = "3"
	colorBlue   = "4"
	colorCyan   = "6"
	colorDim    = "8"
)

func paint(r *lipgloss.Renderer, color string, s string) string {
	return r.NewStyle().Foreground(lipgloss.Color(color)).Render(s)
}

func bold(r *lipgloss.Renderer, s string) string {
	return r.NewStyle().Bold(true).Render(s)
}

// fancy reports whether glyphs, colors and live lines should be used on stdout.
func fancy() bool { return outTTY }

// unicodeOK is false on legacy Windows consoles whose fonts lack the glyphs.
func unicodeOK() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	return os.Getenv("WT_SESSION") != "" || os.Getenv("TERM_PROGRAM") != "" || os.Getenv("ConEmuANSI") == "ON"
}

type glyphs struct{ ok, warn, fail, info, bullet string }

func glyphSet() glyphs {
	if unicodeOK() {
		return glyphs{ok: "✓", warn: "▲", fail: "✗", info: "›", bullet: "•"}
	}
	return glyphs{ok: "+", warn: "!", fail: "x", info: ">", bullet: "-"}
}

func emit(w io.Writer, line string) {
	mu.Lock()
	defer mu.Unlock()

	// Collapse consecutive blank lines so headers and sections never stack gaps.
	if line == "" && lastBlank {
		return
	}
	lastBlank = line == ""

	if cur != nil {
		fmt.Fprint(os.Stdout, "\r\x1b[2K")
	}
	fmt.Fprintln(w, line)
	if cur != nil {
		drawLocked()
	}
}

func Infof(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !fancy() {
		emit(os.Stdout, "[INFO] "+msg)
		return
	}
	emit(os.Stdout, paint(outRenderer, colorCyan, glyphSet().info)+" "+msg)
}

func Okf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !fancy() {
		emit(os.Stdout, "[ OK ] "+msg)
		return
	}
	emit(os.Stdout, paint(outRenderer, colorGreen, glyphSet().ok)+" "+msg)
}

func Warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !errTTY {
		emit(os.Stderr, "[WARN] "+msg)
		return
	}
	emit(os.Stderr, paint(errRenderer, colorYellow, glyphSet().warn)+" "+msg)
}

// Fail prints an error to stderr; non-terminal output keeps the "git-sops: " prefix tools expect.
func Fail(err error) {
	if !errTTY {
		emit(os.Stderr, "git-sops: "+err.Error())
		return
	}
	emit(os.Stderr, paint(errRenderer, colorRed, glyphSet().fail)+" "+err.Error())
}

func Printf(format string, args ...any) {
	emit(os.Stdout, fmt.Sprintf(format, args...))
}

func Dim(s string) string { return paint(outRenderer, colorDim, s) }

// Code styles a command or value inside running text.
func Code(s string) string { return paint(outRenderer, colorCyan, s) }

// Header opens a command's output with its name and the repository it operates on.
func Header(command, repo string) {
	if !fancy() {
		if repo != "" {
			Infof("Repository: %s", repo)
		}
		return
	}

	line := bold(outRenderer, "git-sops "+command)
	if repo != "" {
		line += "  " + Dim(repo)
	}
	emit(os.Stdout, "")
	emit(os.Stdout, line)
	emit(os.Stdout, "")
}

// Section starts a titled group of lines.
func Section(title string) {
	emit(os.Stdout, "")
	if !fancy() {
		emit(os.Stdout, title)
		return
	}
	emit(os.Stdout, bold(outRenderer, title))
}

type Status int

const (
	StatusOK Status = iota
	StatusWarn
	StatusFail
	StatusInfo
)

// Row prints one labelled check result, with optional detail lines underneath.
func Row(status Status, label, value string, details ...string) {
	if !fancy() {
		tag := map[Status]string{StatusOK: "[ OK ]", StatusWarn: "[WARN]", StatusFail: "[FAIL]", StatusInfo: "[INFO]"}[status]
		emit(os.Stdout, fmt.Sprintf("%s %s: %s", tag, label, value))
		for _, d := range details {
			emit(os.Stdout, "       "+d)
		}
		return
	}

	g := glyphSet()
	var mark string
	switch status {
	case StatusOK:
		mark = paint(outRenderer, colorGreen, g.ok)
	case StatusWarn:
		mark = paint(outRenderer, colorYellow, g.warn)
	case StatusFail:
		mark = paint(outRenderer, colorRed, g.fail)
	default:
		mark = paint(outRenderer, colorBlue, g.bullet)
	}

	emit(os.Stdout, fmt.Sprintf("  %s %-18s %s", mark, label, value))
	for _, d := range details {
		emit(os.Stdout, fmt.Sprintf("    %-18s %s", "", Dim(d)))
	}
}

// Box prints a bordered call-out for information the user must not miss.
func Box(title string, lines ...string) {
	emit(os.Stdout, "")

	if !fancy() {
		emit(os.Stdout, title)
		for _, l := range lines {
			emit(os.Stdout, "  "+l)
		}
		return
	}

	body := bold(outRenderer, title) + "\n\n" + strings.Join(lines, "\n")
	box := outRenderer.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(colorCyan)).
		Padding(0, 2)

	emit(os.Stdout, box.Render(body))
}
