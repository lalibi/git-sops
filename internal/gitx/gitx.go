// Package gitx runs the git executable and exposes the few helpers git-sops needs.
package gitx

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// MinimumVersion is required for config-based hooks (hook.<name>.command).
var MinimumVersion = [3]int{2, 55, 0}

type Git struct {
	Exe string
	// Dir is the working directory for every invocation; empty means the current directory.
	Dir string
}

type ExitError struct {
	Args   []string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		return fmt.Sprintf("git %s failed with exit code %d", strings.Join(e.Args, " "), e.Code)
	}
	return fmt.Sprintf("git %s failed: %s", strings.Join(e.Args, " "), msg)
}

func New(dir string) (*Git, error) {
	exe, err := exec.LookPath("git")
	if err != nil {
		return nil, errors.New("git was not found on PATH")
	}
	return &Git{Exe: exe, Dir: dir}, nil
}

// Run executes git with optional stdin and returns raw stdout.
func (g *Git) Run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(g.Exe, args...)
	cmd.Dir = g.Dir

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout.Bytes(), &ExitError{Args: args, Code: exitErr.ExitCode(), Stderr: stderr.String()}
		}
		return nil, err
	}

	return stdout.Bytes(), nil
}

// Output runs git and returns trimmed stdout.
func (g *Git) Output(args ...string) (string, error) {
	out, err := g.Run(nil, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Passthrough runs git with stdout/stderr attached to this process and returns its exit error, if any.
func (g *Git) Passthrough(args ...string) error {
	cmd := exec.Command(g.Exe, args...)
	cmd.Dir = g.Dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &ExitError{Args: args, Code: exitErr.ExitCode()}
		}
		return err
	}
	return nil
}

// ZList runs git and splits its NUL-delimited stdout into entries.
func (g *Git) ZList(args ...string) ([]string, error) {
	out, err := g.Run(nil, args...)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, part := range strings.Split(string(out), "\x00") {
		if part != "" {
			result = append(result, part)
		}
	}
	return result, nil
}

var versionPattern = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

func (g *Git) Version() ([3]int, error) {
	out, err := g.Output("--version")
	if err != nil {
		return [3]int{}, err
	}

	m := versionPattern.FindStringSubmatch(out)
	if m == nil {
		return [3]int{}, fmt.Errorf("could not parse git version from %q", out)
	}

	var v [3]int
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			v[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return v, nil
}

func VersionAtLeast(have, want [3]int) bool {
	for i := 0; i < 3; i++ {
		if have[i] != want[i] {
			return have[i] > want[i]
		}
	}
	return true
}

func FormatVersion(v [3]int) string {
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}

// ToplevelOf resolves the working-tree root containing path.
func ToplevelOf(exe, path string) (string, error) {
	cmd := exec.Command(exe, "-C", path, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("'%s' is not inside a Git working tree", path)
	}
	return strings.TrimSpace(string(out)), nil
}
