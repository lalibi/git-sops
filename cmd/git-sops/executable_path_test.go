package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfiguredExecutableSurvivesDifferentGitClientPath(t *testing.T) {
	s := newSandbox(t)
	originalPath := os.Getenv("PATH")
	setPath := func(value string) {
		var env []string
		for _, entry := range s.env {
			key, _, _ := strings.Cut(entry, "=")
			if !strings.EqualFold(key, "PATH") {
				env = append(env, entry)
			}
		}
		s.env = append(env, "PATH="+value)
	}
	// The executable is discoverable when setup runs, as in a developer terminal.
	setPath(filepath.Dir(binary) + string(os.PathListSeparator) + originalPath)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")
	executable, err := filepath.EvalSymlinks(binary)
	if err != nil {
		executable = binary // Match setup's fallback when symlink resolution is unavailable.
	}
	prefix := "'" + filepath.ToSlash(executable) + "'"
	keys := []string{"filter.sops.clean", "filter.sops.smudge", "diff.sops.textconv", "merge.sops.driver", "hook.sops-index.command"}
	assertPinned := func() {
		t.Helper()
		for _, key := range keys {
			if value := s.git(repo, "config", "--local", "--get", key); !strings.HasPrefix(value, prefix+" ") {
				t.Fatalf("%s does not pin the executable: %q", key, value)
			}
		}
	}
	assertPinned()
	// A GUI launched elsewhere does not inherit that addition to PATH.
	setPath(originalPath)
	write(t, filepath.Join(repo, "secrets", "token.txt"), "discard this edit\n")
	s.git(repo, "reset", "--hard", "HEAD")
	if got := read(t, filepath.Join(repo, "secrets", "token.txt")); got != textSecret {
		t.Fatalf("reset failed to decrypt the committed file: %q", got)
	}
	s.git(repo, "hook", "run", "pre-commit")
	// join must repair old bare-name configurations, too.
	for _, key := range keys {
		value := strings.TrimSpace(s.git(repo, "config", "--local", "--get", key))
		s.git(repo, "config", "--local", key, "git-sops"+strings.TrimPrefix(value, prefix))
	}
	s.mustGitSops(repo, "join")
	assertPinned()
	write(t, filepath.Join(repo, "secrets", "token.txt"), "discard another edit\n")
	s.git(repo, "reset", "--hard", "HEAD")
	if status := strings.TrimSpace(s.git(repo, "status", "--porcelain")); status != "" {
		t.Fatalf("reset left a dirty working tree: %s", status)
	}
}
