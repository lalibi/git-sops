package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusInspectsIndexWithoutChangingFiles(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	before := s.git(repo, "write-tree")
	plain := read(t, filepath.Join(repo, "secrets", "token.txt"))
	// No usable private key: metadata inspection must still work.
	reader := s.as("no-key")
	out := reader.mustGitSops(repo, "status")
	for _, want := range []string{"README.md", "unprotected", "plaintext", "secrets/token.txt", "protected", "encrypted"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	out = reader.mustGitSops(repo, "status", "--protected")
	if strings.Contains(out, "README.md") || !strings.Contains(out, "secrets/token.txt") {
		t.Fatal(out)
	}
	out = reader.mustGitSops(repo, "status", "--unprotected")
	if !strings.Contains(out, "README.md") || strings.Contains(out, "secrets/token.txt") {
		t.Fatal(out)
	}
	if before != s.git(repo, "write-tree") || plain != read(t, filepath.Join(repo, "secrets", "token.txt")) {
		t.Fatal("status mutated repository")
	}
	if r := s.gitSops(repo, "status", "--protected", "--unprotected"); r.code == 0 {
		t.Fatal("accepted incompatible flags")
	}

	// Bypass clean deliberately, reproducing accidentally staged plaintext.
	hash := strings.TrimSpace(s.git(repo, "hash-object", "-w", "--no-filters", "secrets/token.txt"))
	s.git(repo, "update-index", "--cacheinfo", "100644,"+hash+",secrets/token.txt")
	// Unstaged attributes must not conceal the staged protection rule.
	write(t, filepath.Join(repo, ".gitattributes"), "")
	for _, args := range [][]string{{"status"}, {"status", "--unprotected"}} {
		r := reader.gitSops(repo, args...)
		if r.code != 1 {
			t.Fatalf("expected failure for plaintext: %+v", r)
		}
		if len(args) == 1 && !strings.Contains(r.out, "plaintext (!)") {
			t.Fatal(r.out)
		}
	}
}

func TestStatusEmptyIndex(t *testing.T) {
	s := newSandbox(t)
	repo := t.TempDir()
	s.git(repo, "init")
	if out := s.mustGitSops(repo, "status"); !strings.Contains(out, "No tracked files") {
		t.Fatal(out)
	}
}
