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
	if got := reader.mustGitSops(repo, "status", "README.md"); !strings.Contains(got, "1 tracked") || strings.Contains(got, "token.txt") {
		t.Fatalf("out-of-scope issue affected a single-file check: %s", got)
	}
	if r := reader.gitSops(repo, "status", "--unprotected", "secrets/"); r.code != 1 || !strings.Contains(r.out, "1 issues") {
		t.Fatalf("scoped check missed an issue hidden by the display filter: %+v", r)
	}
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

func TestStatusPathSelection(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	for _, name := range []string{".env", "app/prod.env", "app/nested/service.env", "app/prod.env.example", "untracked.env"} {
		write(t, filepath.Join(repo, name), "SETTING=example\n")
	}
	s.git(repo, "add", "--", ".env", "app")
	for _, tc := range []struct {
		args       []string
		count      string
		want, omit []string
	}{
		{[]string{"**/*.env"}, "3 tracked", []string{"  .env ", "app/prod.env", "app/nested/service.env"}, []string{"untracked.env", ".env.example", "README.md"}},
		{[]string{"*.env"}, "1 tracked", []string{"  .env "}, []string{"app/prod.env", "app/nested/service.env"}},
		{[]string{"app/*.env", "secrets/", "app/prod.env"}, "3 tracked", []string{"app/prod.env", "secrets/db.json", "secrets/token.txt"}, []string{"app/nested/service.env", "README.md"}},
		{[]string{"--protected", "secrets", ".env"}, "3 tracked", []string{"secrets/db.json", "Showing 2 of 3"}, []string{"  .env "}},
		{[]string{"missing/**/*.env"}, "No tracked files match", nil, []string{"README.md"}},
	} {
		out := s.mustGitSops(filepath.Join(repo, "app"), append([]string{"status"}, tc.args...)...)
		for _, want := range append(tc.want, tc.count) {
			if !strings.Contains(out, want) {
				t.Errorf("%v missing %q in %s", tc.args, want, out)
			}
		}
		for _, omit := range tc.omit {
			if strings.Contains(out, omit) {
				t.Errorf("%v included %q in %s", tc.args, omit, out)
			}
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
