package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptHistoryRequiresApprovalAndPreservesGraph(t *testing.T) {
	s := newSandbox(t)
	repo := filepath.Join(t.TempDir(), "repo")
	s.git(filepath.Dir(repo), "init", "-b", "main", repo)
	write(t, filepath.Join(repo, "old token.txt"), "first secret\r\n")
	write(t, filepath.Join(repo, "README.md"), "public\n")
	write(t, filepath.Join(repo, "src", ".gitattributes"), "*.txt text\n")
	write(t, filepath.Join(repo, "src", "private.txt"), "nested secret\n")
	s.git(repo, "add", ".")
	s.git(repo, "commit", "-m", "plaintext root")
	root := strings.TrimSpace(s.git(repo, "rev-parse", "HEAD"))
	s.git(repo, "tag", "-a", "historical", "-m", "historical tag")
	s.git(repo, "checkout", "-b", "feature")
	write(t, filepath.Join(repo, "feature.txt"), "feature\n")
	s.git(repo, "add", "feature.txt")
	s.git(repo, "commit", "-m", "feature commit")
	s.git(repo, "checkout", "main")
	s.git(repo, "mv", "old token.txt", "token.txt")
	write(t, filepath.Join(repo, "token.txt"), "second secret\n")
	s.git(repo, "add", "token.txt")
	s.git(repo, "commit", "-m", "renamed secret")
	s.git(repo, "merge", "--no-ff", "feature", "-m", "merge feature")
	s.mustGitSops(repo, "init", "--protect", "token.txt")
	s.git(repo, "commit", "-m", "protect tip")
	s.git(repo, "update-ref", "refs/remotes/origin/feature", "feature")
	s.git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/feature")
	oldHead := s.git(repo, "rev-parse", "HEAD")
	count := s.git(repo, "rev-list", "--all", "--count")
	meta := s.git(repo, "log", "--all", "--format=%an <%ae> %at %cn <%ce> %ct %s")
	args := []string{"encrypt-history", "--protect", "old token.txt,src/private.txt"}
	r := s.gitSops(repo, args...)
	if r.code == 0 || !strings.Contains(r.out, "explicit approval required") {
		t.Fatalf("approval was not required: %+v", r)
	}
	if s.git(repo, "rev-parse", "HEAD") != oldHead {
		t.Fatal("unapproved rewrite changed HEAD")
	}
	out := s.mustGitSops(repo, append(args, "--confirm-rewrite")...)
	if !strings.Contains(out, "Recovery bundle") {
		t.Fatal("missing recovery location")
	}
	if s.git(repo, "rev-parse", "HEAD") == oldHead {
		t.Fatal("HEAD was not rewritten")
	}
	if got := s.git(repo, "rev-list", "--all", "--count"); got != count {
		t.Fatalf("commit count changed: %s -> %s", count, got)
	}
	if got := s.git(repo, "log", "--all", "--format=%an <%ae> %at %cn <%ce> %ct %s"); got != meta {
		t.Fatal("commit metadata changed")
	}
	if parents := strings.Fields(s.git(repo, "rev-list", "--parents", "--max-count=1", "HEAD^")); len(parents) != 3 {
		t.Fatalf("merge graph lost: %v", parents)
	}
	if target := strings.TrimSpace(s.git(repo, "symbolic-ref", "refs/remotes/origin/HEAD")); target != "refs/remotes/origin/feature" {
		t.Fatal("symbolic remote ref changed")
	}
	for _, ref := range []string{"main", "feature", "historical", "refs/remotes/origin/feature"} {
		for _, oid := range strings.Fields(s.git(repo, "rev-list", ref)) {
			for _, p := range []string{"old token.txt", "token.txt", "src/private.txt"} {
				blob := s.run(repo, "git", "cat-file", "blob", oid+":"+p)
				if blob.code == 0 && (!strings.Contains(blob.out, "sops") || strings.Contains(blob.out, "secret")) {
					t.Fatalf("plaintext remains at %s:%s", oid, p)
				}
			}
		}
	}
	if got := read(t, filepath.Join(repo, "token.txt")); got != "second secret\n" {
		t.Fatalf("working plaintext changed: %q", got)
	}
	s.mustGitSops(repo, "verify")
	s.git(repo, "add", "--renormalize", ".")
	if status := strings.TrimSpace(s.git(repo, "status", "--porcelain")); status != "" {
		t.Fatalf("working tree dirty after rewrite: %s", status)
	}
	backups, _ := filepath.Glob(filepath.Join(repo, ".git", "git-sops-before-history-*.bundle"))
	if len(backups) != 1 {
		t.Fatalf("expected a recovery bundle: %v", backups)
	}
	if !strings.Contains(s.git(repo, "bundle", "list-heads", backups[0]), strings.TrimSpace(oldHead)) {
		t.Fatal("backup does not retain original HEAD")
	}
	if !strings.Contains(s.git(repo, "cat-file", "blob", root+":old token.txt"), "first secret") {
		t.Fatal("recovery objects unexpectedly pruned")
	}
	// Historical checkouts have the attributes and recipients needed to join.
	clone := filepath.Join(t.TempDir(), "historical-clone")
	s.git(filepath.Dir(clone), "clone", "--no-local", repo, clone)
	s.git(clone, "checkout", "historical")
	s.mustGitSops(clone, "join")
	if got := read(t, filepath.Join(clone, "old token.txt")); got != "first secret\n" && got != "first secret\r\n" {
		t.Fatalf("historical decryption failed: %q", got)
	}
}

func TestEncryptHistoryFailureLeavesSourceUntouched(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")
	write(t, filepath.Join(repo, "bad.json"), "not valid JSON")
	s.git(repo, "add", "bad.json")
	s.git(repo, "commit", "-m", "invalid historical json")
	head := s.git(repo, "rev-parse", "HEAD")
	index := s.git(repo, "write-tree")
	policy := read(t, filepath.Join(repo, ".sops.yaml"))
	r := s.gitSops(repo, "encrypt-history", "--protect", "bad.json", "--confirm-rewrite")
	if r.code == 0 {
		t.Fatal("invalid historical JSON should fail")
	}
	if s.git(repo, "rev-parse", "HEAD") != head || s.git(repo, "write-tree") != index || read(t, filepath.Join(repo, ".sops.yaml")) != policy {
		t.Fatal("failed preparation changed source repository")
	}
	if _, err := os.Stat(filepath.Join(repo, "bad.json")); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptHistoryDetachedHead(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")
	s.git(repo, "checkout", "--detach", "HEAD")
	write(t, filepath.Join(repo, "README.md"), "detached change\n")
	s.git(repo, "add", "README.md")
	s.git(repo, "commit", "-m", "detached commit")
	head := s.git(repo, "rev-parse", "HEAD")
	s.mustGitSops(repo, "encrypt-history", "--confirm-rewrite")
	if s.git(repo, "rev-parse", "HEAD") == head {
		t.Fatal("detached HEAD was not rewritten")
	}
	if s.run(repo, "git", "symbolic-ref", "-q", "HEAD").code == 0 {
		t.Fatal("rewrite attached HEAD to a branch")
	}
	if s.git(repo, "rev-parse", "HEAD^") != s.git(repo, "rev-parse", "main") {
		t.Fatal("detached ancestry was not preserved")
	}
	if status := strings.TrimSpace(s.git(repo, "status", "--porcelain")); status != "" {
		t.Fatalf("detached working tree dirty: %s", status)
	}
}

func TestEncryptHistoryRollsBackAfterFinalValidationFailure(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")
	head := s.git(repo, "rev-parse", "HEAD")
	index := s.git(repo, "write-tree")
	attrs := read(t, filepath.Join(repo, ".gitattributes"))
	policy := read(t, filepath.Join(repo, ".sops.yaml"))
	s.git(repo, "config", "hook.reject.command", "git rev-parse --verify refs/heads/a-branch-that-does-not-exist")
	s.git(repo, "config", "hook.reject.event", "pre-commit")
	r := s.gitSops(repo, "encrypt-history", "--confirm-rewrite")
	if r.code == 0 || !strings.Contains(r.out, "recovery bundle") {
		t.Fatalf("expected final validation failure: %+v", r)
	}
	if s.git(repo, "rev-parse", "HEAD") != head || s.git(repo, "write-tree") != index {
		t.Fatal("source refs or index were not restored")
	}
	if read(t, filepath.Join(repo, ".gitattributes")) != attrs || read(t, filepath.Join(repo, ".sops.yaml")) != policy {
		t.Fatal("policy was not restored")
	}
	if status := strings.TrimSpace(s.git(repo, "status", "--porcelain")); status != "" {
		t.Fatalf("rollback left dirty files: %s", status)
	}
}
