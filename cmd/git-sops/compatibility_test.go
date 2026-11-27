package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/lalibi/git-sops/internal/config"
)

// Exercise the released parser and filters so shared changes to our reader and
// writer cannot make an incompatible format appear to pass a round trip.
func TestReleasedPolicyCompatibility(t *testing.T) {
	for _, tag := range []string{"v0.3.2", "v0.5.1"} {
		t.Run(tag, func(t *testing.T) { checkReleasedPolicyCompatibility(t, tag) })
	}
}

func checkReleasedPolicyCompatibility(t *testing.T, tag string) {
	s := newSandbox(t)
	if r := s.run(".", "git", "rev-parse", "--verify", "refs/tags/"+tag+"^{commit}"); r.code != 0 {
		t.Skip("cross-version test requires the local " + tag + " tag")
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "release")
	root := strings.TrimSpace(s.git(".", "rev-parse", "--show-toplevel"))
	s.git(tmp, "clone", "--no-hardlinks", "--single-branch", "--branch", tag, root, src)
	released := filepath.Join(tmp, filepath.Base(binary))
	if r := s.run(src, "go", "build", "-o", released, "./cmd/git-sops"); r.code != 0 {
		t.Fatalf("build %s: %s", tag, r.out)
	}
	repo := filepath.Join(tmp, "project")
	s.git(tmp, "init", repo)
	old := func(args ...string) {
		t.Helper()
		if r := s.run(repo, released, args...); r.code != 0 {
			t.Fatalf("%s %v failed: %s", tag, args, r.out)
		}
	}
	s, owner := groupMember(t, s, "owner")
	member, key := groupMember(t, s, "member")
	write(t, filepath.Join(repo, "secrets", "token.txt"), textSecret)
	old("init", "--protect", "secrets/", "--recipient", key, "--commit")
	policy := filepath.Join(repo, ".sops.yaml")
	legacy := read(t, policy)
	original := s.git(repo, "rev-parse", "HEAD:secrets/token.txt")
	tree := s.git(repo, "write-tree")
	s.mustGitSops(repo, "check")
	overview := s.mustGitSops(repo, "access")
	for _, recipient := range []string{owner, key} {
		if !strings.Contains(overview, recipient+"  1  default") {
			t.Fatalf("missing released policy recipient in access overview: %s", overview)
		}
	}
	s.mustGitSops(repo, "join")
	s.mustGitSops(repo, "verify")
	s.git(repo, "add", "--renormalize", ".")
	if read(t, policy) != legacy || s.git(repo, "write-tree") != tree || s.git(repo, "status", "--porcelain") != "" {
		t.Fatal("using the new CLI changed the released policy or ciphertext")
	}

	s.mustGitSops(repo, "add-recipient", "--name", "HAL9000", key, "--commit")
	write(t, filepath.Join(repo, "service key.txt"), "shared token\n")
	s.mustGitSops(repo, "protect", "service key.txt", "--group", "default", "--commit")
	if !strings.HasPrefix(read(t, policy), config.SopsMarker+"\n") || !strings.Contains(read(t, policy), "age: *recipients") {
		t.Fatal("explicit default group should keep the shared policy format")
	}
	clone := filepath.Join(tmp, "member")
	member.git(tmp, "clone", repo, clone)
	if r := member.run(clone, released, "join"); r.code != 0 {
		t.Fatalf("released client joining shared policy: %s", r.out)
	}
	if read(t, filepath.Join(clone, "secrets", "token.txt")) != textSecret || read(t, filepath.Join(clone, "service key.txt")) != "shared token\n" {
		t.Fatal("second recipient could not read both protected paths with the released CLI")
	}
	old("join")
	if s.git(repo, "rev-parse", "HEAD:secrets/token.txt") != original {
		t.Fatal("policy migration changed unrelated ciphertext")
	}

	assertEditsRefused := func() {
		t.Helper()
		tree := s.git(repo, "write-tree")
		before := read(t, policy)
		for _, args := range [][]string{{"protect", "extra.txt"}, {"add-recipient", key}, {"remove-recipient", key}} {
			if r := s.run(repo, released, args...); r.code == 0 || !strings.Contains(r.out, ".sops.yaml") {
				t.Fatalf("expected %s %v to refuse the upgraded policy: %s", tag, args, r.out)
			}
		}
		if read(t, policy) != before || s.git(repo, "write-tree") != tree || s.git(repo, "status", "--porcelain") != "" {
			t.Fatal("released policy commands modified the upgraded repository")
		}
	}
	assertEditsRefused()
	s.mustGitSops(repo, "group", "set", "private", owner, "--commit")
	s.mustGitSops(repo, "protect", "third.txt", "--group", "private", "--commit")
	assertEditsRefused()
}
