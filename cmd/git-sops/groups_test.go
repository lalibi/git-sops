package main

import (
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func groupMember(t *testing.T, s *sandbox, name string) (*sandbox, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	member := s.as(name)
	write(t, member.keyFile, id.String()+"\n")
	return member, id.Recipient().String()
}

func TestAccessListsAllRecipients(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "shared policy")
	policy := filepath.Join(repo, ".sops.yaml")
	shared := read(t, policy)
	owner := recipientIn(t, shared)
	_, pending := groupMember(t, s, "pending")
	observer := s.as("no-identity")
	tree := s.git(repo, "write-tree")
	for _, tc := range []struct {
		name, policy string
		want         []string
	}{
		{"shared", shared, []string{owner + "  2  default"}},
		{"pending policy change", strings.ReplaceAll(shared, owner, pending), []string{owner + "  2  (index only)", pending + "  0  default", "staged recipients differ"}},
		{"custom", strings.TrimPrefix(shared, "# Managed by git-sops\n"), []string{owner + "  2  (index only)", "staged filter=sops files only"}},
	} {
		write(t, policy, tc.policy)
		out := observer.mustGitSops(repo, "access")
		for _, want := range tc.want {
			if !strings.Contains(out, want) {
				t.Fatalf("%s: missing %q in %s", tc.name, want, out)
			}
		}
		if read(t, policy) != tc.policy || s.git(repo, "write-tree") != tree {
			t.Fatalf("%s: access changed the working policy or index", tc.name)
		}
	}
}

func TestRecipientName(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "initialize")
	_, key := groupMember(t, s, "collaborator")
	policy := filepath.Join(repo, ".sops.yaml")
	owner := recipientIn(t, read(t, policy))
	if r := s.gitSops(repo, "add-recipient", "--name", "Ambiguous", owner, key); r.code == 0 {
		t.Fatal("accepted a single name for two recipients")
	}
	if r := s.gitSops(repo, "add-recipient", "--name", "two\nlines", key); r.code == 0 {
		t.Fatal("accepted a multiline name")
	}
	s.mustGitSops(repo, "add-recipient", "--name", "Alex Morgan", key, "--commit")
	for _, args := range [][]string{{"access"}, {"access", key}} {
		out := s.mustGitSops(repo, args...)
		if !strings.Contains(out, key) || !strings.Contains(out, "Alex Morgan") {
			t.Fatal("recipient name or key missing from access output")
		}
	}
	s.mustGitSops(repo, "init")
	before := s.git(repo, "rev-parse", ":secrets/token.txt")
	s.mustGitSops(repo, "add-recipient", "--name", "Alex #2", key, "--commit")
	if after := s.git(repo, "rev-parse", ":secrets/token.txt"); after != before {
		t.Fatal("renaming a recipient changed ciphertext")
	}
	s.mustGitSops(repo, "group", "set", "ops", owner, "--commit")
	s.mustGitSops(repo, "add-recipient", "--group", "ops", "--name", "Operations", key, "--dry-run")
	if !strings.Contains(read(t, policy), "Alex #2") {
		t.Fatal("preview changed the name or conversion lost it")
	}
	s.mustGitSops(repo, "add-recipient", "--group", "ops", "--name", "Operations", key, "--commit")
	s.mustGitSops(repo, "remove-recipient", "--group", "ops", key, "--commit")
	if !strings.Contains(s.mustGitSops(repo, "access", key), "Operations") {
		t.Fatal("remaining group lost the name")
	}
	s.mustGitSops(repo, "remove-recipient", "--everywhere", key, "--commit")
	if strings.Contains(read(t, policy), key) {
		t.Fatal("removed recipient or its name remains")
	}
}

func TestRecipientGroups(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "shared policy")
	owner := recipientIn(t, read(t, filepath.Join(repo, ".sops.yaml")))
	bob, b := groupMember(t, s, "bob")
	alice, a := groupMember(t, s, "alice")
	s.mustGitSops(repo, "add-recipient", b, "--commit")
	s.mustGitSops(repo, "group", "set", "database", owner, a, "--commit")
	index := s.git(repo, "write-tree")
	preview := s.mustGitSops(repo, "protect", "secrets/db.json", "--group", "database", "--dry-run")
	if !strings.Contains(preview, "Re-encrypt secrets/db.json") || strings.Contains(preview, "Re-encrypt secrets/token.txt") || s.git(repo, "write-tree") != index {
		t.Fatalf("bad assignment preview: %s", preview)
	}
	parentBlob := s.git(repo, "rev-parse", ":secrets/token.txt")
	s.mustGitSops(repo, "protect", "secrets/db.json", "--group", "database", "--commit")
	if parentBlob != s.git(repo, "rev-parse", ":secrets/token.txt") {
		t.Fatal("assignment rekeyed an unaffected sibling")
	}
	if policy := read(t, filepath.Join(repo, ".sops.yaml")); !strings.HasPrefix(policy, "# Managed by git-sops (recipient groups v1)\n") || strings.Index(policy, "age: *database") > strings.Index(policy, "age: *default") {
		t.Fatalf("invalid grouped policy: %s", policy)
	}
	access := s.mustGitSops(repo, "access", b)
	if !strings.Contains(access, "secrets/token.txt") || strings.Contains(access, "secrets/db.json") {
		t.Fatalf("incorrect effective access: %s", access)
	}
	overview := s.mustGitSops(repo, "access")
	for _, want := range []string{owner + "  2  database, default", b + "  1  default", a + "  1  database"} {
		if !strings.Contains(overview, want) {
			t.Fatalf("missing %q in overview: %s", want, overview)
		}
	}
	clone := func(member *sandbox, name string) string {
		dir := filepath.Join(t.TempDir(), name)
		member.git(filepath.Dir(dir), "clone", repo, dir)
		member.mustGitSops(dir, "join")
		return dir
	}
	bobRepo := clone(bob, "bob")
	aliceRepo := clone(alice, "alice")
	assertLocked := func(member *sandbox, dir, path string) {
		t.Helper()
		blob := member.git(dir, "cat-file", "blob", ":"+path)
		if !strings.Contains(blob, "sops") || read(t, filepath.Join(dir, path)) != blob {
			t.Fatalf("%s should remain ciphertext", path)
		}
		if r := member.gitSops(dir, "decrypt", path); r.code == 0 {
			t.Fatalf("excluded identity decrypted %s", path)
		}
	}
	assertLocked(bob, bobRepo, "secrets/db.json")
	assertLocked(alice, aliceRepo, "secrets/token.txt")
	if read(t, filepath.Join(bobRepo, "secrets/token.txt")) != textSecret || !strings.Contains(read(t, filepath.Join(aliceRepo, "secrets/db.json")), "hunter2") {
		t.Fatal("authorized working copies should be decrypted")
	}
	bob.git(bobRepo, "add", "-A")
	bob.git(bobRepo, "rm", "--cached", "--", "secrets/db.json")
	bob.git(bobRepo, "add", "--", "secrets/db.json")
	if st := bob.git(bobRepo, "status", "--porcelain"); st != "" {
		t.Fatalf("partial checkout is dirty: %s", st)
	}
	before := bob.git(bobRepo, "write-tree")
	if r := bob.gitSops(bobRepo, "add-recipient", "--group", "database", b); r.code == 0 || bob.git(bobRepo, "write-tree") != before || bob.git(bobRepo, "status", "--porcelain") != "" {
		t.Fatalf("expected failed, rolled-back rekey: %+v", r)
	}
	s.mustGitSops(repo, "add-recipient", "--group", "database", b, "--commit")
	bob.git(bobRepo, "pull", "--ff-only")
	if !strings.Contains(read(t, filepath.Join(bobRepo, "secrets/db.json")), "hunter2") {
		t.Fatal("newly authorized member could not read the database")
	}
	s.mustGitSops(repo, "remove-recipient", "--everywhere", b, "--commit")
	bob.git(bobRepo, "pull", "--ff-only")
	assertLocked(bob, bobRepo, "secrets/db.json")
	assertLocked(bob, bobRepo, "secrets/token.txt")
	if out := s.mustGitSops(repo, "access", b); !strings.Contains(out, "0 accessible tracked file(s)") {
		t.Fatalf("offboarding left access: %s", out)
	}
	s.mustGitSops(repo, "group", "set", "database", owner, "--commit")
	before = s.git(repo, "write-tree")
	if r := s.gitSops(repo, "remove-recipient", "--everywhere", owner); r.code == 0 || !strings.Contains(r.out, "no recipients") || s.git(repo, "write-tree") != before {
		t.Fatalf("last recipient removal: %+v", r)
	}
}

func TestGroupHandoffAndStagedRecipientValidation(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	for p, content := range map[string]string{"secrets/private.ini": "[service]\nkey=one\n", "secrets/service.env": "KEY=two\n", "secrets/multi.yaml": "key: three\n---\nkey: four\n"} {
		write(t, filepath.Join(repo, p), content)
	}
	s.git(repo, "add", "secrets/")
	s.git(repo, "commit", "-m", "old shared files")
	old := strings.TrimSpace(s.git(repo, "rev-parse", ":secrets/private.ini"))
	other, key := groupMember(t, s, "handoff")
	s.mustGitSops(repo, "group", "set", "handoff", key, "--commit")
	write(t, filepath.Join(repo, "outside.env"), "TOKEN=fresh\n")
	s.mustGitSops(repo, "protect", "--group", "handoff", "secrets/private.ini", "outside.env", "--commit")
	if got := read(t, filepath.Join(repo, "outside.env")); got != s.git(repo, "cat-file", "blob", ":outside.env") {
		t.Fatal("newly protected file should be locked for the excluded maintainer")
	}
	if got := read(t, filepath.Join(repo, "secrets/private.ini")); got != s.git(repo, "cat-file", "blob", ":secrets/private.ini") {
		t.Fatal("handoff should leave ciphertext for the excluded maintainer")
	}
	if r := s.gitSops(repo, "decrypt", "secrets/private.ini"); r.code == 0 {
		t.Fatal("former recipient can still decrypt")
	}
	if got := other.mustGitSops(repo, "decrypt", "secrets/private.ini"); !strings.Contains(got, "one") {
		t.Fatal("new recipient could not decrypt")
	}
	s.git(repo, "update-index", "--cacheinfo", "100644,"+old+",secrets/private.ini")
	if out := s.mustGitSops(repo, "access", key); !strings.Contains(out, "staged recipients differ") || !strings.Contains(out, "1 accessible tracked file(s)") {
		t.Fatalf("access audit should use actual staged recipients: %s", out)
	}
	if r := s.gitSops(repo, "verify"); r.code == 0 || !strings.Contains(r.out, "recipients differ") {
		t.Fatalf("stale recipients passed index validation: %+v", r)
	}
}
