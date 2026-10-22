package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectAndUnprotectCompleteRules(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")
	write(t, filepath.Join(repo, "settings.txt"), "settings token\n")
	write(t, filepath.Join(repo, "public.txt"), "public defaults\n")
	s.git(repo, "add", "settings.txt", "public.txt")
	s.git(repo, "commit", "-m", "settings initially plaintext")
	s.mustGitSops(repo, "protect", "--protect", "settings.txt,public.txt")
	for _, p := range []string{"settings.txt", "public.txt", "secrets/token.txt"} {
		if !strings.Contains(s.git(repo, "cat-file", "blob", ":"+p), "sops") {
			t.Fatalf("%s was not protected", p)
		}
	}
	s.git(repo, "commit", "-m", "extend protection")
	before := read(t, filepath.Join(repo, ".sops.yaml"))
	index := s.git(repo, "write-tree")
	r := s.gitSops(repo, "unprotect", "secrets/token.txt")
	if r.code != 0 || !strings.Contains(r.out, "Skipping") || !strings.Contains(r.out, "remains protected") {
		t.Fatalf("nested removal should only warn: %+v", r)
	}
	if read(t, filepath.Join(repo, ".sops.yaml")) != before || s.git(repo, "write-tree") != index {
		t.Fatal("rejected removal changed policy or index")
	}
	s.mustGitSops(repo, "unprotect", "secrets/token.txt", "settings.txt")
	if got := s.git(repo, "cat-file", "blob", ":settings.txt"); got != "settings token\n" {
		t.Fatalf("unprotected index = %q", got)
	}
	if !strings.Contains(s.git(repo, "cat-file", "blob", "HEAD:settings.txt"), "sops") {
		t.Fatal("unprotect changed history")
	}
	s.git(repo, "commit", "-m", "publish settings")
	s.mustGitSops(repo, "unprotect", "--protect", "secrets/,public.txt")
	s.mustGitSops(repo, "verify")
	s.git(repo, "commit", "-m", "remove final rules")
	// Rerunning init must preserve a deliberately empty protection set.
	s.mustGitSops(repo, "init")
	if attr := s.git(repo, "check-attr", "filter", "--", "secrets/token.txt"); strings.Contains(attr, ": sops") {
		t.Fatal("init reintroduced a removed rule")
	}
	if status := strings.TrimSpace(s.git(repo, "status", "--porcelain")); status != "" {
		t.Fatalf("init changed empty policy: %s", status)
	}
}

func TestUnprotectExplicitChildRuleOnlyWarns(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.mustGitSops(repo, "init", "--protect", "secrets/,secrets/token.txt")
	policy := read(t, filepath.Join(repo, ".sops.yaml"))
	attrs := read(t, filepath.Join(repo, ".gitattributes"))
	index := s.git(repo, "write-tree")
	working := read(t, filepath.Join(repo, "secrets", "token.txt"))
	// A warning-only no-op must also preserve existing staged changes.
	r := s.gitSops(repo, "unprotect", "secrets/token.txt")
	if r.code != 0 || !strings.Contains(r.out, "Skipping") || !strings.Contains(r.out, "remains protected") {
		t.Fatalf("expected only a warning: %+v", r)
	}
	if read(t, filepath.Join(repo, ".sops.yaml")) != policy || read(t, filepath.Join(repo, ".gitattributes")) != attrs || s.git(repo, "write-tree") != index || read(t, filepath.Join(repo, "secrets", "token.txt")) != working {
		t.Fatal("warning-only unprotect changed policy, index or working file")
	}
}

func TestUnprotectRollsBackWhenOtherAttributesStillProtectFile(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")
	attrs := filepath.Join(repo, ".gitattributes")
	write(t, attrs, read(t, attrs)+"/secrets/** filter=sops\n")
	s.git(repo, "add", ".gitattributes")
	s.git(repo, "commit", "-m", "extra unmanaged rule")
	before := read(t, attrs)
	index := s.git(repo, "write-tree")
	r := s.gitSops(repo, "unprotect", "secrets/")
	if r.code == 0 || !strings.Contains(r.out, "still protected") {
		t.Fatalf("expected rejection: %+v", r)
	}
	if read(t, attrs) != before || s.git(repo, "write-tree") != index {
		t.Fatal("failed unprotect was not rolled back")
	}
}

func TestProtectRejectsOverridingAttributes(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")
	attrs := filepath.Join(repo, ".gitattributes")
	write(t, attrs, read(t, attrs)+"/new.txt -filter\n")
	write(t, filepath.Join(repo, "new.txt"), "new token\n")
	s.git(repo, "add", ".gitattributes", "new.txt")
	s.git(repo, "commit", "-m", "overriding rule")
	before := read(t, attrs)
	index := s.git(repo, "write-tree")
	r := s.gitSops(repo, "protect", "new.txt")
	if r.code == 0 || !strings.Contains(r.out, "attributes do not protect") {
		t.Fatalf("expected overriding attributes failure: %+v", r)
	}
	if read(t, attrs) != before || s.git(repo, "write-tree") != index {
		t.Fatal("failed protection was not rolled back")
	}
}
