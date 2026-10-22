package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommitFlagsAreLimitedToRepositoryChangeCommands(t *testing.T) {
	for _, name := range []string{"init", "protect", "unprotect", "add-recipient", "remove-recipient", "migrate-git-crypt"} {
		cmd, _, err := newRootCommand().Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Flags().Lookup("commit") == nil || cmd.Flags().Lookup("message") == nil {
			t.Fatalf("%s lacks commit flags", name)
		}
	}
	for _, name := range []string{"join", "decrypt", "install-sops", "encrypt-history"} {
		cmd, _, err := newRootCommand().Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Flags().Lookup("commit") != nil || cmd.Flags().Lookup("message") != nil {
			t.Fatalf("%s unexpectedly accepts commit flags", name)
		}
	}
	for _, args := range [][]string{
		{"init", "--commit", "--no-stage"},
		{"add-recipient", "age1test", "--commit", "--no-stage"},
		{"remove-recipient", "age1test", "--commit", "--no-stage"},
		{"migrate-git-crypt", "--commit", "--no-stage"},
		{"protect", "file.txt", "--message", "custom"},
		{"unprotect", "file.txt", "--commit", "--message", ""},
	} {
		cmd := newRootCommand()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--") {
			t.Fatalf("expected commit flag validation for %v: %v", args, err)
		}
	}
}

func TestCommitLifecycleAndGeneratedMessages(t *testing.T) {
	s := newSandbox(t)
	repo := filepath.Join(t.TempDir(), "repo")
	s.git(filepath.Dir(repo), "init", "-b", "main", repo)
	write(t, filepath.Join(repo, "README.md"), "public\n")
	s.git(repo, "add", "README.md")
	s.git(repo, "commit", "-m", "initial")
	write(t, filepath.Join(repo, "secrets", "token.txt"), textSecret)
	write(t, filepath.Join(repo, "settings.txt"), "settings\n")
	write(t, filepath.Join(repo, "unrelated.txt"), "leave untracked\n")
	s.mustGitSops(repo, "init", "--protect", "secrets/,settings.txt", "--commit")
	message := s.git(repo, "log", "-1", "--format=%B")
	if !strings.HasPrefix(message, "chore(git-sops): 🔐 Configure transparent file encryption\n") || !strings.Contains(message, "- secrets/\n- settings.txt\n") {
		t.Fatalf("unexpected init message: %q", message)
	}
	if tracked := strings.TrimSpace(s.git(repo, "ls-files", "unrelated.txt")); tracked != "" {
		t.Fatal("auto-commit included an unrelated untracked file")
	}
	assertClean := func() {
		t.Helper()
		if status := strings.TrimSpace(s.git(repo, "status", "--porcelain", "--untracked-files=no")); status != "" {
			t.Fatalf("tracked files are dirty: %s", status)
		}
	}
	assertClean()
	head := s.git(repo, "rev-parse", "HEAD")
	out := s.mustGitSops(repo, "init", "--commit")
	if !strings.Contains(out, "nothing to commit") || s.git(repo, "rev-parse", "HEAD") != head {
		t.Fatal("idempotent init created a commit")
	}
	write(t, filepath.Join(repo, "examples", "sample.txt"), "public example\n")
	s.mustGitSops(repo, "protect", "examples/", "--commit")
	if message := s.git(repo, "log", "-1", "--format=%B"); !strings.Contains(message, "Protect additional paths") || !strings.Contains(message, "- examples/\n") || strings.Contains(message, "- secrets/\n") {
		t.Fatalf("protect message describes unrelated paths: %q", message)
	}
	head = s.git(repo, "rev-parse", "HEAD")
	s.mustGitSops(repo, "unprotect", "secrets/token.txt", "--commit")
	if s.git(repo, "rev-parse", "HEAD") != head {
		t.Fatal("skipped unprotect created a commit")
	}
	custom := "chore(config): 🔓 Publish example configuration\n\nUse public sample values."
	s.mustGitSops(repo, "unprotect", "secrets/token.txt", "examples/", "--commit", "--message", custom)
	if got := strings.TrimSpace(s.git(repo, "log", "-1", "--format=%B")); got != custom {
		t.Fatalf("custom message = %q", got)
	}
	if got := s.git(repo, "cat-file", "blob", "HEAD:examples/sample.txt"); got != "public example\n" {
		t.Fatalf("unprotect commit retained ciphertext: %q", got)
	}
	guest := s.as("guest")
	r := guest.gitSops(repo, "join")
	if r.code != 2 {
		t.Fatalf("generate guest identity: %+v", r)
	}
	recipient := recipientIn(t, r.out)
	s.mustGitSops(repo, "add-recipient", recipient, "--commit")
	message = s.git(repo, "log", "-1", "--format=%B")
	if !strings.Contains(message, "Add encryption recipients") || !strings.Contains(message, "- "+recipient+"\n") || !strings.Contains(message, "- secrets/\n- settings.txt\n") {
		t.Fatalf("add-recipient message = %q", message)
	}
	head = s.git(repo, "rev-parse", "HEAD")
	s.mustGitSops(repo, "add-recipient", recipient, "--commit")
	if s.git(repo, "rev-parse", "HEAD") != head {
		t.Fatal("duplicate recipient created a commit")
	}
	s.mustGitSops(repo, "remove-recipient", recipient, "--commit")
	message = s.git(repo, "log", "-1", "--format=%B")
	if !strings.Contains(message, "Remove encryption recipients") || !strings.Contains(message, "- "+recipient+"\n") {
		t.Fatalf("remove-recipient message = %q", message)
	}
	s.mustGitSops(repo, "unprotect", "settings.txt", "--commit")
	if message := s.git(repo, "log", "-1", "--format=%B"); !strings.Contains(message, "Remove file protection") || !strings.Contains(message, "- settings.txt\n") {
		t.Fatalf("default unprotect message = %q", message)
	}
	assertClean()
}

func TestCommitRequiresCleanTrackedStateBeforeMutation(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s) // Initialization changes are staged but uncommitted.
	policy := read(t, filepath.Join(repo, ".sops.yaml"))
	attrs := read(t, filepath.Join(repo, ".gitattributes"))
	index := s.git(repo, "write-tree")
	for _, args := range [][]string{{"init"}, {"protect", "extra.txt"}, {"unprotect", "secrets/"}, {"add-recipient", "age1test"}, {"remove-recipient", "age1test"}, {"migrate-git-crypt"}} {
		r := s.gitSops(repo, append(args, "--commit")...)
		if r.code == 0 || !strings.Contains(r.out, "uncommitted changes") {
			t.Fatalf("dirty index accepted by %v: %+v", args, r)
		}
		if s.git(repo, "write-tree") != index || read(t, filepath.Join(repo, ".sops.yaml")) != policy || read(t, filepath.Join(repo, ".gitattributes")) != attrs {
			t.Fatalf("%v mutated the dirty repository", args)
		}
	}
	s.git(repo, "commit", "-m", "protect secrets")
	write(t, filepath.Join(repo, "README.md"), "keep local edits\n")
	r := s.gitSops(repo, "init", "--commit")
	if r.code == 0 || !strings.Contains(r.out, "uncommitted changes") || read(t, filepath.Join(repo, "README.md")) != "keep local edits\n" {
		t.Fatalf("working changes were not preserved: %+v", r)
	}
	s.git(repo, "restore", "README.md")
	write(t, filepath.Join(repo, ".git", "MERGE_HEAD"), strings.TrimSpace(s.git(repo, "rev-parse", "HEAD"))+"\n")
	r = s.gitSops(repo, "init", "--commit")
	if r.code == 0 || !strings.Contains(r.out, "finish the current merge") {
		t.Fatalf("active merge was accepted: %+v", r)
	}
}

func TestInitCommitCreatesFirstCommit(t *testing.T) {
	s := newSandbox(t)
	repo := filepath.Join(t.TempDir(), "repo")
	s.git(filepath.Dir(repo), "init", "-b", "main", repo)
	write(t, filepath.Join(repo, "secret.txt"), "first secret\n")
	s.mustGitSops(repo, "init", "--protect", "secret.txt", "--commit")
	if count := strings.TrimSpace(s.git(repo, "rev-list", "--count", "HEAD")); count != "1" {
		t.Fatalf("initialization created %s commits", count)
	}
	if blob := s.git(repo, "cat-file", "blob", "HEAD:secret.txt"); !strings.Contains(blob, "sops") || strings.Contains(blob, "first secret") {
		t.Fatal("initial commit did not encrypt the selected file")
	}
}

func TestCommitFailureKeepsPreparedChanges(t *testing.T) {
	for _, failure := range []string{"hook", "signing"} {
		t.Run(failure, func(t *testing.T) {
			s := newSandbox(t)
			repo := protectedRepo(t, s)
			s.git(repo, "commit", "-m", "protect secrets")
			head := s.git(repo, "rev-parse", "HEAD")
			if failure == "hook" {
				s.git(repo, "config", "hook.reject.command", "git rev-parse --verify refs/heads/a-branch-that-does-not-exist")
				s.git(repo, "config", "hook.reject.event", "prepare-commit-msg")
			} else {
				s.git(repo, "config", "commit.gpgsign", "true")
				s.git(repo, "config", "gpg.program", "git-sops-test-no-such-signing-program")
			}
			write(t, filepath.Join(repo, "extra.txt"), "new secret\n")
			r := s.gitSops(repo, "protect", "extra.txt", "--commit")
			if r.code == 0 || !strings.Contains(r.out, "prepared changes remain staged") {
				t.Fatalf("expected %s failure: %+v", failure, r)
			}
			if s.git(repo, "rev-parse", "HEAD") != head {
				t.Fatal("failed commit advanced HEAD")
			}
			if blob := s.git(repo, "cat-file", "blob", ":extra.txt"); !strings.Contains(blob, "sops") || strings.Contains(blob, "new secret") {
				t.Fatal("prepared ciphertext was not preserved")
			}
			if !strings.Contains(read(t, filepath.Join(repo, ".sops.yaml")), "# protected-path: extra.txt") {
				t.Fatal("prepared policy was rolled back after commit failed")
			}
		})
	}
}

func TestMigrateGitCryptCanCommitPreparedSopsFiles(t *testing.T) {
	s := newSandbox(t)
	// Stand in for git-crypt's status command; the repository represents an unlocked
	// checkout. The migration and subsequent encryption use the real Git and SOPS.
	toolDir := t.TempDir()
	toolName := "git-crypt"
	if runtime.GOOS == "windows" {
		toolName += ".exe"
	}
	toolSource := filepath.Join(toolDir, "main.go")
	write(t, toolSource, "package main\nimport \"os\"\nfunc main() { if len(os.Args)!=3 || os.Args[1]!=\"status\" || os.Args[2]!=\"-e\" { os.Exit(1) } }\n")
	build := exec.Command("go", "build", "-o", filepath.Join(toolDir, toolName), toolSource)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build status stub: %v\n%s", err, out)
	}
	s.env = append(s.env, "PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	repo := filepath.Join(t.TempDir(), "repo")
	s.git(filepath.Dir(repo), "init", "-b", "main", repo)
	write(t, filepath.Join(repo, ".gitattributes"), "/secrets/** filter=git-crypt diff=git-crypt\n")
	write(t, filepath.Join(repo, "secrets", "token.txt"), "unlocked secret\n")
	s.git(repo, "add", ".")
	s.git(repo, "commit", "-m", "unlocked git-crypt checkout")
	s.mustGitSops(repo, "migrate-git-crypt", "--protect", "secrets/", "--yes", "--commit")
	if message := s.git(repo, "log", "-1", "--format=%B"); !strings.Contains(message, "Migrate git-crypt protection to SOPS") || !strings.Contains(message, "- secrets/\n") {
		t.Fatalf("migration message = %q", message)
	}
	if blob := s.git(repo, "cat-file", "blob", "HEAD:secrets/token.txt"); !strings.Contains(blob, "sops") || strings.Contains(blob, "unlocked secret") {
		t.Fatal("migration committed plaintext")
	}
}
