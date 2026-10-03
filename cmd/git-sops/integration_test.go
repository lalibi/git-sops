package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "git-sops-test-*")
	if err != nil {
		panic(err)
	}

	name := "git-sops"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary = filepath.Join(dir, "bin dir", name) // space on purpose: Git runs the filter through sh

	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type sandbox struct {
	t       *testing.T
	keyFile string
	env     []string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()

	for _, tool := range []string{"git", "sops"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required for integration tests", tool)
		}
	}

	dir := t.TempDir()
	emptyConfig := filepath.Join(dir, "gitconfig")
	if err := os.WriteFile(emptyConfig, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	return &sandbox{
		t:       t,
		keyFile: filepath.Join(dir, "keys", "keys.txt"),
		env: append(os.Environ(),
			"GIT_CONFIG_GLOBAL="+emptyConfig,
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		),
	}
}

// as returns a sandbox that uses another age key file but shares everything else.
func (s *sandbox) as(name string) *sandbox {
	c := *s
	c.keyFile = filepath.Join(filepath.Dir(s.keyFile), name, "keys.txt")
	return &c
}

type result struct {
	out  string
	code int
}

func (s *sandbox) run(dir, exe string, args ...string) result {
	s.t.Helper()

	cmd := exec.Command(exe, args...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, s.env...), "SOPS_AGE_KEY_FILE="+s.keyFile)

	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf

	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		s.t.Fatalf("%s %v: %v", exe, args, err)
	}
	return result{out: buf.String(), code: code}
}

func (s *sandbox) git(dir string, args ...string) string {
	s.t.Helper()
	r := s.run(dir, "git", args...)
	if r.code != 0 {
		s.t.Fatalf("git %v failed (%d):\n%s", args, r.code, r.out)
	}
	return r.out
}

func (s *sandbox) gitSops(dir string, args ...string) result {
	s.t.Helper()
	return s.run(dir, binary, args...)
}

func (s *sandbox) mustGitSops(dir string, args ...string) string {
	s.t.Helper()
	r := s.gitSops(dir, args...)
	if r.code != 0 {
		s.t.Fatalf("git-sops %v failed (%d):\n%s", args, r.code, r.out)
	}
	return r.out
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	jsonSecret = `{"password": "hunter2"}` + "\n"
	// SOPS re-serializes structured formats when decrypting.
	jsonDecrypted = "{\n\t\"password\": \"hunter2\"\n}\n"
	textSecret    = "plain text token\r\nsecond line\n"
)

// protectedRepo creates a repository protected with git-sops and returns its path.
func protectedRepo(t *testing.T, s *sandbox) string {
	t.Helper()

	repo := filepath.Join(t.TempDir(), "origin")
	s.git(filepath.Dir(repo), "init", "-b", "main", repo)

	write(t, filepath.Join(repo, "README.md"), "hello\n")
	write(t, filepath.Join(repo, "secrets", "db.json"), jsonSecret)
	write(t, filepath.Join(repo, "secrets", "token.txt"), textSecret)

	s.git(repo, "add", "README.md")
	s.git(repo, "commit", "-m", "initial")

	out := s.mustGitSops(repo, "init", "--protect", "secrets/")
	if !strings.Contains(out, "Repository initialized") {
		t.Fatalf("unexpected init output:\n%s", out)
	}
	return repo
}

func TestInitEncryptsIndexAndKeepsPlaintextLocally(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)

	if got := read(t, filepath.Join(repo, "secrets", "db.json")); got != jsonSecret {
		t.Errorf("working tree json = %q", got)
	}
	if got := read(t, filepath.Join(repo, "secrets", "token.txt")); got != textSecret {
		t.Errorf("working tree text = %q", got)
	}

	for _, p := range []string{"secrets/db.json", "secrets/token.txt"} {
		blob := s.git(repo, "cat-file", "blob", ":"+p)
		if strings.Contains(blob, "hunter2") || strings.Contains(blob, "plain text token") {
			t.Errorf("index blob for %s holds plaintext", p)
		}
		if !strings.Contains(blob, "sops") {
			t.Errorf("index blob for %s is not SOPS output", p)
		}
	}

	if _, err := os.Stat(filepath.Join(repo, ".githooks")); err == nil {
		t.Error("init must not create .githooks")
	}
}

func TestAddIsStableForUnchangedPlaintext(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	before := s.git(repo, "rev-parse", ":secrets/db.json")
	s.git(repo, "add", "-A")
	if after := s.git(repo, "rev-parse", ":secrets/db.json"); after != before {
		t.Errorf("blob changed without a content change: %s -> %s", before, after)
	}
	if status := s.git(repo, "status", "--porcelain"); strings.TrimSpace(status) != "" {
		t.Errorf("working tree not clean:\n%s", status)
	}
}

func TestReformattedJSONKeepsCiphertext(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	before := s.git(repo, "rev-parse", ":secrets/db.json")
	write(t, filepath.Join(repo, "secrets", "db.json"), "{\n    \"password\":   \"hunter2\"\n}\n")

	// Git trusts a changed file size without running the filter, so status can show a
	// stale ' M' until the entry is refreshed by add.
	s.git(repo, "add", "-A")

	if after := s.git(repo, "rev-parse", ":secrets/db.json"); after != before {
		t.Errorf("formatting-only change produced new ciphertext: %s -> %s", before, after)
	}
	if status := s.git(repo, "status", "--porcelain"); strings.TrimSpace(status) != "" {
		t.Errorf("tree not clean after add:\n%s", status)
	}
}

func TestEditedPlaintextIsReencrypted(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	before := s.git(repo, "rev-parse", ":secrets/db.json")
	write(t, filepath.Join(repo, "secrets", "db.json"), `{"password": "changed"}`+"\n")
	s.git(repo, "add", "-A")

	if after := s.git(repo, "rev-parse", ":secrets/db.json"); after == before {
		t.Error("blob did not change after an edit")
	}
	if blob := s.git(repo, "cat-file", "blob", ":secrets/db.json"); strings.Contains(blob, "changed") {
		t.Error("edited value leaked into the index")
	}
}

func TestJoinOnFreshCloneDecrypts(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	clone := filepath.Join(t.TempDir(), "clone")
	s.git(filepath.Dir(clone), "clone", repo, clone)

	if got := read(t, filepath.Join(clone, "secrets", "db.json")); strings.Contains(got, "hunter2") {
		t.Fatal("a clone without filters should hold ciphertext")
	}

	out := s.mustGitSops(clone, "join")
	if !strings.Contains(out, "SOPS index validation passed") {
		t.Errorf("unexpected join output:\n%s", out)
	}

	if got := read(t, filepath.Join(clone, "secrets", "db.json")); got != jsonDecrypted {
		t.Errorf("decrypted json = %q", got)
	}
	if got := read(t, filepath.Join(clone, "secrets", "token.txt")); got != textSecret {
		t.Errorf("decrypted text = %q (byte-exact round trip expected)", got)
	}
	if status := s.git(clone, "status", "--short"); strings.TrimSpace(status) != "" {
		t.Errorf("clone not clean after join:\n%s", status)
	}
}

func TestCollaboratorOnboarding(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	bob := s.as("bob")
	clone := filepath.Join(t.TempDir(), "bob")
	s.git(filepath.Dir(clone), "clone", repo, clone)

	r := bob.gitSops(clone, "join")
	if r.code != 2 {
		t.Fatalf("join without access should exit 2, got %d:\n%s", r.code, r.out)
	}

	var recipient string
	for _, f := range strings.Fields(r.out) {
		if _, err := age.ParseX25519Recipient(f); err == nil {
			recipient = f
		}
	}
	if recipient == "" {
		t.Fatalf("no recipient printed:\n%s", r.out)
	}

	s.mustGitSops(repo, "add-recipient", recipient)
	s.git(repo, "commit", "-m", "add bob")
	if got := read(t, filepath.Join(repo, "secrets", "db.json")); got != jsonSecret {
		t.Errorf("maintainer plaintext changed: %q", got)
	}

	s.git(clone, "pull", "--ff-only")
	bob.mustGitSops(clone, "join")

	if got := read(t, filepath.Join(clone, "secrets", "db.json")); got != jsonDecrypted {
		t.Errorf("bob could not decrypt: %q", got)
	}
}

func TestVerifyRejectsPlaintextInIndex(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)

	if r := s.gitSops(repo, "verify"); r.code != 0 {
		t.Fatalf("verify should pass on a healthy index:\n%s", r.out)
	}

	hash := strings.TrimSpace(s.git(repo, "hash-object", "-w", "--no-filters", "secrets/db.json"))
	s.git(repo, "update-index", "--cacheinfo", "100644,"+hash+",secrets/db.json")

	r := s.gitSops(repo, "verify")
	if r.code == 0 || !strings.Contains(r.out, "secrets/db.json") {
		t.Fatalf("verify should reject plaintext (code %d):\n%s", r.code, r.out)
	}
}

func TestCheckReportsHealthyAndUnconfiguredRepos(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	r := s.gitSops(repo, "check")
	if r.code != 0 || !strings.Contains(r.out, "2 protected file(s), all ciphertext") {
		t.Fatalf("check on a healthy repo (code %d):\n%s", r.code, r.out)
	}

	clone := filepath.Join(t.TempDir(), "clone")
	s.git(filepath.Dir(clone), "clone", repo, clone)

	r = s.gitSops(clone, "check")
	if r.code != 1 || !strings.Contains(r.out, "Git filter") || !strings.Contains(r.out, "not configured") {
		t.Fatalf("check on an unconfigured clone should fail (code %d):\n%s", r.code, r.out)
	}
}

func TestInitUpgradesLegacyPowerShellSetup(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)

	write(t, filepath.Join(repo, ".githooks", "git-sops-filter.ps1"), "# legacy\n")
	write(t, filepath.Join(repo, ".githooks", "Setup-SopsGit.ps1"), "# legacy\n")
	s.git(repo, "add", ".githooks")
	s.git(repo, "commit", "-m", "legacy setup")

	s.mustGitSops(repo, "init")

	if _, err := os.Stat(filepath.Join(repo, ".githooks")); err == nil {
		t.Error("legacy .githooks should be removed")
	}
	if tracked := s.git(repo, "ls-files", ".githooks"); strings.TrimSpace(tracked) != "" {
		t.Errorf("legacy files still tracked:\n%s", tracked)
	}
	if got := s.git(repo, "config", "--local", "filter.sops.clean"); !strings.Contains(got, "clean %f") || strings.Contains(got, "pwsh") {
		t.Errorf("filter not repointed: %s", got)
	}
}

func recipientIn(t *testing.T, out string) string {
	t.Helper()
	for _, f := range strings.Fields(out) {
		if _, err := age.ParseX25519Recipient(f); err == nil {
			return f
		}
	}
	t.Fatalf("no recipient found in:\n%s", out)
	return ""
}

func TestRemoveRecipientRevokesAccess(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	own := recipientIn(t, s.mustGitSops(repo, "check"))
	if r := s.gitSops(repo, "remove-recipient", own); r.code == 0 || !strings.Contains(r.out, "your own") {
		t.Fatalf("removing your own recipient must be refused (code %d):\n%s", r.code, r.out)
	}

	bob := s.as("bob")
	clone := filepath.Join(t.TempDir(), "bob")
	s.git(filepath.Dir(clone), "clone", repo, clone)
	bobRecipient := recipientIn(t, bob.gitSops(clone, "join").out)

	s.mustGitSops(repo, "add-recipient", bobRecipient)
	s.git(repo, "commit", "-m", "add bob")

	s.mustGitSops(repo, "remove-recipient", bobRecipient)
	s.git(repo, "commit", "-m", "remove bob")

	if got := read(t, filepath.Join(repo, "secrets", "db.json")); got != jsonSecret {
		t.Errorf("maintainer plaintext changed: %q", got)
	}
	if sops := read(t, filepath.Join(repo, ".sops.yaml")); strings.Contains(sops, bobRecipient) {
		t.Error("bob is still listed in .sops.yaml")
	}

	s.git(clone, "pull", "--ff-only")
	if r := bob.gitSops(clone, "join"); r.code == 0 {
		t.Fatalf("bob should no longer be able to decrypt:\n%s", r.out)
	}

	if r := s.gitSops(repo, "remove-recipient", bobRecipient); r.code == 0 {
		t.Error("removing a recipient that is not listed should fail")
	}
}

func TestDecryptWithoutGit(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	clone := filepath.Join(t.TempDir(), "clone")
	s.git(filepath.Dir(clone), "clone", repo, clone)

	r := s.gitSops(clone, "decrypt", filepath.Join("secrets", "token.txt"))
	if r.code != 0 || r.out != textSecret {
		t.Fatalf("decrypt to stdout (code %d) = %q", r.code, r.out)
	}
	if got := read(t, filepath.Join(clone, "secrets", "token.txt")); strings.Contains(got, "plain text token") {
		t.Error("decrypting to stdout must not touch the file")
	}

	if r := s.gitSops(clone, "decrypt", "secrets"); r.code == 0 {
		t.Error("a directory needs --in-place --recursive")
	}

	s.mustGitSops(clone, "decrypt", "--in-place", "--recursive", "secrets")
	if got := read(t, filepath.Join(clone, "secrets", "db.json")); got != jsonDecrypted {
		t.Errorf("decrypted json = %q", got)
	}
	if got := read(t, filepath.Join(clone, "secrets", "token.txt")); got != textSecret {
		t.Errorf("decrypted text = %q", got)
	}

	// A second run finds only plaintext and leaves it alone.
	if out := s.mustGitSops(clone, "decrypt", "--in-place", "--recursive", "secrets"); !strings.Contains(out, "Decrypted 0") {
		t.Errorf("unexpected second run output:\n%s", out)
	}
}

func TestDiffShowsDecryptedChanges(t *testing.T) {
	s := newSandbox(t)
	repo := protectedRepo(t, s)
	s.git(repo, "commit", "-m", "protect secrets")

	write(t, filepath.Join(repo, "secrets", "db.json"), `{"password": "changed"}`+"\n")
	s.git(repo, "add", "-A")
	s.git(repo, "commit", "-m", "rotate password")

	diff := s.git(repo, "diff", "HEAD~1", "HEAD", "--", "secrets/db.json")
	if !strings.Contains(diff, "hunter2") || !strings.Contains(diff, "changed") {
		t.Errorf("diff should show decrypted values:\n%s", diff)
	}
	if strings.Contains(diff, "ENC[") {
		t.Errorf("diff still shows ciphertext:\n%s", diff)
	}
	if r := s.run(repo, "git", "config", "--local", "diff.sops.cachetextconv"); r.code == 0 && strings.TrimSpace(r.out) == "true" {
		t.Error("cachetextconv would store plaintext in the repository")
	}
}

// A line between the edited keys is needed: Git treats edits on adjacent lines as a conflict.
const mergeBase = `{"a": "1", "m": "m", "b": "2"}` + "\n"

// mergeRepo has secrets/app.json on main and a feature branch that diverges from it.
func mergeRepo(t *testing.T, s *sandbox, mainEdit, featureEdit string) string {
	t.Helper()

	repo := protectedRepo(t, s)
	app := filepath.Join(repo, "secrets", "app.json")
	write(t, app, mergeBase)
	s.git(repo, "add", "-A")
	s.git(repo, "commit", "-m", "protect secrets")

	s.git(repo, "switch", "-c", "feature")
	write(t, app, featureEdit)
	s.git(repo, "commit", "-am", "feature edit")

	s.git(repo, "switch", "main")
	write(t, app, mainEdit)
	s.git(repo, "commit", "-am", "main edit")
	return repo
}

func TestMergeCombinesEncryptedChanges(t *testing.T) {
	s := newSandbox(t)
	repo := mergeRepo(t, s,
		`{"a": "1", "m": "m", "b": "main"}`+"\n",
		`{"a": "feature", "m": "m", "b": "2"}`+"\n")

	s.git(repo, "merge", "--no-edit", "feature")

	got := read(t, filepath.Join(repo, "secrets", "app.json"))
	if !strings.Contains(got, `"a": "feature"`) || !strings.Contains(got, `"b": "main"`) {
		t.Errorf("merged plaintext = %q", got)
	}

	blob := s.git(repo, "cat-file", "blob", ":secrets/app.json")
	if strings.Contains(blob, "feature") || strings.Contains(blob, "main") || !strings.Contains(blob, "sops") {
		t.Errorf("merged index blob is not ciphertext:\n%s", blob)
	}
	if status := s.git(repo, "status", "--porcelain"); strings.TrimSpace(status) != "" {
		t.Errorf("tree not clean after merge:\n%s", status)
	}
}

func TestMergeConflictLeavesMarkersThenEncryptsResolution(t *testing.T) {
	s := newSandbox(t)
	repo := mergeRepo(t, s,
		`{"a": "main", "m": "m", "b": "2"}`+"\n",
		`{"a": "feature", "m": "m", "b": "2"}`+"\n")

	r := s.run(repo, "git", "merge", "--no-edit", "feature")
	if r.code == 0 || !strings.Contains(r.out, "CONFLICT") {
		t.Fatalf("expected a merge conflict (code %d):\n%s", r.code, r.out)
	}

	app := filepath.Join(repo, "secrets", "app.json")
	if got := read(t, app); !strings.Contains(got, "<<<<<<<") || !strings.Contains(got, "main") || !strings.Contains(got, "feature") {
		t.Fatalf("working tree should hold plaintext conflict markers:\n%s", got)
	}

	write(t, app, `{"a": "resolved", "m": "m", "b": "2"}`+"\n")
	s.git(repo, "add", "secrets/app.json")
	s.git(repo, "commit", "--no-edit")

	blob := s.git(repo, "cat-file", "blob", "HEAD:secrets/app.json")
	if strings.Contains(blob, "resolved") || !strings.Contains(blob, "sops") {
		t.Errorf("resolved blob is not ciphertext:\n%s", blob)
	}
	if r := s.gitSops(repo, "verify"); r.code != 0 {
		t.Errorf("verify failed after resolving:\n%s", r.out)
	}
}
