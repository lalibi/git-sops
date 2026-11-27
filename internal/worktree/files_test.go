package worktree

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegularFilesOnly(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(dir, "nested/data", []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(dir, "nested/data"); err != nil || string(b) != "content" {
		t.Fatalf("regular file read failed: %v", err)
	}
	for _, path := range []string{"../file", ".git/data", "nested"} {
		if err := WriteFile(dir, path, nil, 0o600); err == nil {
			t.Fatalf("expected %q to be refused", path)
		}
	}
}

func TestRefuseSymlinkedWorktreeFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(dir, "original/data", []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("original", filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := WriteFile(dir, "link/data", []byte("replacement"), 0o600); err == nil {
		t.Fatal("followed a symlinked directory")
	}
	if b, err := ReadFile(dir, "original/data"); err != nil || string(b) != "content" {
		t.Fatal("changed symlink target")
	}
}
