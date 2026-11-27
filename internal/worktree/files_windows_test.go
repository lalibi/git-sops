package worktree

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRefuseDirectoryJunction(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(dir, "original/data", []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"New-Item -ItemType Junction -Path $env:TEST_JUNCTION -Target $env:TEST_TARGET -ErrorAction Stop | Out-Null")
	cmd.Env = append(os.Environ(), "TEST_JUNCTION="+filepath.Join(dir, "link"), "TEST_TARGET="+filepath.Join(dir, "original"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create test junction: %v: %s", err, out)
	}
	if err := WriteFile(dir, "link/data", nil, 0o600); err == nil {
		t.Fatal("followed a directory junction")
	}
}
