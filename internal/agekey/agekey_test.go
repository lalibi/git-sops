package agekey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestImportValidatesBeforeWritingAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "identity.txt")
	t.Setenv("SOPS_AGE_KEY_FILE", dest)
	if _, err := Generate(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "import.txt")
	const invalid = "AGE-SECRET-KEY-invalid"
	if err := os.WriteFile(source, []byte(id.String()+"\n"+invalid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Import(source); err == nil || strings.Contains(err.Error(), invalid) {
		t.Fatal("expected a redacted error for the malformed identity")
	}
	after, err := os.ReadFile(dest)
	if err != nil || string(after) != string(original) {
		t.Fatal("invalid import modified the existing key file")
	}
	if err := os.WriteFile(source, []byte(strings.Repeat(id.String()+"\n", 2)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Import(source); err != nil {
		t.Fatal(err)
	}
	keys, err := readSecretLines(dest)
	if err != nil || len(keys) != 2 || keys[1] != id.String() {
		t.Fatal("import must append one copy and preserve the existing key")
	}
	if _, err := Generate(); err == nil {
		t.Fatal("generate must refuse to overwrite an existing identity")
	}
}
