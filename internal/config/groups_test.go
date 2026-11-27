package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestGroupedGlobsFollowSOPSPrecedence(t *testing.T) {
	root := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{id.Recipient().String()}
	m := &Managed{Groups: map[string][]string{DefaultGroup: keys, "ops": keys}, Assignments: map[string]string{"**/*.env": "ops"}}
	specs, err := BuildSpecs(root, []string{"**/*.env", "api/", "ops/**/*.env", ".env", "*.env"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManagedConfig(root, specs, m, false, t.Logf); err != nil {
		t.Fatal(err)
	}
	parsed, err := ReadManaged(filepath.Join(root, ".sops.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(parsed.ProtectedPaths, ","); got != ".env,api/,ops/**/*.env,*.env,**/*.env" {
		t.Fatalf("SOPS rule order = %q", got)
	}
	for file, want := range map[string]string{".env": ".env", "api/prod.env": "api/", "ops/db/prod.env": "ops/**/*.env", "other.env": "*.env", "sub/other.env": "**/*.env", "other.xml": ""} {
		if got := parsed.RuleFor(file); got != want {
			t.Errorf("rule for %s = %q, want %q", file, got, want)
		}
	}
}

func TestGroupedPolicyRejectsAmbiguousOrIncompleteRules(t *testing.T) {
	root := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{id.Recipient().String()}
	m := &Managed{Groups: map[string][]string{DefaultGroup: keys, "production": keys}, Assignments: map[string]string{"secrets/prod.env": "production"}}
	specs, err := BuildSpecs(root, []string{"secrets/", "secrets/prod.env"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManagedConfig(root, specs, m, false, t.Logf); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, ".sops.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	head, rules, ok := strings.Cut(string(data), "creation_rules:\n")
	first, second, split := strings.Cut(rules, "\n\n")
	if !ok || !split {
		t.Fatal("expected two group rules")
	}
	for _, invalid := range []string{
		head + "creation_rules:\n" + strings.TrimSuffix(second, "\n") + "\n\n" + first + "\n",
		head + "creation_rules:\n" + first + "\n\n# protected-path: secrets/\n",
		strings.Replace(string(data), "age: *production", "age: *missing", 1),
		strings.Replace(string(data), "age: *production", "age: *production\n    pgp: another-key", 1),
	} {
		if _, err := ParseManaged([]byte(invalid)); err == nil {
			t.Fatalf("accepted invalid grouped policy: %s", invalid)
		}
	}
	if err := WriteSopsConfig(root, specs, keys, true, t.Logf); err == nil {
		t.Fatal("grouped access was flattened")
	}
}
