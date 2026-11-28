package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestMigrateV1GroupPolicy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".sops.yaml")
	const key = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	old := groupV1Marker + "\nrecipient_groups:\n  default: &default\n    - " + key + "\n  ops: &ops\n    - " + key +
		"\ncreation_rules:\n# protected-path: prod.env\n  - path_regex: '^prod\\.env$'\n    age: *ops\n"
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := ReadManaged(path)
	if err != nil || before == nil || before.GroupForRule("prod.env") != "ops" {
		t.Fatalf("v1 group policy: %+v, %v", before, err)
	}
	specs, err := BuildSpecs(root, before.ProtectedPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManagedConfig(root, specs, before, false, t.Logf); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), GroupMarker+"\n") || !strings.Contains(string(data), "creation_rules:\n  # protected-path: prod.env\n  - path_regex:") {
		t.Fatalf("unexpected migrated group policy:\n%s", data)
	}
	after, err := ParseManaged(data)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("changed policy on migration: %+v, %v", after, err)
	}
}

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

func TestGroupedSortPreservesOverlappingRules(t *testing.T) {
	specs, err := BuildSpecs(t.TempDir(), []string{"z", "folder/", "x*.env", "folder/z.env", "*x.env", "folder.bak", "folder/a/", "folder/a/b", "a"})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, spec := range orderedSpecs(specs, true) {
		paths = append(paths, spec.policyPath())
	}
	if got := strings.Join(paths, ","); got != "a,folder.bak,folder/a/b,folder/a/,folder/z.env,folder/,z,x*.env,*x.env" {
		t.Fatalf("unexpected group rule order: %s", got)
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
