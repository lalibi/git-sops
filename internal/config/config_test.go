package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	good := map[string]string{
		"secrets/":                 "secrets",
		`src\Web\appsettings.json`: "src/Web/appsettings.json",
		"/appsettings.json":        "appsettings.json",
	}
	for in, want := range good {
		got, err := NormalizePath(in)
		if err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	for _, in := range []string{"", "/", ".", "./", "../x", "a/../b", "*.json", "a?b", "a[1]", "a\nb", "C:/secrets"} {
		if _, err := NormalizePath(in); err == nil {
			t.Errorf("NormalizePath(%q) should fail", in)
		}
	}
}

func TestQuotedPathsRoundTripManagedPolicy(t *testing.T) {
	root := t.TempDir()
	specs, err := BuildSpecs(root, []string{"private folder/", "it's-secret.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if specs[0].AttributePattern != `"/private folder/**"` {
		t.Fatalf("attributes pattern = %q", specs[0].AttributePattern)
	}
	if err := WriteSopsConfig(root, specs, []string{"age1aaa"}, false, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, ".sops.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "it''s-secret") {
		t.Fatalf("single-quoted YAML path was not escaped: %s", b)
	}
	m, err := ReadManaged(filepath.Join(root, ".sops.yaml"))
	if err != nil || m == nil || strings.Join(m.ProtectedPaths, ",") != "private folder/,it's-secret.txt" {
		t.Fatalf("policy round trip: %+v, %v", m, err)
	}
}

func TestSopsRegexMatchesBothSeparators(t *testing.T) {
	root := t.TempDir()
	specs, err := BuildSpecs(root, []string{"secrets/", "src/Web/appsettings.Production.json"})
	if err != nil {
		t.Fatal(err)
	}

	parts := []string{specs[0].RegexPart, specs[1].RegexPart}
	re := regexp.MustCompile("^(?:" + strings.Join(parts, "|") + ")$")

	for _, p := range []string{"secrets/a.txt", `secrets\sub\a.txt`, "src/Web/appsettings.Production.json"} {
		if !re.MatchString(p) {
			t.Errorf("expected %q to match", p)
		}
	}
	for _, p := range []string{"secrets", "src/Web/appsettings.json", "xsecrets/a.txt"} {
		if re.MatchString(p) {
			t.Errorf("expected %q not to match", p)
		}
	}
}

func TestUpdateAttributesReplacesManagedBlockOnly(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".gitattributes")
	original := "*.md text eol=lf\n" +
		AttributesBegin + "\n/.githooks/*.ps1 text eol=lf\n\n/old/** filter=sops -text\n" + AttributesEnd + "\n" +
		"*.png binary\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	specs, _ := BuildSpecs(root, []string{"secrets/"})
	if err := UpdateAttributes(root, specs, false); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(path)
	want := "*.md text eol=lf\n" +
		AttributesBegin + "\n/secrets/** filter=sops diff=sops merge=sops -text\n" + AttributesEnd + "\n" +
		"*.png binary\n"
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestUpdateAttributesMigratesGitCrypt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".gitattributes")
	if err := os.WriteFile(path, []byte("secrets/** filter=git-crypt diff=git-crypt\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	specs, _ := BuildSpecs(root, []string{"secrets/"})
	if err := UpdateAttributes(root, specs, true); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(got), "secrets/** filter=sops merge=sops diff=sops -text\n") {
		t.Errorf("unexpected rewrite: %q", got)
	}
}

func TestUpdateAttributesRejectsMalformedBlock(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".gitattributes")
	if err := os.WriteFile(path, []byte(AttributesBegin+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpdateAttributes(root, nil, false); err == nil {
		t.Fatal("expected an error for a block without an end marker")
	}
}

func TestCompactMigratedAttributes(t *testing.T) {
	const attrs = " filter=sops merge=sops diff=sops -text\n"
	const existing = "**/*.env" + attrs + "secrets.md" + attrs + "\n_backups/**" + attrs +
		"\ncerts/**" + attrs + "secrets/**" + attrs +
		"\n# CoreOS runs these scripts directly; preserve Unix line endings.\nobservability/*.sh text eol=lf\n"
	specs, err := BuildSpecs(t.TempDir(), []string{"secrets/", ".env", "observability/portal.env",
		"certs/name with spaces.pem", "_backups/db/db.dump", "secrets.md"})
	if err != nil {
		t.Fatal(err)
	}
	oldBlock, err := RenderAttributes(nil, specs, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{existing, existing + "\n" + string(oldBlock)} {
		got, err := RenderAttributes([]byte(input), specs, false)
		if err != nil || string(got) != existing {
			t.Fatalf("compacted attributes = %q, %v", got, err)
		}
	}
}

func TestKeepRulesForIncompleteOrOverriddenCoverage(t *testing.T) {
	const full = " filter=sops diff=sops merge=sops -text\n"
	for _, tc := range []struct{ path, before string }{
		{"dir/", "dir/*.env" + full},
		{"dir/", "dir/**" + full + "dir/future*.txt -filter\n"},
		{"dir/file.env", "**/*.env" + full + "/dir/file.env text\n"},
		{"dir/file.env", "**/*.env" + full + "DIR/** -diff\n"},
		{"dir/file.env", "dir/** filter=sops -text\n"},
		{"dir/file.env", "other/**" + full},
		{"dir/file.env", "dir/**" + full + "**/dir/file.env -filter\n"},
	} {
		specs, err := BuildSpecs(t.TempDir(), []string{tc.path})
		if err != nil {
			t.Fatal(err)
		}
		got, err := RenderAttributes([]byte(tc.before), specs, false)
		if err != nil || !strings.Contains(string(got), AttributesBegin+"\n"+specs[0].AttributePattern+full) {
			t.Errorf("explicit rule for %s missing after %q: %s, %v", tc.path, tc.before, got, err)
		}
	}
}

func TestSopsConfigRoundTrip(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}

	specs, _ := BuildSpecs(root, []string{"secrets", "appsettings.json"})
	recipients := []string{"age1bbb", "age1aaa", "age1aaa", "not-a-recipient"}
	if err := WriteSopsConfig(root, specs, recipients, false, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}

	m, err := ReadManaged(filepath.Join(root, ".sops.yaml"))
	if err != nil || m == nil {
		t.Fatalf("ReadManaged = %v, %v", m, err)
	}

	if got := strings.Join(m.Recipients, ","); got != "age1aaa,age1bbb" {
		t.Errorf("recipients = %s", got)
	}
	if got := strings.Join(m.ProtectedPaths, ","); got != "secrets/,appsettings.json" {
		t.Errorf("protected paths = %s", got)
	}
}

func TestWriteSopsConfigRefusesHandWrittenFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".sops.yaml"), []byte("creation_rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	specs, _ := BuildSpecs(root, []string{"secrets/"})
	warn := func(string, ...any) {}

	if err := WriteSopsConfig(root, specs, []string{"age1aaa"}, false, warn); err == nil {
		t.Fatal("expected a refusal without force")
	}
	if err := WriteSopsConfig(root, specs, []string{"age1aaa"}, true, warn); err != nil {
		t.Fatalf("force should succeed: %v", err)
	}

	backups, _ := filepath.Glob(filepath.Join(root, ".sops.yaml.bak.*"))
	if len(backups) != 1 {
		t.Errorf("expected one backup, found %d", len(backups))
	}
}

func TestReadManagedAcceptsLegacyMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sops.yaml")
	content := LegacySopsMarker + "\n# protected-path: secrets\ncreation_rules:\n  - path_regex: 'x'\n    age:\n      - age1abc\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := ReadManaged(path)
	if err != nil || m == nil || len(m.Recipients) != 1 || len(m.ProtectedPaths) != 1 {
		t.Fatalf("ReadManaged = %+v, %v", m, err)
	}
}
