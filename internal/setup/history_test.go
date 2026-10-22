package setup

import (
	"strings"
	"testing"

	"github.com/lalibi/git-sops/internal/config"
)

func TestRewriteHeadersPreservesMetadataAndRemovesInvalidSignatures(t *testing.T) {
	input := "tree oldtree\nparent oldparent\nauthor A <a@example.com> 123 +0200\ncommitter C <c@example.com> 456 -0300\ngpgsig signature\n continuation\nmergetag object oldparent\n embedded-tag\nencoding UTF-8\n\nmessage\nwith blank\n\nlines\n"
	got, err := rewriteHeaders([]byte(input), func(key, val string) (string, error) {
		if key == "tree" {
			return "newtree", nil
		}
		if key == "parent" {
			return "newparent", nil
		}
		return val, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "tree newtree\nparent newparent\nauthor A <a@example.com> 123 +0200\ncommitter C <c@example.com> 456 -0300\nencoding UTF-8\n\nmessage\nwith blank\n\nlines\n"
	if string(got) != want {
		t.Fatalf("rewritten commit = %q", got)
	}
}

func TestRelativeSpecsKeepsDirectoryPatternsQuoted(t *testing.T) {
	specs, err := config.BuildSpecs(t.TempDir(), []string{"src/private folder/", "src/token.txt", "outside/"})
	if err != nil {
		t.Fatal(err)
	}
	nested := relativeSpecs(specs, "src/")
	if len(nested) != 2 || nested[0].AttributePattern != `"/private folder/**"` || nested[1].AttributePattern != "/token.txt" {
		t.Fatalf("nested rules: %+v", nested)
	}
	inside := relativeSpecs(specs, "src/private folder/nested/")
	if len(inside) != 1 || !strings.EqualFold(inside[0].AttributePattern, "/**") {
		t.Fatalf("directory coverage lost: %+v", inside)
	}
}
