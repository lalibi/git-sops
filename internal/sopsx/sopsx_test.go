package sopsx

import "testing"

func TestTypesFor(t *testing.T) {
	cases := map[string]Types{
		"a/b.json":      {"json", "json"},
		"A.YAML":        {"yaml", "yaml"},
		"x.yml":         {"yaml", "yaml"},
		"prod.env":      {"dotenv", "dotenv"},
		"c.ini":         {"ini", "ini"},
		"secrets/a.txt": {"binary", "json"},
		"noext":         {"binary", "json"},
	}
	for path, want := range cases {
		if got := TypesFor(path); got != want {
			t.Errorf("TypesFor(%q) = %+v, want %+v", path, got, want)
		}
	}
}
