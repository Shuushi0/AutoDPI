package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTidyTakesOutTheRetiredKeyAndNothingElse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"auto_update": false, "hedge_ms": 900, "ciadpi_args": "-s 1", "my_note": "kept"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	did, err := Tidy(p)
	if err != nil || !did {
		t.Fatalf("Tidy: %v %v", did, err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	if strings.Contains(s, "auto_update") {
		t.Fatalf("the key is still there:\n%s", s)
	}
	for _, want := range []string{`"hedge_ms": 900`, `"ciadpi_args": "-s 1"`, `"my_note": "kept"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("%s was lost:\n%s", want, s)
		}
	}
	if c, err := Load(p); err != nil || c.HedgeMS != 900 {
		t.Fatalf("the tidied file does not load as before: %+v %v", c.HedgeMS, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("the file's mode changed: %v", fi.Mode().Perm())
	}
	// Nothing left to take out: not written again.
	if did, err := Tidy(p); did || err != nil {
		t.Fatalf("second Tidy: %v %v", did, err)
	}
}

func TestTidyLeavesOtherFilesAlone(t *testing.T) {
	dir := t.TempDir()
	if did, err := Tidy(filepath.Join(dir, "none.json")); did || err != nil {
		t.Fatalf("a missing file: %v %v", did, err)
	}
	for name, body := range map[string]string{
		"no key":            `{"hedge_ms":900}` + "\n\n  ",
		"not JSON":          `{"auto_update": true,`,
		"refused value":     `{"auto_update": true, "engines": ["nope"]}`,
		"null":              `null`,
		"a list, not a map": `["auto_update"]`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		did, _ := Tidy(p)
		after, _ := os.ReadFile(p)
		if did || string(after) != body {
			t.Fatalf("%s: the file was rewritten (%v):\n%s", name, did, after)
		}
	}
}
