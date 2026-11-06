package i18n

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"tr": "tr", "tr_TR.UTF-8": "tr", "tr-TR": "tr", "TR": "tr", "en": "en", "en_US.UTF-8": "en",
		"en-GB": "en", "de_DE": "", "": "", "trk": "", "turkish": "",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChoiceOrder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AUTODPI_HOME", home)
	cfg := filepath.Join(home, "config.json")

	t.Setenv("AUTODPI_LANG", "")
	if err := os.WriteFile(cfg, []byte(`{"language":"tr"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	Reload()
	if !Turkish() || T("a", "b") != "a" || Lang() != "tr" {
		t.Fatal("config.json language tr not used")
	}

	t.Setenv("AUTODPI_LANG", "en_US.UTF-8") // the environment wins over the file
	Reload()
	if Turkish() || T("a", "b") != "b" {
		t.Fatal("AUTODPI_LANG not used")
	}

	t.Setenv("AUTODPI_LANG", "")
	if err := os.WriteFile(cfg, []byte(`{"language":"en"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	Reload()
	if Turkish() {
		t.Fatal("config.json language en not used")
	}
	Reload()
}
