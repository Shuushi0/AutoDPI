//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLanguageFollowsTheSetting(t *testing.T) {
	home := t.TempDir()
	run := func(env string, args ...string) string {
		cmd := exec.Command(area4Bin(t), args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "AUTODPI_HOME=" + home, env}
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	if out := run("AUTODPI_LANG=en", "help"); !strings.Contains(out, "local, transparent DPI-bypass service") {
		t.Errorf("English help:\n%s", out)
	}
	if out := run("AUTODPI_LANG=tr", "help"); !strings.Contains(out, "yerel, şeffaf DPI-bypass servisi") {
		t.Errorf("Turkish help:\n%s", out)
	}
	// Without the variable the settings decide.
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(`{"language":"en"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := run("AUTODPI_LANG=", "lang"); out != "en\n" {
		t.Errorf("lang with config en: %q", out)
	}
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(`{"language":"tr"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := run("AUTODPI_LANG=", "lang"); out != "tr\n" {
		t.Errorf("lang with config tr: %q", out)
	}
	if out := run("AUTODPI_LANG=en", "status"); !strings.Contains(out, "error: the service is not running") {
		t.Errorf("English error: %q", out)
	}
}
