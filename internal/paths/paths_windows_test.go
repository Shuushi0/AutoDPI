//go:build windows

package paths

import (
	"path/filepath"
	"testing"
)

func TestSystemDefaultSocketInOwnDir(t *testing.T) {
	t.Setenv("AUTODPI_HOME", "")
	t.Setenv("ProgramData", `C:\Evil`) // W9: the variable must not matter
	s := Default()
	if filepath.Dir(s.Sock) == s.Support || filepath.Dir(filepath.Dir(s.Sock)) != s.Support {
		t.Errorf("socket %s should sit in a sub-directory of %s", s.Sock, s.Support)
	}
	if filepath.VolumeName(s.Support) == "" || filepath.Dir(s.Support) == `C:\Evil` {
		t.Errorf("Support %s was derived from the environment", s.Support)
	}
}
