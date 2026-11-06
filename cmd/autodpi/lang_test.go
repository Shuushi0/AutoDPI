package main

import (
	"os"
	"testing"
)

// The tests read the Turkish texts; the language must not follow the
// machine's (child processes inherit the variable).
func TestMain(m *testing.M) {
	os.Setenv("AUTODPI_LANG", "tr")
	os.Exit(m.Run())
}
