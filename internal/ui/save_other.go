//go:build !windows

package ui

import (
	"fmt"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

// saveElevated only exists on Windows; elsewhere (tests that pretend to be
// Windows) it reports what the real one would need.
func saveElevated(_ string, _ []byte, cause error) error {
	return fmt.Errorf(i18n.T("config.json yazılamadı (%v): yönetici izni gerekiyor", "config.json could not be written (%v): administrator permission is needed"), cause)
}

// shareConfig has nothing to do here: the file is written 0644.
func shareConfig(string, string) {}
