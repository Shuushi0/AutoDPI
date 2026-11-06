//go:build !windows

package i18n

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// systemLanguage is the language the user chose: an explicit LC_ALL or
// LC_MESSAGES, then (macOS) the first of the preferred languages in System
// Settings, then LANG.
func systemLanguage() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES"} {
		if v := os.Getenv(k); v != "" && v != "C" && v != "POSIX" {
			return v
		}
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("/usr/bin/defaults", "read", "-g", "AppleLanguages").Output(); err == nil {
			// ( "tr-TR", "en-US" )
			for _, f := range strings.FieldsFunc(string(out), func(r rune) bool { return strings.ContainsRune("()\", \n\t", r) }) {
				return f
			}
		}
	}
	return os.Getenv("LANG")
}
