//go:build !windows

package launchd

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	b, err := Render("/Library/Application Support/AutoDPI/autodpi")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"<string>com.autodpi.daemon</string>",
		"<string>/Library/Application Support/AutoDPI/autodpi</string>",
		"<string>daemon</string>",
		"<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>",
		"<key>RunAtLoad</key>",
		"<integer>16384</integer>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist lacks %q", want)
		}
	}
}
