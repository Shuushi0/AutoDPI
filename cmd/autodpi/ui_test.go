package main

import (
	"slices"
	"strings"
	"testing"
)

func TestBrowserCommand(t *testing.T) {
	const url = "http://127.0.0.1:1234/?t=abc"
	t.Setenv("SystemRoot", `C:\Windows`)
	name, args := browserCommand("windows", url)
	if !strings.HasSuffix(name, "rundll32.exe") || !strings.HasPrefix(name, `C:\Windows`) || !slices.Equal(args, []string{"url.dll,FileProtocolHandler", url}) {
		t.Errorf("windows: %s %q", name, args)
	}
	if name, args := browserCommand("darwin", url); name != "/usr/bin/open" || !slices.Equal(args, []string{url}) {
		t.Errorf("darwin: %s %q", name, args)
	}
}
