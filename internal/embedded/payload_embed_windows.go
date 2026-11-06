//go:build embedbins

package embedded

import (
	"embed"
	"io"
)

// The slim sing-box windows-amd64 build (scripts/build-singbox.sh; or the
// official release's sing-box.exe) and byedpi's x86_64-w64 build, placed here
// by scripts/build-windows.sh together with their hashes
// (payload_hashes_windows_gen.go). sing-box's libcronet.dll is left out on
// purpose: sing-box.exe imports no DLLs statically and loads it only for the
// naive outbound, which this service never configures.
//
//go:embed payload/sing-box.exe payload/ciadpi.exe
var files embed.FS

func openPayload(name string) (io.ReadCloser, error) { return files.Open("payload/" + name) }
