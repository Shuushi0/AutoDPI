//go:build embedbins && !windows

package embedded

import (
	"embed"
	"io"
)

//go:embed payload/sing-box payload/ciadpi
var files embed.FS

// openPayload streams from the executable's read-only data; ReadFile would
// copy the whole helper (tens of MB) onto the heap.
func openPayload(name string) (io.ReadCloser, error) { return files.Open("payload/" + name) }
