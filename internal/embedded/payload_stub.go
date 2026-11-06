//go:build !embedbins

package embedded

import "io"

func openPayload(string) (io.ReadCloser, error) { return nil, errNotEmbedded }

// payloadHashes is empty: nothing is embedded, Prepare uses devBins.
var payloadHashes = map[string]string{}
