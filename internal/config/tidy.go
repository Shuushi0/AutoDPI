package config

import (
	"encoding/json"
	"os"

	"github.com/Shuushi0/AutoDPI/internal/fsx"
)

// retired are the keys of earlier versions that nothing reads any more.
// "auto_update": until 0.1.1 a newer release could install by itself; now it
// is announced and installed when the user asks.
var retired = []string{"auto_update"}

// Retired reports whether key is one an earlier version had and this one no
// longer reads.
func Retired(key string) bool {
	for _, k := range retired {
		if k == key {
			return true
		}
	}
	return false
}

// Tidy takes the retired keys out of the config file at path and reports
// whether it rewrote the file. Everything else in the file is kept. A file
// that is missing, that the service cannot use as it is, or that has none of
// the keys is not touched.
func Tidy(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	raw := map[string]json.RawMessage{}
	if _, perr := Parse(b); perr != nil || json.Unmarshal(b, &raw) != nil {
		return false, nil // not ours to repair here; the page says what is wrong with it
	}
	found := false
	for _, k := range retired {
		if _, ok := raw[k]; ok {
			delete(raw, k)
			found = true
		}
	}
	if !found {
		return false, nil
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return false, err
	}
	out = append(out, '\n')
	if _, err := Parse(out); err != nil {
		return false, err // never write what the service would not read
	}
	perm := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}
	return true, fsx.WriteFile(path, out, perm)
}
