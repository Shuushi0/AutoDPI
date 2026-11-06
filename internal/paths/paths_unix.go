//go:build !windows

package paths

const (
	Label = "com.autodpi.daemon"
	Plist = "/Library/LaunchDaemons/" + Label + ".plist"
	Link  = "/usr/local/bin/autodpi"
)

const exeSuffix = ""

func systemDefault() Set {
	return under("/Library/Application Support/AutoDPI", "/var/run/autodpi.sock", "/var/log/autodpi.log")
}
