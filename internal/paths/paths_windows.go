package paths

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ServiceName is the Windows service (sc.exe query AutoDPI).
const ServiceName = "AutoDPI"

const exeSuffix = ".exe"

// programData asks the shell for C:\ProgramData instead of trusting the
// ProgramData environment variable, which a user can set in the shell that
// runs the CLI. The fallback derives the system drive from the (trusted)
// system directory.
func programData() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
		return p
	}
	if d, err := windows.GetSystemDirectory(); err == nil && filepath.VolumeName(d) != "" {
		return filepath.VolumeName(d) + `\ProgramData`
	}
	return `C:\ProgramData`
}

// systemDefault keeps everything under %ProgramData%\AutoDPI, the
// Windows counterpart of /Library/Application Support. The control socket
// is an AF_UNIX socket (Windows 10 1803+) in its own protected sub-directory
// (ctl): the socket's DACL cannot be trusted alone, the directory's owner and
// DACL are what keeps other users from swapping it. The log lives in the root
// because there is no /var/log.
func systemDefault() Set {
	root := filepath.Join(programData(), "AutoDPI")
	return under(root, filepath.Join(root, "ctl", "ctl.sock"), filepath.Join(root, "autodpi.log"))
}
