package sysx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

// AdminHint is how the user gets the privileges IsRoot asks for.
func AdminHint() string {
	return i18n.T("yönetici (Run as administrator) terminali", "an administrator (Run as administrator) terminal")
}

// IsRoot reports whether the process runs with an elevated token: an
// administrator's "Run as administrator" shell, or LocalSystem (the service).
func IsRoot() bool { return windows.GetCurrentProcessToken().IsElevated() }

// dirSDDL mirrors the macOS root:wheel 0755 install root. SYSTEM and
// Administrators may change anything (and, through inheritance, everything
// below); ordinary users get read/execute on the directory itself only, with
// no inheritable ACE: they can reach the installed executable (which gets its
// own ACE, see exeSDDL) and the control-socket directory, but cannot read the
// state and log files (config.json gets an ACE of its own, see configSDDL).
// P (protected) drops what C:\ProgramData would otherwise pass down, which
// lets any user create files in a new sub-directory: a service running as
// SYSTEM must not execute anything a user could have planted next to it.
const dirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)"

// exeSDDL is for the installed autodpi.exe: everybody may run it (the
// unelevated `autodpi status` is the point), only SYSTEM/Administrators
// may replace it.
const exeSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"

// configSDDL is for config.json: signed-in (interactive) users may read it, so
// that the tray app and an unelevated settings page show the real settings and
// language; only SYSTEM and Administrators may change it. Without it the file
// inherits dirSDDL's SYSTEM/Administrators-only access like everything else in
// the install directory.
const configSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;IU)"

// ctlDirSDDL is for the directory that holds nothing but the control socket.
// Interactively logged-on users may enter it, and the socket file inherits
// read/write for them; ipc re-applies and verifies a socket DACL of its own.
const ctlDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;IU)(A;OICIIO;FRFW;;;IU)"

const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// isTrustedOwner: only SYSTEM and Administrators may own what a SYSTEM
// service executes or trusts. An owner keeps WRITE_DAC whatever the DACL says.
func isTrustedOwner(o *windows.SID) bool {
	return o != nil && (o.IsWellKnown(windows.WinLocalSystemSid) || o.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

// openNoFollow opens path itself, not what a link there points at. AF_UNIX
// socket files are reparse points that a plain open refuses with
// ERROR_CANT_ACCESS_FILE, and a directory needs BACKUP_SEMANTICS anyway.
func openNoFollow(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access, shareAll, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

// ownerAndKind reads, through h, the owner and whether the object is a
// reparse point (symlink, junction, mount point) and a directory.
func ownerAndKind(h windows.Handle) (owner *windows.SID, reparse, dir bool, err error) {
	var fi windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &fi); err != nil {
		return nil, false, false, err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, false, false, err
	}
	owner, _, err = sd.Owner()
	return owner, fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0,
		fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, err
}

// EnsureTrustedDir makes dir a plain directory that only SYSTEM and
// Administrators control, with dirSDDL on it.
func EnsureTrustedDir(dir string) error { return ensureDir(dir, dirSDDL) }

// EnsureCtlDir is EnsureTrustedDir with ctlDirSDDL, for the control-socket
// directory.
func EnsureCtlDir(dir string) error { return ensureDir(dir, ctlDirSDDL) }

// SecureDir is what the platform-neutral callers (install, daemon start,
// embedded.Prepare) use; unlike the macOS no-op it creates a missing
// directory, atomically with the DACL, and fails closed.
func SecureDir(dir string) error { return EnsureTrustedDir(dir) }

// ensureDir creates dir atomically with the DACL in sddl (no window in which
// it is writable by others and no chance to pre-create it as a plain user),
// or, when it exists, refuses anything that is not a plain directory owned by
// SYSTEM/Administrators before (re)applying the DACL through the very handle
// it inspected.
func ensureDir(dir, sddl string) error {
	// O:BA pins the owner to Administrators instead of whatever the creating
	// token's default owner is (the elevated user's SID under some policies),
	// so the service's own start-up check (owner is trusted) cannot fail on a
	// directory the installer just made.
	sd, err := windows.SecurityDescriptorFromString("O:BA" + sddl)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(p, sa)
	if errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		if err = os.MkdirAll(filepath.Dir(dir), 0o755); err == nil {
			err = windows.CreateDirectory(p, sa)
		}
	}
	runtime.KeepAlive(sd)
	if err == nil {
		return nil // ours: owned by the caller's default owner, DACL set at creation
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	h, err := openNoFollow(dir, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return fmt.Errorf(i18n.T("%s var ama açılamıyor: %w", "%s exists and cannot be opened: %w"), dir, err)
	}
	defer windows.CloseHandle(h)
	owner, reparse, isDir, err := ownerAndKind(h)
	if err != nil {
		return err
	}
	if reparse || !isDir {
		return fmt.Errorf(i18n.T("%s var ama düz bir klasör değil (bağlantı, junction ya da dosya): silip yeniden deneyin", "%s exists and is not a plain directory (link, junction or file): delete it and retry"), dir)
	}
	if !isTrustedOwner(owner) {
		return fmt.Errorf(i18n.T("%s klasörünün sahibi %s, SYSTEM ya da Administrators değil: silin (ya da sahipliğini alın) ve yeniden deneyin", "%s is owned by %s, not SYSTEM/Administrators: delete it (or take ownership) and retry"), dir, owner)
	}
	return setDACLHandle(h, sddl)
}

// CheckTrustedDir verifies dir is a plain directory owned by SYSTEM or
// Administrators, without changing it.
func CheckTrustedDir(dir string) error {
	h, err := openNoFollow(dir, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	owner, reparse, isDir, err := ownerAndKind(h)
	if err != nil {
		return err
	}
	if reparse || !isDir {
		return fmt.Errorf("%s is not a plain directory", dir)
	}
	if !isTrustedOwner(owner) {
		return fmt.Errorf("%s is owned by %s, not SYSTEM/Administrators", dir, owner)
	}
	return nil
}

func setDACLHandle(h windows.Handle, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// SetDACL replaces path's DACL with the one in sddl and blocks inheritance.
// It acts on path itself (see openNoFollow), so it also works on a socket
// file and is not redirected by a link planted there.
func SetDACL(path, sddl string) error {
	h, err := openNoFollow(path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return setDACLHandle(h, sddl)
}

// SecureExe gives the installed executable exeSDDL.
func SecureExe(path string) error { return SetDACL(path, exeSDDL) }

// ShareConfig gives path, the config file in the locked-down install
// directory, configSDDL. It refuses a link or a directory there; a missing
// file is an fs.ErrNotExist error.
func ShareConfig(path string) error {
	h, err := openNoFollow(path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	_, reparse, isDir, err := ownerAndKind(h)
	if err != nil {
		return err
	}
	if reparse || isDir {
		return fmt.Errorf(i18n.T("%s düz bir dosya değil (bağlantı ya da klasör)", "%s is not a plain file (a link or a directory)"), path)
	}
	return setDACLHandle(h, configSDDL)
}

// CheckProtectedDACL verifies that path's DACL does not inherit, is not
// NULL, and has ACEs only for the allowed well-known SIDs.
func CheckProtectedDACL(path string, allow ...windows.WELL_KNOWN_SID_TYPE) error {
	h, err := openNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	ctl, _, err := sd.Control()
	if err != nil {
		return err
	}
	if ctl&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("DACL of %s still inherits: %s", path, sd)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil {
		return fmt.Errorf("%s has a NULL DACL (everyone has full access)", path)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		// Allowed and denied ACEs share one layout; anything else (object,
		// callback, audit ACEs) is not something we ever set.
		if t := ace.Header.AceType; t != windows.ACCESS_ALLOWED_ACE_TYPE && t != windows.ACCESS_DENIED_ACE_TYPE {
			return fmt.Errorf("unexpected ACE type %d on %s: %s", t, path, sd)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		ok := false
		for _, w := range allow {
			if sid.IsWellKnown(w) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%s grants access to %s: %s", path, sid, sd)
		}
	}
	return nil
}

// OwnByRoot makes sure path is owned by SYSTEM or Administrators (the macOS
// root:wheel). A file an elevated process just created already is; if not, it
// is handed to Administrators, and an error is returned when that fails or
// when path is a link: an owner can rewrite the DACL, and the file is going to
// be executed by SYSTEM.
func OwnByRoot(path string) error {
	h, err := openNoFollow(path, windows.READ_CONTROL|windows.WRITE_OWNER)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	owner, reparse, _, err := ownerAndKind(h)
	if err != nil {
		return err
	}
	if reparse {
		return fmt.Errorf("%s is a link", path)
	}
	if isTrustedOwner(owner) {
		return nil
	}
	ba, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, ba, nil, nil, nil); err != nil {
		return fmt.Errorf("%s is owned by %s and cannot be handed to Administrators: %w", path, owner, err)
	}
	return nil
}

type proc struct {
	pid  uint32
	exe  string // image file name, e.g. sing-box.exe
	path string // full image path, "" when it cannot be queried
}

func processes(withPath bool) []proc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var out []proc
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := proc{pid: e.ProcessID, exe: windows.UTF16ToString(e.ExeFile[:])}
		if withPath && p.pid != 0 {
			p.path = imagePath(p.pid)
		}
		out = append(out, p)
	}
	return out
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// KillByPath terminates every process whose image is one of paths (compared
// case-insensitively, as NTFS does). It reports the paths that matched.
func KillByPath(paths ...string) []string {
	want := map[string]string{}
	for _, p := range paths {
		want[strings.ToLower(filepath.Clean(p))] = p
	}
	seen := map[string]bool{}
	var hit []string
	for _, p := range processes(true) {
		orig, ok := want[strings.ToLower(filepath.Clean(p.path))]
		if p.path == "" || !ok {
			continue
		}
		if terminateAndWait(p.pid) && !seen[orig] {
			seen[orig] = true
			hit = append(hit, orig)
		}
	}
	return hit
}

// killWait bounds the wait for one terminated process to be gone.
const killWait = 5 * time.Second

// terminateAndWait ends pid and returns once the process object is signalled,
// i.e. the image is no longer mapped and can be replaced. TerminateProcess
// alone is asynchronous: the daemon's next step (rewriting sing-box.exe) used
// to hit sharing violations.
func terminateAndWait(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	if windows.TerminateProcess(h, 1) != nil {
		return false
	}
	_, _ = windows.WaitForSingleObject(h, uint32(killWait/time.Millisecond))
	return true
}

// ProcessRunning reports whether a process with image file name name runs
// (case-insensitive, e.g. "warp-svc.exe").
func ProcessRunning(name string) bool {
	for _, p := range processes(false) {
		if strings.EqualFold(p.exe, name) {
			return true
		}
	}
	return false
}

// ProcessNames maps running process IDs to their image file names.
func ProcessNames() map[uint32]string {
	out := map[uint32]string{}
	for _, p := range processes(false) {
		out[p.pid] = p.exe
	}
	return out
}

// conflictingTools are other DPI-bypass programs that rewrite the same
// outgoing packets through WinDivert. Next to them the capture fails its own
// TLS check (their decoy ClientHello reaches the server and is answered), and
// browsers get ERR_SSL_PROTOCOL_ERROR, so the daemon waits until they close.
var conflictingTools = []struct{ exe, name string }{
	{"goodbyedpi.exe", "GoodbyeDPI"},
	{"winws.exe", "zapret (winws)"},
}

// ConflictingTool returns the name of a running DPI-bypass program that works
// on the same packets, if there is one.
func ConflictingTool() (string, bool) {
	ps := processes(false)
	for _, t := range conflictingTools {
		for _, p := range ps {
			if strings.EqualFold(p.exe, t.exe) {
				return t.name, true
			}
		}
	}
	return "", false
}

// KillOtherInstances terminates every other process of the running
// executable's image name (autodpi.exe): after the service is gone these are
// only settings-page servers (`autodpi ui`, started hidden by the Windows
// menu) and stray CLI calls, which would otherwise live on after an uninstall.
func KillOtherInstances() int {
	self, err := os.Executable()
	if err != nil {
		return 0
	}
	name := filepath.Base(self)
	me := uint32(os.Getpid())
	n := 0
	for _, p := range processes(false) {
		if p.pid != me && strings.EqualFold(p.exe, name) && terminateAndWait(p.pid) {
			n++
		}
	}
	return n
}
