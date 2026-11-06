package netx

import (
	"context"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the IP Helper API delivers route-table and interface changes
// (NotifyRouteChange2 and NotifyIpInterfaceChange), the counterpart of the
// routing socket on macOS.

var (
	iphlpapi                    = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyRouteChange2      = iphlpapi.NewProc("NotifyRouteChange2")
	procNotifyIpInterfaceChange = iphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = iphlpapi.NewProc("CancelMibChangeNotify2")
)

// The callbacks run on system threads. windows.NewCallback slots are never
// freed, so there is one callback for the whole process, made once; it calls
// whatever the current watch registered.
var (
	routeCallbackOnce sync.Once
	routeCallback     uintptr
	routeOnChange     struct {
		sync.Mutex
		fn func()
	}
)

func routeChanged(_, _, _ uintptr) uintptr {
	routeOnChange.Lock()
	fn := routeOnChange.fn
	routeOnChange.Unlock()
	if fn != nil {
		fn()
	}
	return 0
}

func watchRoutes(ctx context.Context, onChange func()) error {
	if err := procNotifyRouteChange2.Find(); err != nil {
		return err
	}
	routeCallbackOnce.Do(func() { routeCallback = windows.NewCallback(routeChanged) })
	routeOnChange.Lock()
	routeOnChange.fn = onChange
	routeOnChange.Unlock()

	const afUnspec = 0 // IPv4 and IPv6
	var route, iface windows.Handle
	if r, _, _ := procNotifyRouteChange2.Call(afUnspec, routeCallback, 0, 0, uintptr(unsafe.Pointer(&route))); r != 0 {
		return syscall.Errno(r)
	}
	// Interface changes (an address arrives with DHCP, an adapter goes down)
	// are worth a pulse too; a failure here still leaves route changes.
	if r, _, _ := procNotifyIpInterfaceChange.Call(afUnspec, routeCallback, 0, 0, uintptr(unsafe.Pointer(&iface))); r != 0 {
		iface = 0
	}
	go func() {
		<-ctx.Done()
		_, _, _ = procCancelMibChangeNotify2.Call(uintptr(route))
		if iface != 0 {
			_, _, _ = procCancelMibChangeNotify2.Call(uintptr(iface))
		}
		routeOnChange.Lock()
		routeOnChange.fn = nil
		routeOnChange.Unlock()
	}()
	return nil
}
