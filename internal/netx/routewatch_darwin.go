//go:build darwin

package netx

import (
	"context"
	"encoding/binary"
	"os"
	"syscall"
)

// Routing-socket message types worth waking up for (net/route.h). RTM_GET,
// RTM_MISS, RTM_RESOLVE and friends are deliberately absent: our own
// `route get` calls produce RTM_GET and would feed back into themselves.
const (
	rtmAdd     = 0x1
	rtmDelete  = 0x2
	rtmChange  = 0x3
	rtmNewAddr = 0xc
	rtmDelAddr = 0xd
	rtmIfInfo  = 0xe
	rtmIfInfo2 = 0x12

	rtfHost      = 0x4
	rtfLLInfo    = 0x400   // ARP / neighbour entries come and go all the time
	rtfWasCloned = 0x20000 // host routes cloned from a network route
)

func relevant(msg []byte) bool {
	if len(msg) < 12 {
		return false
	}
	switch msg[3] {
	case rtmNewAddr, rtmDelAddr, rtmIfInfo, rtmIfInfo2:
		return true
	case rtmAdd, rtmDelete, rtmChange:
		flags := binary.NativeEndian.Uint32(msg[8:12])
		return flags&(rtfLLInfo|rtfWasCloned) == 0
	}
	return false
}

func watchRoutes(ctx context.Context, onChange func()) error {
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, 0)
	if err != nil {
		return err
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return err
	}
	f := os.NewFile(uintptr(fd), "route")
	if f == nil {
		syscall.Close(fd)
		return os.ErrInvalid
	}
	go func() {
		<-ctx.Done()
		f.Close() // unblocks the reader below
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			if relevant(buf[:n]) {
				onChange()
			}
		}
	}()
	return nil
}
