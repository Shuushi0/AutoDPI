//go:build !darwin && !windows

package netx

import "syscall"

func bindControl(int) func(network, address string, c syscall.RawConn) error { return nil }
