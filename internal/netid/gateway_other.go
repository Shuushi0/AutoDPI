//go:build !darwin && !windows

package netid

func gatewayMAC(string) string { return "" }
