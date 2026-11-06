//go:build darwin

package netid

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// gatewayMAC returns the link-layer address of gw from the ARP cache, or "".
func gatewayMAC(gw string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/arp", "-n", gw).Output()
	if err != nil {
		return ""
	}
	_, rest, ok := strings.Cut(string(out), " at ")
	if !ok {
		return ""
	}
	f := strings.Fields(rest)
	if len(f) == 0 || f[0] == "(incomplete)" {
		return ""
	}
	return f[0]
}
