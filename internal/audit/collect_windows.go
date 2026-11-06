package audit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

// The NRPT: rules a tool or the user added, and rules that came with a policy.
var nrptKeys = []string{
	`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`,
	`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`,
}

func readNRPT(path string) ([]Policy, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	var out []Policy
	for _, sub := range subs {
		r, err := registry.OpenKey(k, sub, registry.READ)
		if err != nil {
			continue
		}
		names, _, _ := r.GetStringsValue("Name")
		servers, _, _ := r.GetStringValue("GenericDNSServers")
		r.Close()
		// A rule without servers only sets DNSSEC or the like: it does not move queries.
		if list := splitServers(servers); len(names) > 0 && len(list) > 0 {
			out = append(out, Policy{Names: normalizeNames(names), Servers: list})
		}
	}
	return out, nil
}

func readAdapters() ([]AdapterDNS, error) {
	size := uint32(16 * 1024)
	for range 3 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []AdapterDNS
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			d := AdapterDNS{Name: windows.UTF16PtrToString(a.FriendlyName)}
			for s := a.FirstDnsServerAddress; s != nil; s = s.Next {
				if ip := s.Address.IP(); ip != nil {
					d.Servers = append(d.Servers, ip.String())
				}
			}
			if len(d.Servers) > 0 {
				out = append(out, d)
			}
		}
		return out, nil
	}
	return nil, errors.New("adapter list keeps growing")
}

// Collect reads what decides where names resolve.
func Collect(ctx context.Context) Facts {
	var f Facts
	for _, key := range nrptKeys {
		ps, err := readNRPT(key)
		if err != nil {
			f.Errors = append(f.Errors, "NRPT: "+err.Error())
		}
		f.Policies = append(f.Policies, ps...)
	}
	if out, err := exec.CommandContext(ctx, "netstat", "-ano").Output(); err != nil {
		f.Errors = append(f.Errors, "netstat: "+err.Error())
	} else {
		f.Listeners = parseNetstat(string(out), sysx.ProcessNames())
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	if b, err := os.ReadFile(filepath.Join(root, "System32", "drivers", "etc", "hosts")); err == nil {
		f.Hosts = parseHosts(string(b))
	} else if !errors.Is(err, os.ErrNotExist) {
		f.Errors = append(f.Errors, "hosts: "+err.Error())
	}
	if as, err := readAdapters(); err != nil {
		f.Errors = append(f.Errors, "adapters: "+err.Error())
	} else {
		f.Adapters = as
	}
	return f
}
