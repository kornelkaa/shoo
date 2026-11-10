//go:build linux

package dnsblock

import (
	"net"
	"os"
	"os/exec"
)

// systemServers asks Linux for the DNS servers the network handed out.
// Once shoo is on, NetworkManager's global DNS setting is 127.0.0.1, but
// each device still reports the servers it got from DHCP (or set by hand
// on the connection), so those come first. Without NetworkManager, the
// resolv.conf files are read instead (loopback entries are dropped later).
func systemServers() []string {
	if out, err := exec.Command("nmcli", "-t", "-g", "IP4.DNS,IP6.DNS,DHCP4.OPTION,DHCP6.OPTION", "device", "show").Output(); err == nil {
		if ips := nonLoopback(parseNMCLI(string(out))); len(ips) > 0 {
			return ips
		}
	}
	for _, f := range []string{
		"/run/NetworkManager/no-stub-resolv.conf",
		"/run/systemd/resolve/resolv.conf",
		"/etc/resolv.conf",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if ips := nonLoopback(parseResolvConf(string(b))); len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func nonLoopback(ips []string) []string {
	var out []string
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			out = append(out, s)
		}
	}
	return out
}
