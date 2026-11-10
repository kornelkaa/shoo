package dnsblock

import (
	"net"
	"strings"
)

// parseNMCLI finds DNS servers in the output of
// `nmcli -t -g IP4.DNS,IP6.DNS,DHCP4.OPTION,DHCP6.OPTION device show`:
// plain addresses (IP4.DNS) and the name servers the network's DHCP server
// handed out ("domain_name_servers = 192.168.1.1 1.1.1.1"). Terse output
// separates values with " | " and escapes colons.
func parseNMCLI(out string) []string {
	out = strings.ReplaceAll(out, `\:`, ":")
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		for _, item := range strings.Split(line, " | ") {
			item = strings.TrimSpace(item)
			if k, v, ok := strings.Cut(item, "="); ok {
				switch strings.TrimSpace(k) {
				case "domain_name_servers", "dhcp6_name_servers":
					for _, f := range strings.Fields(v) {
						if net.ParseIP(f) != nil {
							ips = append(ips, f)
						}
					}
				}
				continue
			}
			if net.ParseIP(item) != nil {
				ips = append(ips, item)
			}
		}
	}
	return ips
}

// parseResolvConf finds the "nameserver" lines of a resolv.conf file.
func parseResolvConf(s string) []string {
	var ips []string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil {
			ips = append(ips, f[1])
		}
	}
	return ips
}
