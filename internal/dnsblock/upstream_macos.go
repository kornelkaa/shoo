//go:build !windows

package dnsblock

import (
	"os/exec"
	"regexp"
	"strings"
)

var ipRe = regexp.MustCompile(`[0-9a-fA-F:.]+`)

// systemServers asks macOS for the DNS servers the network handed out:
// the DHCP packet of the main network interface, then the main network
// service's DNS state.
func systemServers() []string {
	var out []string
	primary := scutil("show State:/Network/Global/IPv4")
	if iface := field(primary, "PrimaryInterface"); iface != "" {
		pkt, _ := exec.Command("/usr/sbin/ipconfig", "getpacket", iface).Output()
		for _, l := range strings.Split(string(pkt), "\n") {
			if strings.HasPrefix(l, "domain_name_server") {
				if i := strings.IndexByte(l, '{'); i >= 0 {
					out = append(out, ipRe.FindAllString(l[i:], -1)...)
				}
			}
		}
	}
	if svc := field(primary, "PrimaryService"); svc != "" {
		dns := scutil("show State:/Network/Service/" + svc + "/DNS")
		inServers := false
		for _, l := range strings.Split(dns, "\n") {
			l = strings.TrimSpace(l)
			switch {
			case strings.HasPrefix(l, "ServerAddresses"):
				inServers = true
			case inServers && l == "}":
				inServers = false
			case inServers:
				if _, v, ok := strings.Cut(l, " : "); ok {
					out = append(out, strings.TrimSpace(v))
				}
			}
		}
	}
	return out
}

func scutil(cmd string) string {
	c := exec.Command("/usr/sbin/scutil")
	c.Stdin = strings.NewReader(cmd + "\n")
	out, _ := c.Output()
	return string(out)
}

// field finds "  Name : value" in scutil output.
func field(out, name string) string {
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), " : "); ok && k == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
