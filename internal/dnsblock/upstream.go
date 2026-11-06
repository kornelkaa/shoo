package dnsblock

import (
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultFallback is used when the network gives no DNS servers.
var DefaultFallback = []string{"1.1.1.1", "8.8.8.8"}

// Upstreams finds the DNS servers of the network the Mac is on. Once macOS
// is pointed at shoo, its own DNS setting is 127.0.0.1, so the servers come
// from the network itself (DHCP) instead. The result is cached briefly so
// that switching Wi-Fi networks is picked up.
type Upstreams struct {
	// Preferred servers come first (e.g. DNS servers the user had set by hand
	// before shoo took over).
	Preferred []string
	// Fallback is used when nothing else is found (default DefaultFallback).
	Fallback []string
	// Lookup finds the network's servers (default: ask macOS).
	Lookup func() []string
	TTL    time.Duration

	mu      sync.Mutex
	cached  []string
	expires time.Time
}

// Servers returns "ip:53" addresses, never this machine's own address.
func (u *Upstreams) Servers() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cached != nil && time.Now().Before(u.expires) {
		return u.cached
	}
	lookup := u.Lookup
	if lookup == nil {
		lookup = systemServers
	}
	fallback := u.Fallback
	if fallback == nil {
		fallback = DefaultFallback
	}
	var out []string
	seen := map[string]bool{}
	add := func(ips []string) {
		for _, s := range ips {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			out = append(out, net.JoinHostPort(ip.String(), "53"))
		}
	}
	add(u.Preferred)
	add(lookup())
	if len(out) == 0 {
		add(fallback)
	}
	ttl := u.TTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	u.cached, u.expires = out, time.Now().Add(ttl)
	return out
}

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
