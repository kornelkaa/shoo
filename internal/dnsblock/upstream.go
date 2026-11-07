package dnsblock

import (
	"net"
	"strings"
	"sync"
	"time"
)

// DefaultFallback is used when the network gives no DNS servers.
var DefaultFallback = []string{"1.1.1.1", "8.8.8.8"}

// Upstreams finds the DNS servers of the network the computer is on. Once
// it is pointed at shoo, its own DNS setting is 127.0.0.1, so the servers come
// from the network itself (DHCP) instead. The result is cached briefly so
// that switching Wi-Fi networks is picked up.
type Upstreams struct {
	// Preferred returns servers that come first (e.g. DNS servers the user had
	// set by hand before shoo took over). It is called on every refresh, so it
	// sees servers saved after the DNS server started.
	Preferred func() []string
	// Fallback is used when nothing else is found (default DefaultFallback).
	Fallback []string
	// Lookup finds the network's servers (default: ask the system).
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
			// Link-local addresses (fe80::...) can't be reached without
			// naming the network interface, which "ip:53" doesn't.
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			out = append(out, net.JoinHostPort(ip.String(), "53"))
		}
	}
	if u.Preferred != nil {
		add(u.Preferred())
	}
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
