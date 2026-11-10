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
// the system is pointed at shoo, its own DNS setting is 127.0.0.1, so the servers come
// from the network itself (DHCP) instead. The result is cached briefly so
// that switching Wi-Fi networks is picked up.
type Upstreams struct {
	// Preferred servers come first (e.g. DNS servers the user had set by hand
	// before shoo took over).
	Preferred []string
	// Fallback is used when nothing else is found (default DefaultFallback).
	Fallback []string
	// Lookup finds the network's servers (default: ask the system,
	// upstream_darwin.go / upstream_linux.go).
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
