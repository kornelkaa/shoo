// Package local keeps shoo's own servers reachable only from this Mac.
package local

import (
	"fmt"
	"net"
	"net/http"
)

// RequireLoopback refuses listen addresses other machines could reach.
func RequireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing to use %s: only loopback IP addresses like 127.0.0.1 are allowed", addr)
	}
	return nil
}

// Request reports whether r was addressed to a loopback IP address, as
// shoo's own clients (macOS, `shoo status`) do. A website using DNS
// rebinding reaches the same port under its own name, so it is refused.
func Request(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
