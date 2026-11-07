// Package local keeps shoo's own servers reachable only from this computer.
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

// NoEmbed stops web pages from using one of shoo's own responses (the PAC
// file, stats) as a script or anything else they could read: a site could
// otherwise load the PAC file with <script src> and see which sites the user
// told shoo never to decrypt.
func NoEmbed(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
}
