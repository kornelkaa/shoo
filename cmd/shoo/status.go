package main

// `shoo status`, and small helpers shared by every platform.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"time"

	"shoo/internal/certs"
	"shoo/internal/cosmetic"
	"shoo/internal/netfilter"
	"shoo/internal/sites"
)

func status(dir, addr, pacURL string) {
	fmt.Println("Certificate:")
	if t, err := isTrusted(dir); err != nil {
		fmt.Println("  missing:", err)
	} else if t && caConstrained(dir) {
		fmt.Println("  trusted, but YouTube only (run `shoo setup` to hide ads on other websites)")
	} else if t {
		fmt.Println("  trusted")
		if ca, err := certs.Load(dir); err == nil {
			fmt.Printf("  valid until %s\n", ca.Cert.NotAfter.Format("2006-01-02"))
			if r := certs.ReplaceReason(ca.Cert, sites.Exclusions(), loadSettings(dir).Sites != sitesOff); r != "" {
				fmt.Printf("  should be replaced (%s): run `shoo setup`\n", r)
			}
		}
	} else {
		fmt.Println("  NOT trusted (run `shoo trust`)")
	}

	fmt.Printf("Proxy on %s:\n", addr)
	c := http.Client{Timeout: 2 * time.Second}
	if resp, err := c.Get(pacURL); err != nil {
		fmt.Println("  NOT running (run `shoo start`)")
	} else {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Println("  running")
	}

	fmt.Println("Background service:")
	set := loadSettings(dir)
	if agentLoaded() && set.StartAtLogin {
		fmt.Println("  installed (starts at login)")
	} else if agentLoaded() {
		fmt.Println("  installed (doesn't start at login: run `shoo start`)")
	} else if agentInstalled() {
		fmt.Println("  stopped (run `shoo start`)")
	} else {
		fmt.Println("  not installed (run `shoo setup`)")
	}

	fmt.Println("Other websites:")
	if set.Sites == sitesOff {
		fmt.Println("  off (YouTube only; change with `shoo setup`)")
	} else if fi, err := os.Stat(filepath.Join(dir, sites.BlocklistFile)); err != nil {
		fmt.Println("  no ad-domain list (run `shoo update-lists`)")
	} else if l, err := sites.Load(dir); err == nil {
		fmt.Printf("  %d ad domains, list updated %s\n", l.Len(), fi.ModTime().Format("2006-01-02 15:04"))
		if r, err := cosmetic.Load(dir); err == nil && r.Len() > 0 {
			fmt.Printf("  %d rules for hiding ad boxes\n", r.Len())
			if nr, err := netfilter.Load(dir, cosmetic.ListFile); err == nil {
				fmt.Printf("  %d URL rules (single ad scripts, images, trackers)\n", nr.Len())
			}
		} else {
			fmt.Println("  no element-hiding lists (run `shoo update-lists`)")
		}
		fmt.Printf("  %d sites never decrypted (banks, logins...; add with `shoo skip`)\n", len(sites.Exclusions()))
	}
	var st sites.Stats
	if resp, err := c.Get("http://" + addr + "/stats"); err == nil {
		if resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&st) == nil {
			fmt.Printf("  %d ad requests blocked by the proxy since it started\n", st.Blocked)
		} else {
			fmt.Println("  proxy is running YouTube-only (-sites=false)")
		}
		resp.Body.Close()
	}

	if set.Sites != sitesOff {
		dnsStatus()
	}

	networkStatus(pacURL, set.Sites != sitesOff)
}

// pacLine describes one network setting, for `shoo status`.
func pacLine(cur string, on bool, pacURL string) string {
	switch {
	case on && cur == pacURL:
		return "on"
	case on && isShooPAC(cur):
		return "on, but an older PAC address (run `shoo setup`)"
	case on:
		return "not shoo (another PAC file is on: " + cur + ")"
	}
	return "off"
}

// isShooPAC reports whether url is a shoo PAC file: any version of it, and
// on any port (setup gives each user their own, and older versions used
// 8899).
func isShooPAC(url string) bool {
	u, err := neturl.Parse(url)
	if err != nil || u.Scheme != "http" || u.Path != "/proxy.pac" || u.Port() == "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
