package main

// `shoo status`.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	for _, l := range trustNotes(dir) {
		fmt.Println("  " + l)
	}

	fmt.Printf("Proxy on %s:\n", addr)
	c := http.Client{Timeout: 2 * time.Second}
	if resp, err := c.Get(pacURL); err != nil {
		fmt.Println("  NOT running (run `shoo run`)")
	} else {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Println("  running")
	}

	fmt.Println("Background service:")
	set := loadSettings(dir)
	switch {
	case agentLoaded() && set.StartAtLogin:
		fmt.Println("  installed (starts at login)")
	case agentLoaded():
		fmt.Println("  installed (doesn't start at login: run `shoo start`)")
	case agentInstalled():
		fmt.Println("  stopped (run `shoo start`)")
	default:
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
		fmt.Printf("  %d sites never decrypted (banks, logins, Apple...; add with `shoo skip`)\n", len(sites.Exclusions()))
	}
	var st sites.Stats
	if resp, err := c.Get("http://" + addr + "/stats"); err == nil {
		if resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&st) == nil {
			fmt.Println("  " + statsSummary(loadStats(dir, addr), time.Now()))
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

// isShooPAC reports whether url is shoo's PAC file, any version of it.
func isShooPAC(url, pacURL string) bool {
	base, _, _ := strings.Cut(pacURL, "?")
	return url == base || strings.HasPrefix(url, base+"?")
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
