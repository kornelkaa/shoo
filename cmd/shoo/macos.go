package main

// macOS system integration: Keychain trust and network proxy settings.

import (
	"crypto/sha1"
	"encoding/json"
	"encoding/pem"
	"errors"
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

func loginKeychain() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

// trust adds the CA to the user's login keychain as a trusted root.
// macOS shows a password prompt. Safari and Chrome read this trust setting.
func trust(dir string) error {
	if os.Geteuid() == 0 {
		return errors.New("run `shoo trust` without sudo, so the certificate goes into your own keychain")
	}
	kc, err := loginKeychain()
	if err != nil {
		return err
	}
	return run("security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", kc, filepath.Join(dir, certs.CertFile))
}

// untrust removes the trust setting and the certificate from the keychain.
func untrust(dir string) error {
	certPath := filepath.Join(dir, certs.CertFile)
	b, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return errors.New("certificate file is not valid PEM")
	}
	kc, err := loginKeychain()
	if err != nil {
		return err
	}
	// Ignore "not found" errors: the goal is just that it's gone.
	_ = run("security", "remove-trusted-cert", certPath)
	_ = run("security", "delete-certificate", "-Z", fmt.Sprintf("%X", sha1.Sum(block.Bytes)), kc)
	return nil
}

// isTrusted asks macOS (the same check Safari uses) whether a YouTube
// certificate signed by our CA would be accepted.
func isTrusted(dir string) (bool, error) {
	ca, err := certs.Load(dir)
	if err != nil {
		return false, err
	}
	leaf, err := ca.LeafFor("www.youtube.com")
	if err != nil {
		return false, err
	}
	f, err := os.CreateTemp("", "shoo-leaf-*.pem")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	f.Close()
	// The exit code is the answer; macOS prints Certificate Transparency
	// notes even on success, so the output can't be used.
	err = exec.Command("security", "verify-cert", "-c", f.Name(), "-p", "ssl", "-s", "www.youtube.com", "-q").Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return err == nil, err
}

// networkServices lists enabled network services (Wi-Fi, Ethernet, ...).
func networkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	for i, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		l = strings.TrimSpace(l)
		if i == 0 || l == "" || strings.HasPrefix(l, "*") { // header line; "*" = disabled
			continue
		}
		svcs = append(svcs, l)
	}
	return svcs, nil
}

func autoProxy(svc string) (url string, enabled bool) {
	out, _ := exec.Command("networksetup", "-getautoproxyurl", svc).Output()
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(l, "URL: "); ok {
			url = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "Enabled: "); ok {
			enabled = strings.TrimSpace(v) == "Yes"
		}
	}
	return url, enabled
}

// enable points every network service at our PAC file. It won't replace a
// different PAC file the user already has, unless force is set.
func enable(pacURL string, force bool) error {
	if os.Geteuid() != 0 {
		return errors.New("changing network settings needs admin rights: run `sudo shoo enable`")
	}
	svcs, err := networkServices()
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		if cur, on := autoProxy(svc); on && !isShooPAC(cur, pacURL) && !force {
			fmt.Printf("  %-24s skipped: already uses %s (use -force to replace)\n", svc, cur)
			continue
		}
		if err := run("networksetup", "-setautoproxyurl", svc, pacURL); err != nil {
			return fmt.Errorf("%s: %w", svc, err)
		}
		if err := run("networksetup", "-setautoproxystate", svc, "on"); err != nil {
			return fmt.Errorf("%s: %w", svc, err)
		}
		fmt.Printf("  %-24s on\n", svc)
	}
	return nil
}

// disable turns the PAC setting off, only where it's ours.
func disable(pacURL string) error {
	if os.Geteuid() != 0 {
		return errors.New("changing network settings needs admin rights: run `sudo shoo disable`")
	}
	svcs, err := networkServices()
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		if cur, on := autoProxy(svc); on && isShooPAC(cur, pacURL) {
			if err := run("networksetup", "-setautoproxystate", svc, "off"); err != nil {
				return fmt.Errorf("%s: %w", svc, err)
			}
			fmt.Printf("  %-24s off\n", svc)
		}
	}
	return nil
}

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
		fmt.Println("  NOT running (run `shoo run`)")
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
	} else if p, err := agentPlistPath(); err == nil && fileExists(p) {
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

	fmt.Println("Network services:")
	svcs, _ := networkServices()
	for _, svc := range svcs {
		cur, on := autoProxy(svc)
		var line string
		switch {
		case on && cur == pacURL:
			line = "on"
		case on && isShooPAC(cur, pacURL):
			line = "on, but an older PAC address (run `shoo setup`)"
		case on:
			line = "not shoo (another PAC file is on: " + cur + ")"
		default:
			line = "off"
		}
		if usesShooDNS(svc) {
			line += ", DNS shoo"
		} else if set.Sites != sitesOff {
			line += ", DNS not shoo"
		}
		fmt.Printf("  %-24s %s\n", svc, line)
	}
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
