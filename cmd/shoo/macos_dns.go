//go:build darwin

package main

// The DNS server as a macOS system service (LaunchDaemon), and the DNS
// setting of each network service.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	dnsLabel     = "com.kornelkaa.shoo.dns"
	dnsPlistPath = "/Library/LaunchDaemons/" + dnsLabel + ".plist"
	// sysDir holds root-owned files: a copy of the shoo binary for the
	// system service (so it never runs a file the user account can change)
	// and the DNS settings from before shoo, to put back later.
	sysDir     = "/Library/Application Support/shoo"
	dnsLogPath = "/Library/Logs/shoo-dns.log"
)

func dnsBinary() string { return filepath.Join(sysDir, "shoo") }

// dnsInstalled reports whether the DNS system service is installed.
func dnsInstalled() bool { return fileExists(dnsPlistPath) }

func dnsPlist(dir string) string {
	e := html.EscapeString
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + dnsLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + e(dnsBinary()) + `</string>
		<string>dns</string>
		<string>-data</string>
		<string>` + e(dir) + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>StandardOutPath</key>
	<string>` + e(dnsLogPath) + `</string>
	<key>StandardErrorPath</key>
	<string>` + e(dnsLogPath) + `</string>
</dict>
</plist>
`
}

func getDNSServers(svc string) []string {
	out, _ := exec.Command("networksetup", "-getdnsservers", svc).Output()
	var ips []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if net.ParseIP(strings.TrimSpace(l)) != nil {
			ips = append(ips, strings.TrimSpace(l))
		}
	}
	return ips // empty: the network's automatic (DHCP) DNS
}

func usesShooDNS(svc string) bool {
	return slices.Equal(getDNSServers(svc), []string{dnsServerIP})
}

// dnsEverywhere reports whether every network service uses shoo's DNS.
func dnsEverywhere() bool {
	svcs, err := networkServices()
	if err != nil || len(svcs) == 0 {
		return false
	}
	for _, svc := range svcs {
		if !usesShooDNS(svc) {
			return false
		}
	}
	return true
}

// enableDNS (root) installs the DNS system service and points every network
// service's DNS at it. It only switches DNS once the server answers.
func enableDNS(exe, dir string) error {
	if os.Geteuid() != 0 {
		return errors.New("needs admin rights: run `sudo shoo enable -dns -data DIR`")
	}
	if _, _, err := dirOwner(dir); err != nil {
		return err
	}
	if err := copyBinary(exe, dnsBinary()); err != nil {
		return err
	}

	plist := []byte(dnsPlist(dir))
	if cur, err := os.ReadFile(dnsPlistPath); err != nil || !bytes.Equal(cur, plist) {
		if err := os.WriteFile(dnsPlistPath, plist, 0o644); err != nil {
			return err
		}
	}
	// (Re)start so a new binary or folder takes effect.
	exec.Command("launchctl", "bootout", "system/"+dnsLabel).Run()
	var out []byte
	var err error
	for i := 0; i < 10; i++ { // bootout finishes in the background
		out, err = exec.Command("launchctl", "bootstrap", "system", dnsPlistPath).CombinedOutput()
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("starting the DNS service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if !waitForDNS() {
		return fmt.Errorf("the DNS service didn't start, so DNS settings were left unchanged; see %s", dnsLogPath)
	}

	svcs, err := networkServices()
	if err != nil {
		return err
	}
	before, _ := readDNSBefore()
	for _, svc := range svcs {
		if usesShooDNS(svc) {
			fmt.Printf("  %-24s DNS already shoo\n", svc)
			continue
		}
		before[svc] = getDNSServers(svc)
		if err := run("networksetup", "-setdnsservers", svc, dnsServerIP); err != nil {
			fmt.Printf("  %-24s DNS not changed: %v\n", svc, err)
			delete(before, svc)
			continue
		}
		fmt.Printf("  %-24s DNS shoo\n", svc)
	}
	flushDNSCache()
	b, _ := json.MarshalIndent(before, "", "  ")
	return os.WriteFile(filepath.Join(sysDir, dnsBeforeFile), b, 0o644)
}

// flushDNSCache makes macOS forget addresses it looked up earlier, so ad
// domains it already knew are looked up again (root only).
func flushDNSCache() {
	exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

// disableDNS (root) puts the DNS settings back and removes the DNS service.
func disableDNS() error {
	if os.Geteuid() != 0 {
		return errors.New("needs admin rights: run `sudo shoo disable`")
	}
	before, _ := readDNSBefore()
	svcs, _ := networkServices()
	for _, svc := range svcs {
		if !usesShooDNS(svc) {
			continue
		}
		args := append([]string{"-setdnsservers", svc}, before[svc]...)
		if len(before[svc]) == 0 {
			args = append(args, "Empty") // back to the network's automatic DNS
		}
		if err := run("networksetup", args...); err != nil {
			fmt.Printf("  %-24s DNS: %v\n", svc, err)
			continue
		}
		fmt.Printf("  %-24s DNS back to normal\n", svc)
	}
	flushDNSCache()
	exec.Command("launchctl", "bootout", "system/"+dnsLabel).Run()
	var failed []string
	for _, p := range []string{dnsPlistPath, dnsBinary(), filepath.Join(sysDir, dnsBeforeFile)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = append(failed, p)
		}
	}
	os.Remove(sysDir) // only if empty
	if len(failed) > 0 {
		return fmt.Errorf("could not remove %s", strings.Join(failed, ", "))
	}
	return nil
}
