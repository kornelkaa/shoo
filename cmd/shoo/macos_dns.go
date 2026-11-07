//go:build !windows

package main

// The macOS side of DNS blocking. The port needs admin rights, so the server
// runs as a system service (LaunchDaemon). It opens the port as root and then
// immediately switches to the user who owns shoo's data folder.

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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

// dnsExtraAddrs are further addresses to listen on, none here.
var dnsExtraAddrs []string

func systemDir() string  { return sysDir }
func dnsLogFile() string { return dnsLogPath }
func dnsBinary() string  { return filepath.Join(sysDir, "shoo") }

// dnsInstalled reports whether the DNS system service is installed.
func dnsInstalled() bool { return fileExists(dnsPlistPath) }

// dnsMain is `shoo dns`.
func dnsMain(dir string) error { return runDNS([]string{dir}, os.Stderr) }

// dnsServes reports whether the DNS service blocks for the user whose shoo
// folder is dir. macOS has one DNS service for one user's folder.
func dnsServes(string) bool { return dnsInstalled() }

// dnsPrivileges runs before the port opens; the function it returns runs
// after, and gives up root.
func dnsPrivileges(dir string) (func() error, error) {
	uid, gid, err := dirOwner(dir)
	if err != nil {
		return nil, err
	}
	return func() error {
		if os.Geteuid() == 0 {
			return dropPrivileges(uid, gid)
		}
		return nil
	}, nil
}

// dirOwner is the user who owns dir; the DNS server runs as that user.
func dirOwner(dir string) (uid, gid int, err error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("can't read the owner of " + dir)
	}
	if st.Uid == 0 {
		return 0, 0, fmt.Errorf("%s belongs to root; it should be in your home folder", dir)
	}
	return int(st.Uid), int(st.Gid), nil
}

func dropPrivileges(uid, gid int) error {
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("dropping admin rights: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("dropping admin rights: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("dropping admin rights: %w", err)
	}
	if syscall.Setuid(0) == nil {
		return errors.New("dropping admin rights failed")
	}
	return nil
}

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

// dnsInstalledFrom reports whether the system service is installed and runs
// the same shoo binary as exe.
func dnsInstalledFrom(exe string) bool {
	if !dnsInstalled() {
		return false
	}
	a, err1 := fileHash(exe)
	b, err2 := fileHash(dnsBinary())
	return err1 == nil && err2 == nil && a == b
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
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		return err
	}
	// Copy the binary to the root-owned folder, replacing it atomically.
	src, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	tmp := dnsBinary() + ".new"
	if err := os.WriteFile(tmp, src, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dnsBinary()); err != nil {
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
	ok := false
	for i := 0; i < 40 && !ok; i++ {
		time.Sleep(250 * time.Millisecond)
		ok = dnsAnswers()
	}
	if !ok {
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
		// Saved before the change, so a crash in between can't lose DNS
		// servers set by hand.
		before[svc] = getDNSServers(svc)
		if err := writeDNSBefore(before); err != nil {
			return fmt.Errorf("saving the DNS settings: %w", err)
		}
		if err := run("networksetup", "-setdnsservers", svc, dnsServerIP); err != nil {
			fmt.Printf("  %-24s DNS not changed: %v\n", svc, err)
			delete(before, svc)
			continue
		}
		fmt.Printf("  %-24s DNS shoo\n", svc)
	}
	flushDNSCache()
	return writeDNSBefore(before)
}

// flushDNSCache makes macOS forget addresses it looked up earlier, so ad
// domains it already knew are looked up again (root only).
func flushDNSCache() {
	exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

// disableDNS (root) puts the DNS settings back and removes the DNS service.
func disableDNS(string) error {
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
	beforeFile := filepath.Join(systemDir(), dnsBeforeFile)
	for _, p := range []string{dnsPlistPath, dnsBinary(), beforeFile, beforeFile + ".tmp"} {
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
