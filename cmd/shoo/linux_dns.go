//go:build linux

package main

// The DNS server as a systemd system service, and NetworkManager's global
// DNS setting pointing every connection at it.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	dnsUnitPath = "/etc/systemd/system/" + dnsUnitName
	// sysDir holds the root-owned copy of the shoo binary the system
	// service runs, so it never runs a file the user account can change.
	sysDir     = "/usr/local/libexec/shoo"
	dnsLogPath = "/var/log/shoo-dns.log"
	nmConfPath = "/etc/NetworkManager/conf.d/90-shoo-dns.conf"
)

func dnsBinary() string { return filepath.Join(sysDir, "shoo") }

// dnsInstalled reports whether the DNS system service is installed.
func dnsInstalled() bool { return fileExists(dnsUnitPath) }

// networkManager reports whether NetworkManager runs this computer's
// network; shoo's DNS needs it to point every connection at shoo.
func networkManager() bool {
	out, err := exec.Command("nmcli", "-t", "-f", "RUNNING", "general").Output()
	return err == nil && strings.TrimSpace(string(out)) == "running"
}

// dnsEverywhere reports whether NetworkManager sends all lookups to shoo.
func dnsEverywhere() bool {
	b, err := os.ReadFile(nmConfPath)
	return err == nil && string(b) == nmDNSConf && networkManager()
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// portFree checks that nothing else answers on the DNS port.
func portFree() error {
	pc, err := net.ListenPacket("udp4", dnsAddr)
	if err != nil {
		holder, _ := exec.Command("ss", "-Hlunp", "sport = :53").Output()
		return fmt.Errorf("another program uses %s, so shoo's DNS server can't start: %s",
			dnsAddr, strings.TrimSpace(string(holder)))
	}
	pc.Close()
	return nil
}

// enableDNS (root) installs the DNS system service and points
// NetworkManager at it. It only switches DNS once the server answers.
func enableDNS(exe, dir string) error {
	if os.Geteuid() != 0 {
		return errors.New("needs admin rights: run `sudo shoo enable -dns -data DIR`")
	}
	uid, gid, err := dirOwner(dir)
	if err != nil {
		return err
	}
	if !networkManager() {
		return errors.New("DNS blocking needs NetworkManager, which isn't running")
	}
	if err := copyBinary(exe, dnsBinary()); err != nil {
		return err
	}
	// Fedora's SELinux only lets system services run files marked as programs.
	if exec.Command("selinuxenabled").Run() == nil {
		exec.Command("chcon", "-t", "bin_t", dnsBinary()).Run()
	}

	unit := []byte(dnsUnit(dnsBinary(), dir, uid, gid, dnsLogPath))
	if cur, err := os.ReadFile(dnsUnitPath); err != nil || !bytes.Equal(cur, unit) {
		if err := os.WriteFile(dnsUnitPath, unit, 0o644); err != nil {
			return err
		}
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	// (Re)start so a new binary or folder takes effect.
	exec.Command("systemctl", "stop", dnsUnitName).Run()
	if err := portFree(); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", dnsUnitName); err != nil {
		return fmt.Errorf("starting the DNS service: %w", err)
	}
	if !waitForDNS() {
		return fmt.Errorf("the DNS service didn't start, so DNS settings were left unchanged; see %s", dnsLogPath)
	}

	if cur, err := os.ReadFile(nmConfPath); err != nil || string(cur) != nmDNSConf {
		if err := os.MkdirAll(filepath.Dir(nmConfPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(nmConfPath, []byte(nmDNSConf), 0o644); err != nil {
			return err
		}
	}
	if err := run("nmcli", "general", "reload"); err != nil {
		return fmt.Errorf("telling NetworkManager to use shoo's DNS: %w", err)
	}
	flushDNSCache()
	fmt.Printf("  %-24s DNS shoo\n", "all connections")
	return nil
}

// flushDNSCache makes systemd-resolved forget addresses it looked up
// earlier, so ad domains it already knew are looked up again.
func flushDNSCache() {
	exec.Command("resolvectl", "flush-caches").Run()
}

// disableDNS (root) puts DNS back and removes the DNS service.
func disableDNS() error {
	if os.Geteuid() != 0 {
		return errors.New("needs admin rights: run `sudo shoo disable-dns`")
	}
	var failed []string
	// DNS goes back to normal first, so lookups never go to a stopped server.
	if fileExists(nmConfPath) {
		if err := os.Remove(nmConfPath); err != nil {
			failed = append(failed, nmConfPath)
		} else {
			exec.Command("nmcli", "general", "reload").Run()
			fmt.Printf("  %-24s DNS back to normal\n", "all connections")
		}
	}
	flushDNSCache()
	exec.Command("systemctl", "disable", "--now", dnsUnitName).Run()
	for _, p := range []string{dnsUnitPath, dnsBinary()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = append(failed, p)
		}
	}
	exec.Command("systemctl", "daemon-reload").Run()
	os.Remove(sysDir) // only if empty
	if len(failed) > 0 {
		return fmt.Errorf("could not remove %s", strings.Join(failed, ", "))
	}
	return nil
}
