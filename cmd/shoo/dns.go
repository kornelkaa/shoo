package main

// DNS blocking for other websites. Refusing ad domains in the proxy isn't
// enough: macOS then connects to them directly. So a small DNS server
// (internal/dnsblock) answers 0.0.0.0 for ad domains and passes every other
// lookup, YouTube included, to the network's normal DNS servers.
//
// The DNS port (53) needs admin rights, so the server runs as a system
// service (LaunchDaemon). It opens the port as root and then immediately
// switches to the user who owns shoo's data folder. It keeps running when
// the proxy is stopped, so DNS never depends on the proxy.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"shoo/internal/dnsblock"
	"shoo/internal/sites"
	"shoo/internal/stats"
)

const (
	dnsLabel     = "com.kornelkaa.shoo.dns"
	dnsAddr      = "127.0.0.1:53"
	dnsServerIP  = "127.0.0.1"
	dnsPlistPath = "/Library/LaunchDaemons/" + dnsLabel + ".plist"
	// sysDir holds root-owned files: a copy of the shoo binary for the
	// system service (so it never runs a file the user account can change)
	// and the DNS settings from before shoo, to put back later.
	sysDir        = "/Library/Application Support/shoo"
	dnsLogPath    = "/Library/Logs/shoo-dns.log"
	dnsBeforeFile = "dns-before.json"
)

func dnsBinary() string { return filepath.Join(sysDir, "shoo") }

// runDNS is `shoo dns`, started by the system service as root.
func runDNS(dir string) error {
	logger := log.New(os.Stderr, "shoo-dns: ", log.LstdFlags)
	uid, gid, err := dirOwner(dir)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp4", dnsAddr)
	if err != nil {
		return fmt.Errorf("DNS port: %w", err)
	}
	tl, err := net.Listen("tcp4", dnsAddr)
	if err != nil {
		return fmt.Errorf("DNS port: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := dropPrivileges(uid, gid); err != nil {
			return err
		}
	}

	list, err := sites.Load(dir)
	if err != nil {
		return err
	}
	var cur atomic.Pointer[sites.List]
	cur.Store(list)
	go sites.WatchFiles(dir, 30*time.Second, func() {
		if l, err := sites.Load(dir); err != nil {
			logger.Printf("reloading block list: %v", err)
		} else {
			cur.Store(l)
			logger.Printf("block list reloaded: %d domains", l.Len())
		}
	})

	before, _ := readDNSBefore()
	ups := &dnsblock.Upstreams{Preferred: manualServers(before)}
	rec := stats.Open(filepath.Join(dir, stats.DNSFile), logger)
	go rec.Run(30 * time.Second)
	saveOnExit(rec)
	srv := &dnsblock.Server{
		Blocked:   func(name string) bool { return cur.Load().Blocked(name) },
		Upstream:  ups.Servers,
		Log:       logger,
		OnBlocked: func(name string) { rec.Add(stats.DNS, name) },
	}
	logger.Printf("shoo %s DNS on %s: blocking %d ad domains, other lookups go to %v", version, dnsAddr, list.Len(), ups.Servers())
	errc := make(chan error, 2)
	go func() { errc <- srv.ServeUDP(pc) }()
	go func() { errc <- srv.ServeTCP(tl) }()
	return <-errc
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

// dnsAnswers checks that shoo's DNS server is running and blocking.
func dnsAnswers() bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dnsAddr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "ip4", "doubleclick.net")
	return err == nil && len(ips) == 1 && ips[0].Equal(net.IPv4zero)
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
	if !fileExists(dnsPlistPath) {
		return false
	}
	a, err1 := fileHash(exe)
	b, err2 := fileHash(dnsBinary())
	return err1 == nil && err2 == nil && a == b
}

func fileHash(p string) ([32]byte, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// readDNSBefore returns each network service's DNS servers from before
// shoo (empty list: automatic).
func readDNSBefore() (map[string][]string, error) {
	m := map[string][]string{}
	b, err := os.ReadFile(filepath.Join(sysDir, dnsBeforeFile))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

func manualServers(before map[string][]string) []string {
	var out []string
	for _, svc := range slices.Sorted(maps.Keys(before)) {
		out = append(out, before[svc]...)
	}
	return out
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

func dnsStatus() {
	fmt.Println("Ad-domain DNS:")
	switch {
	case dnsAnswers():
		fmt.Println("  running")
	case fileExists(dnsPlistPath):
		fmt.Printf("  NOT answering (see %s)\n", dnsLogPath)
	default:
		fmt.Println("  not installed (run `shoo setup`)")
	}
}
