package main

// DNS blocking for other websites. Refusing ad domains in the proxy isn't
// enough: the system then connects to them directly. So a small DNS server
// (internal/dnsblock) answers 0.0.0.0 for ad domains and passes every other
// lookup, YouTube included, to the network's normal DNS servers.
//
// The DNS port (53) needs admin rights, so the server runs as a system
// service (macos_dns.go, linux_dns.go). It never keeps admin rights: on
// macOS it opens the port as root and then switches to the user who owns
// shoo's data folder; on Linux it runs as that user from the start, with
// only the right to open low ports. It keeps running when the proxy is
// stopped, so DNS never depends on the proxy.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	"shoo/internal/dnsblock"
	"shoo/internal/sites"
	"shoo/internal/stats"
)

const (
	dnsAddr       = "127.0.0.1:53"
	dnsServerIP   = "127.0.0.1"
	dnsBeforeFile = "dns-before.json"
)

// runDNS is `shoo dns`, started by the system service.
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

// waitForDNS waits up to 10 seconds for a just-started DNS service.
func waitForDNS() bool {
	for i := 0; i < 40; i++ {
		time.Sleep(250 * time.Millisecond)
		if dnsAnswers() {
			return true
		}
	}
	return false
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

func fileHash(p string) ([32]byte, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// copyBinary (root) copies the shoo binary into the root-owned folder,
// replacing the old copy atomically.
func copyBinary(exe, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	src, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, src, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
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

func dnsStatus() {
	fmt.Println("Ad-domain DNS:")
	switch {
	case dnsAnswers():
		fmt.Println("  running")
	case dnsInstalled():
		fmt.Printf("  NOT answering (see %s)\n", dnsLogPath)
	default:
		fmt.Println("  not installed (run `shoo setup`)")
	}
}
