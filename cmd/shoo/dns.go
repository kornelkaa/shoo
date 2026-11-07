package main

// DNS blocking for other websites. Refusing ad domains in the proxy isn't
// enough: the system then connects to them directly. So a small DNS server
// (internal/dnsblock) answers 0.0.0.0 for ad domains and passes every other
// lookup, YouTube included, to the network's normal DNS servers. It keeps
// running when the proxy is stopped, so DNS never depends on the proxy.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"shoo/internal/dnsblock"
	"shoo/internal/sites"
)

const (
	dnsAddr       = "127.0.0.1:53"
	dnsServerIP   = "127.0.0.1"
	dnsBeforeFile = "dns-before.json"
)

// runDNS is `shoo dns`, started by the system service. It blocks for the
// users whose shoo folders are in dirs: several people can share a computer,
// which has one DNS setting. Failing to listen on dnsAddr is fatal;
// dnsExtraAddrs are optional (IPv6 may be switched off).
func runDNS(dirs []string, out io.Writer) error {
	logger := log.New(out, "shoo-dns: ", log.LstdFlags)
	if len(dirs) == 0 {
		return errors.New("no shoo folders to read lists from")
	}
	lowerPrivileges, err := dnsPrivileges(dirs[0])
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", dnsAddr)
	if err != nil {
		return fmt.Errorf("DNS port: %w", err)
	}
	tl, err := net.Listen("tcp", dnsAddr)
	if err != nil {
		return fmt.Errorf("DNS port: %w", err)
	}
	pcs, tls := []net.PacketConn{pc}, []net.Listener{tl}
	for _, addr := range dnsExtraAddrs {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			logger.Printf("not listening on %s: %v", addr, err)
			continue
		}
		tl, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close()
			logger.Printf("not listening on %s: %v", addr, err)
			continue
		}
		pcs, tls = append(pcs, pc), append(tls, tl)
	}
	if err := lowerPrivileges(); err != nil {
		return err
	}

	lists := make([]atomic.Pointer[sites.List], len(dirs))
	for i, dir := range dirs {
		lists[i].Store(loadOrEmpty(dir, logger))
		go sites.WatchFiles(dir, 30*time.Second, func() {
			l := loadOrEmpty(dir, logger)
			lists[i].Store(l)
			logger.Printf("block list reloaded: %d domains", l.Len())
		})
	}
	blocked := func(name string) bool {
		cur := make([]*sites.List, len(lists))
		for i := range lists {
			cur[i] = lists[i].Load()
		}
		return dnsBlocks(cur, name)
	}

	// Read again on every refresh: on a first install, enableDNS saves the
	// previous settings only after this server has started.
	ups := &dnsblock.Upstreams{Preferred: func() []string {
		before, _ := readDNSBefore()
		return manualServers(before)
	}}
	srv := &dnsblock.Server{
		Blocked:  blocked,
		Upstream: ups.Servers,
		Log:      logger,
	}
	logger.Printf("shoo %s DNS on %s for %d user(s), other lookups go to %v", version, dnsAddr, len(dirs), ups.Servers())
	errc := make(chan error, len(pcs)+len(tls))
	for _, pc := range pcs {
		go func() { errc <- srv.ServeUDP(pc) }()
	}
	for _, tl := range tls {
		go func() { errc <- srv.ServeTCP(tl) }()
	}
	return <-errc
}

// dnsAnswers checks that shoo's DNS server is running and answering. It
// asks for dnsblock.ProbeName, which the server always blocks, so the answer
// doesn't depend on the lists (not downloaded yet, or a domain allowed).
func dnsAnswers() bool { return dnsAnswersAt(dnsAddr) }

func dnsAnswersAt(addr string) bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "ip4", dnsblock.ProbeName)
	return err == nil && len(ips) == 1 && ips[0].Equal(net.IPv4zero)
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
	b, err := os.ReadFile(filepath.Join(systemDir(), dnsBeforeFile))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// writeDNSBefore saves what readDNSBefore reads. It replaces the file in one
// step, so a crash can't leave half of it.
func writeDNSBefore(m map[string][]string) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	path := filepath.Join(systemDir(), dnsBeforeFile)
	if err := os.WriteFile(path+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
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
		fmt.Printf("  NOT answering (see %s)\n", dnsLogFile())
	default:
		fmt.Println("  not installed (run `shoo setup`)")
	}
}

// loadOrEmpty loads one user's lists. A folder that can't be read (its user
// deleted it, say) blocks nothing, instead of stopping DNS for everyone.
func loadOrEmpty(dir string, logger *log.Logger) *sites.List {
	l, err := sites.Load(dir)
	if err != nil {
		logger.Printf("reading the lists in %s: %v", dir, err)
		return sites.NewList(nil, nil)
	}
	return l
}

// dnsBlocks is the DNS server's rule for several users' lists: a domain is
// blocked if anyone's list blocks it and nobody allowed it. DNS can't tell
// who is asking, and allowing is how someone fixes a site that broke.
func dnsBlocks(lists []*sites.List, name string) bool {
	hit := false
	for _, l := range lists {
		if l.Exempt(name) {
			return false
		}
		hit = hit || l.Blocked(name)
	}
	return hit
}
