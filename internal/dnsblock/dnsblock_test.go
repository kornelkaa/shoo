package dnsblock

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"shoo/internal/sites"
)

// fakeUpstream answers every A query with 1.2.3.4 and records the names.
func fakeUpstream(t *testing.T) (addr string, got chan string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	got = make(chan string, 100)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			name, qtype, qend, ok := parseQuestion(q)
			if !ok {
				continue
			}
			got <- name
			resp := responseHeader(q, qend, 0, 0)
			if qtype == typeA {
				resp = blockedAnswer(q, qtype, qend)
				copy(resp[len(resp)-4:], []byte{1, 2, 3, 4})
			}
			pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String(), got
}

func startServer(t *testing.T, upstream string) string {
	t.Helper()
	list := sites.NewList([]string{"doubleclick.net", "ads.example.com", "youtube.com"}, []string{"ok.ads.example.com"})
	s := &Server{
		Blocked:  list.Blocked,
		Upstream: func() []string { return []string{upstream} },
		Log:      log.New(io.Discard, "", 0),
		Timeout:  time.Second,
	}
	// UDP and TCP on the same port. Windows hands out UDP ports from blocks it
	// reserves for TCP (Hyper-V, WSL), so the TCP port is picked first.
	var pc net.PacketConn
	var l net.Listener
	for try := 0; ; try++ {
		var err error
		if l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if pc, err = net.ListenPacket("udp", l.Addr().String()); err == nil {
			break
		}
		l.Close()
		if try == 20 {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { pc.Close(); l.Close() })
	go s.ServeUDP(pc)
	go s.ServeTCP(l)
	return pc.LocalAddr().String()
}

func resolver(server, network string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
}

func TestBlockAndForward(t *testing.T) {
	up, got := fakeUpstream(t)
	srv := startServer(t, up)
	ctx := context.Background()

	for _, network := range []string{"udp", "tcp"} {
		r := resolver(srv, network)
		ips, err := r.LookupIP(ctx, "ip4", "securepubads.g.doubleclick.net")
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4zero) {
			t.Errorf("%s: blocked A = %v, %v; want 0.0.0.0", network, ips, err)
		}
		ips, err = r.LookupIP(ctx, "ip6", "ads.example.com")
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv6unspecified) {
			t.Errorf("%s: blocked AAAA = %v, %v; want ::", network, ips, err)
		}
	}

	// Not blocked, allowed, and YouTube (never blocked, even if listed):
	// forwarded unchanged.
	r := resolver(srv, "udp")
	for _, name := range []string{"www.dictionary.com", "ok.ads.example.com", "www.youtube.com"} {
		ips, err := r.LookupIP(ctx, "ip4", name)
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(1, 2, 3, 4)) {
			t.Errorf("%s = %v, %v; want forwarded answer 1.2.3.4", name, ips, err)
		}
		select {
		case n := <-got:
			if n != name {
				t.Errorf("upstream got %q, want %q", n, name)
			}
		case <-time.After(time.Second):
			t.Errorf("%s was not forwarded", name)
		}
	}
	select {
	case n := <-got:
		t.Errorf("a blocked name reached the upstream: %q", n)
	default:
	}
}

func TestBlockedOtherType(t *testing.T) {
	// An HTTPS-record query (type 65) for a blocked name: empty answer.
	q := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split("ads.example.com", ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 65, 0, 1)
	s := &Server{Blocked: func(string) bool { return true }}
	resp := s.handle(q, "udp")
	if len(resp) != len(q) || resp[0] != 0xab || resp[1] != 0xcd || resp[2]&0x80 == 0 || resp[3]&0x0f != 0 || resp[7] != 0 {
		t.Errorf("unexpected response % x", resp)
	}
}

func TestUpstreamUnavailable(t *testing.T) {
	// Nothing listens on the upstream: the client gets SERVFAIL, not silence.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dead := pc.LocalAddr().String()
	pc.Close()
	srv := startServer(t, dead)
	_, err := resolver(srv, "udp").LookupIP(context.Background(), "ip4", "www.dictionary.com")
	if err == nil {
		t.Error("expected an error")
	}
}

func TestProbeAlwaysBlocked(t *testing.T) {
	// The probe is answered even with an empty list, and never forwarded.
	up, got := fakeUpstream(t)
	s := &Server{
		Blocked:  func(string) bool { return false },
		Upstream: func() []string { return []string{up} },
		Log:      log.New(io.Discard, "", 0),
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go s.ServeUDP(pc)
	ips, err := resolver(pc.LocalAddr().String(), "udp").LookupIP(context.Background(), "ip4", ProbeName)
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4zero) {
		t.Errorf("probe = %v, %v; want 0.0.0.0", ips, err)
	}
	select {
	case n := <-got:
		t.Errorf("the probe reached the upstream: %q", n)
	default:
	}
}

func TestDeadUpstreamTriedLast(t *testing.T) {
	// The first server takes the query but never answers. After one slow
	// lookup it moves to the back, so the next lookups are fast.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() })
	up, _ := fakeUpstream(t)
	s := &Server{
		Upstream: func() []string { return []string{silent.LocalAddr().String(), up} },
		Log:      log.New(io.Discard, "", 0),
		Timeout:  300 * time.Millisecond,
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go s.ServeUDP(pc)
	r := resolver(pc.LocalAddr().String(), "udp")
	for i, name := range []string{"one.example.com", "two.example.com"} {
		start := time.Now()
		ips, err := r.LookupIP(context.Background(), "ip4", name)
		took := time.Since(start)
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(1, 2, 3, 4)) {
			t.Fatalf("%s = %v, %v", name, ips, err)
		}
		if i == 1 && took >= 300*time.Millisecond {
			t.Errorf("second lookup took %v: the dead server was tried first again", took)
		}
	}
}

func TestUpstreams(t *testing.T) {
	u := &Upstreams{
		Preferred: func() []string { return []string{"9.9.9.9", "127.0.0.1"} },
		Lookup:    func() []string { return []string{"192.168.1.1", "9.9.9.9", "::1", "fe80::1", "2001:db8::53"} },
	}
	got := strings.Join(u.Servers(), ",")
	if got != "9.9.9.9:53,192.168.1.1:53,[2001:db8::53]:53" {
		t.Errorf("servers = %s", got)
	}
	u = &Upstreams{Lookup: func() []string { return []string{"127.0.0.1"} }}
	if got := strings.Join(u.Servers(), ","); got != "1.1.1.1:53,8.8.8.8:53" {
		t.Errorf("fallback = %s", got)
	}
}
