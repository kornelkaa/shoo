// Package dnsblock is a small local DNS server that blocks ad domains.
//
// Refusing ad domains in the proxy isn't enough on macOS: when a proxy
// refuses a connection (or the connection fails in any way), macOS quietly
// connects directly instead and the ad loads anyway. A DNS answer of 0.0.0.0
// leaves nothing to fall back to.
//
// Blocked names get 0.0.0.0 (A), :: (AAAA) or an empty answer (any other
// type, e.g. the HTTPS records Safari asks for). Every other query, including
// all of YouTube, is passed unchanged to the network's normal DNS servers.
package dnsblock

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// DNS record types and classes used here.
const (
	typeA    = 1
	typeAAAA = 28
	classIN  = 1
)

// Server answers DNS queries over UDP and TCP.
type Server struct {
	// Blocked reports whether a name (lowercase, no trailing dot) is blocked.
	Blocked func(name string) bool
	// Upstream returns the DNS servers ("ip:53") to forward other queries to.
	Upstream func() []string
	Log      *log.Logger
	// Timeout per upstream server (default 3s).
	Timeout time.Duration

	// OnBlocked is called with each blocked name (nil: nothing).
	OnBlocked func(name string)

	blocked atomic.Int64
}

// BlockedCount is the number of queries answered with a block so far.
func (s *Server) BlockedCount() int64 { return s.blocked.Load() }

func (s *Server) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 3 * time.Second
}

// ServeUDP answers queries on pc until it is closed.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := s.handle(q, "udp"); resp != nil {
				pc.WriteTo(resp, from)
			}
		}()
	}
}

// ServeTCP answers queries on l until it is closed.
func (s *Server) ServeTCP(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serveTCPConn(c)
	}
}

func (s *Server) serveTCPConn(c net.Conn) {
	defer c.Close()
	for {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		q, err := readTCPMsg(c)
		if err != nil {
			return
		}
		resp := s.handle(q, "tcp")
		if resp == nil {
			return
		}
		if writeTCPMsg(c, resp) != nil {
			return
		}
	}
}

// handle answers one query. It returns nil if there is nothing to send.
func (s *Server) handle(q []byte, network string) []byte {
	name, qtype, qend, ok := parseQuestion(q)
	if !ok {
		return nil
	}
	if name != "" && s.Blocked != nil && s.Blocked(name) {
		s.blocked.Add(1) // not logged by name: the log would list the sites you visit
		if s.OnBlocked != nil {
			s.OnBlocked(name)
		}
		return blockedAnswer(q, qtype, qend)
	}
	resp, err := s.forward(q, network)
	if err != nil {
		return serverFailure(q, qend)
	}
	return resp
}

// forward sends the query unchanged to the upstream servers, in order,
// until one answers.
func (s *Server) forward(q []byte, network string) ([]byte, error) {
	var ups []string
	if s.Upstream != nil {
		ups = s.Upstream()
	}
	err := errors.New("no upstream DNS servers")
	for _, up := range ups {
		var resp []byte
		resp, err = exchange(network, up, q, s.timeout())
		if err == nil {
			return resp, nil
		}
	}
	return nil, err
}

func exchange(network, server string, q []byte, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout(network, server, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if network == "tcp" {
		if err := writeTCPMsg(c, q); err != nil {
			return nil, err
		}
		return readTCPMsg(c)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore stray packets that don't match the query ID.
		if n >= 12 && buf[0] == q[0] && buf[1] == q[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func readTCPMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, msg)
	return msg, err
}

func writeTCPMsg(w io.Writer, msg []byte) error {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	_, err := w.Write(out)
	return err
}

// parseQuestion reads the single question of a standard query. name is
// lowercase without the trailing dot; qend is where the question ends.
func parseQuestion(q []byte) (name string, qtype uint16, qend int, ok bool) {
	if len(q) < 12 || q[2]&0x80 != 0 { // too short, or a response
		return "", 0, 0, false
	}
	if opcode := (q[2] >> 3) & 0x0f; opcode != 0 || binary.BigEndian.Uint16(q[4:]) != 1 {
		// Not a plain one-question query: just pass it on.
		return "", 0, len(q), true
	}
	var labels []string
	i := 12
	for {
		if i >= len(q) {
			return "", 0, 0, false
		}
		l := int(q[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(q) { // compression pointers don't occur in questions
			return "", 0, 0, false
		}
		labels = append(labels, string(q[i:i+l]))
		i += l
	}
	if i+4 > len(q) {
		return "", 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(q[i:])
	return strings.ToLower(strings.Join(labels, ".")), qtype, i + 4, true
}

// responseHeader makes a response header for query q with the given
// answer count and response code; the question is copied unchanged.
func responseHeader(q []byte, qend int, ancount uint16, rcode byte) []byte {
	resp := make([]byte, qend, qend+28)
	copy(resp, q[:qend])
	resp[2] = 0x80 | (q[2] & 0x79) // QR, keep opcode and RD
	resp[3] = 0x80 | rcode         // RA
	binary.BigEndian.PutUint16(resp[4:], 1)
	binary.BigEndian.PutUint16(resp[6:], ancount)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)
	return resp
}

// blockedAnswer: 0.0.0.0 for A, :: for AAAA, no records for other types.
func blockedAnswer(q []byte, qtype uint16, qend int) []byte {
	var rdata []byte
	switch qtype {
	case typeA:
		rdata = make([]byte, 4)
	case typeAAAA:
		rdata = make([]byte, 16)
	}
	if rdata == nil {
		return responseHeader(q, qend, 0, 0)
	}
	resp := responseHeader(q, qend, 1, 0)
	var rr [12]byte
	binary.BigEndian.PutUint16(rr[0:], 0xc00c) // pointer to the question's name
	binary.BigEndian.PutUint16(rr[2:], qtype)
	binary.BigEndian.PutUint16(rr[4:], classIN)
	binary.BigEndian.PutUint32(rr[6:], 300) // TTL in seconds
	binary.BigEndian.PutUint16(rr[10:], uint16(len(rdata)))
	return append(append(resp, rr[:]...), rdata...)
}

func serverFailure(q []byte, qend int) []byte {
	if qend < 12 || qend > len(q) {
		qend = 12
	}
	resp := responseHeader(q, qend, 0, 2)
	if qend == 12 {
		binary.BigEndian.PutUint16(resp[4:], 0)
	}
	return resp
}
