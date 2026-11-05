// Package proxy is the local HTTP proxy. YouTube HTTPS connections are
// decrypted so ad fields can be removed; every other connection is tunneled
// through untouched.
package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"ytblock/internal/certs"
	"ytblock/internal/prune"
)

const maxBody = 32 << 20 // responses bigger than this are passed through

type Proxy struct {
	CA    *certs.Authority
	Rules prune.Rules
	// Upstream sends requests to the real YouTube servers.
	Upstream http.RoundTripper
	Log      *log.Logger
	// Addr is the proxy's own host:port, written into the PAC file.
	Addr string

	once  sync.Once
	conns *connListener
}

// New returns a proxy with a sensible upstream transport.
func New(ca *certs.Authority, rules prune.Rules, logger *log.Logger) *Proxy {
	return &Proxy{
		CA:    ca,
		Rules: rules,
		Upstream: &http.Transport{
			Proxy:               nil, // never loop back through a system proxy
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
		Log: logger,
	}
}

func (p *Proxy) start() {
	p.conns = newConnListener()
	srv := &http.Server{
		Handler:           p.reverseProxy(),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          p.Log,
	}
	go srv.Serve(p.conns)
}

// ServeHTTP handles requests made to the proxy itself.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.once.Do(p.start)
	switch {
	case r.Method == http.MethodConnect:
		p.handleConnect(w, r)
	case r.URL.IsAbs() && r.URL.Scheme == "http":
		p.plainHTTP().ServeHTTP(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/proxy.pac":
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, PAC(p.Addr))
	default:
		http.Error(w, "ytblock proxy", http.StatusBadRequest)
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		return
	}
	conn := &bufConn{Conn: clientConn, r: rw.Reader}

	if port == "443" && certs.Allowed(host) {
		p.intercept(conn, host)
		return
	}
	go tunnel(conn, r.Host)
}

// intercept terminates TLS with a YouTube-only certificate and hands the
// decrypted connection to the internal HTTP server.
func (p *Proxy) intercept(conn net.Conn, connectHost string) {
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = connectHost
			}
			return p.CA.LeafFor(name)
		},
	})
	go func() {
		tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			p.Log.Printf("TLS handshake with client for %s failed: %v", connectHost, err)
			tlsConn.Close()
			return
		}
		tlsConn.SetDeadline(time.Time{})
		if !p.conns.push(tlsConn) {
			tlsConn.Close()
		}
	}()
}

func (p *Proxy) reverseProxy() http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			if p.Rules.Matches(pr.In.URL.Path) || wantsHTML(pr.In) {
				// Let the Go transport request gzip and decompress it for us,
				// so the body we edit is plain JSON.
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		Transport:      p.Upstream,
		ModifyResponse: p.modifyResponse,
		FlushInterval:  -1,
		ErrorLog:       p.Log,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The Host header must stay within YouTube, whatever the client sends.
		if !certs.Allowed(hostOnly(r.Host)) {
			http.Error(w, "host not allowed", http.StatusForbidden)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// wantsHTML reports whether the browser is loading a page (watch page, home, ...).
func wantsHTML(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	path := resp.Request.URL.Path
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	isJSON := mt == "application/json" && p.Rules.Matches(path)
	isHTML := mt == "text/html"
	if !isJSON && !isHTML {
		return nil
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		p.Log.Printf("%s: unexpected Content-Encoding %q, passing through", path, ce)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	resp.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		p.Log.Printf("%s: body over %d bytes, passing through", path, maxBody)
		setBody(resp, body)
		return nil
	}

	var out []byte
	var n int
	if isHTML {
		out, n = p.Rules.HTML(body)
	} else if out, n, err = p.Rules.JSON(body); err != nil {
		p.Log.Printf("%s: could not parse JSON: %v", path, err)
	}
	if n > 0 {
		p.Log.Printf("%s: removed %d ad fields", path, n)
	}
	setBody(resp, out)
	return nil
}

// PAC returns a proxy auto-config script that sends only YouTube through the
// proxy at addr. If the proxy isn't running, browsers fall back to DIRECT,
// so YouTube keeps working (with ads) instead of breaking.
func PAC(addr string) string {
	var conds []string
	for _, d := range certs.AllowedDomains {
		conds = append(conds, fmt.Sprintf("host == %q || dnsDomainIs(host, %q)", d, "."+d))
	}
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (%s) {
    return "PROXY %s; DIRECT";
  }
  return "DIRECT";
}
`, strings.Join(conds, " ||\n      "), addr)
}

func setBody(resp *http.Response, b []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.Header.Del("Content-Encoding")
}

// plainHTTP forwards http:// requests (e.g. http://youtube.com, which just
// redirects to https).
func (p *Proxy) plainHTTP() http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			u := *pr.In.URL
			pr.Out.URL = &u
			pr.Out.Host = pr.In.URL.Host
		},
		Transport: p.Upstream,
		ErrorLog:  p.Log,
	}
}

func tunnel(client net.Conn, target string) {
	defer client.Close()
	server, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer server.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(server, client); done <- struct{}{} }()
	go func() { io.Copy(client, server); done <- struct{}{} }()
	<-done
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// bufConn reads from the hijacked bufio.Reader first, so no bytes the client
// sent right after CONNECT are lost.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// connListener feeds decrypted connections to an http.Server.
type connListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnListener() *connListener {
	return &connListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.closed:
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "mitm" }
func (dummyAddr) String() string  { return "mitm" }
