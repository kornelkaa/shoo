// Package proxy is the local HTTP proxy. It decrypts HTTPS so it can:
//   - remove YouTube's ad data (internal/prune),
//   - answer requests to ad domains itself, so they never load,
//   - link stylesheets into pages that hide ad boxes (internal/cosmetic).
//
// Which sites are decrypted is up to Decrypt; the rest are tunneled through
// untouched. Without Decrypt only YouTube is decrypted.
package proxy

import (
	"bufio"
	"bytes"
	"context"
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

	"shoo/internal/certs"
	"shoo/internal/cosmetic"
	"shoo/internal/local"
	"shoo/internal/prune"
)

const maxBody = 32 << 20 // responses bigger than this are passed through

type Proxy struct {
	CA    *certs.Authority
	Rules prune.Rules
	// Upstream sends requests to the real servers.
	Upstream http.RoundTripper
	Log      *log.Logger
	// Addr is the proxy's own host:port, written into the PAC file.
	Addr string

	// Decrypt reports whether HTTPS to host may be decrypted (nil: YouTube only).
	Decrypt func(host string) bool
	// Blocked reports whether host is an ad domain; its requests fail (see
	// refuse) instead of reaching the site (nil: nothing blocked).
	Blocked func(host string) bool
	// Cosmetic hides ad elements in decrypted pages (nil: off).
	Cosmetic *cosmetic.Engine
	// Filter reports whether one request (to scheme://host) should be
	// blocked by URL, e.g. a single ad script on a site (nil: off).
	Filter func(r *http.Request, scheme, host string) bool
	// Pruned is called when ad fields were removed from a YouTube
	// response (nil: nothing).
	Pruned func()

	once  sync.Once
	conns *connListener
	// rejected holds hosts whose client refused our certificate (an app
	// that pins its certificates): they're tunneled from then on.
	rejected sync.Map
}

func (p *Proxy) blocked(host string) bool { return p.Blocked != nil && p.Blocked(host) }

// shouldDecrypt decides whether a CONNECT to host:443 is decrypted.
func (p *Proxy) shouldDecrypt(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// Never-decrypt sites the CA excludes, or a CA about to expire:
	// tunnel instead of showing a certificate error.
	if !p.CA.CanSign(host) {
		return false
	}
	if p.Cosmetic != nil && host == cosmetic.AssetHost {
		return true
	}
	if _, ok := p.rejected.Load(host); ok {
		return false
	}
	if p.Decrypt == nil {
		return certs.Allowed(host)
	}
	return p.Decrypt(host) || p.blocked(host)
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
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if mc, ok := c.(*mitmConn); ok {
				return context.WithValue(ctx, hostKey{}, mc.host)
			}
			return ctx
		},
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
	case r.Method == http.MethodGet && r.URL.Path == "/proxy.pac" && local.Request(r):
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, PAC(p.Addr))
	default:
		http.Error(w, "shoo proxy", http.StatusBadRequest)
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

	if port == "443" && p.shouldDecrypt(host) {
		p.intercept(conn, strings.ToLower(strings.TrimSuffix(host, ".")))
		return
	}
	if p.blocked(host) {
		conn.Close() // not decryptable (other port or IP): just end it
		return
	}
	go tunnel(conn, r.Host)
}

type hostKey struct{}

// mitmConn is a decrypted connection and the site it was opened for.
type mitmConn struct {
	*tls.Conn
	host string
}

// intercept terminates TLS with a certificate for the site and hands the
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
			if strings.Contains(err.Error(), "remote error") {
				// The client refused our certificate (an app that only
				// trusts its own). Stop decrypting this site.
				p.rejected.Store(connectHost, time.Now())
				p.Log.Printf("%s: the app refused shoo's certificate; no longer decrypting it", connectHost)
			}
			tlsConn.Close()
			return
		}
		tlsConn.SetDeadline(time.Time{})
		mc := &mitmConn{Conn: tlsConn, host: connectHost}
		if !p.conns.push(mc) {
			tlsConn.Close()
		}
	}()
}

func (p *Proxy) reverseProxy() http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Send the query exactly as the browser wrote it. ReverseProxy
			// drops parameters containing ";", which breaks URLs like Google
			// Fonts' family=Roboto:wght@300;400 (YouTube's text font).
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			yt := certs.Allowed(hostOnly(pr.In.Host))
			if (yt && p.Rules.Matches(pr.In.URL.Path)) || ((yt || p.Cosmetic != nil) && isPage(pr.In)) {
				// Let the Go transport request gzip and decompress it for us,
				// so the body we edit is plain JSON or HTML.
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		Transport:      p.Upstream,
		ModifyResponse: p.modifyResponse,
		FlushInterval:  -1,
		ErrorLog:       p.Log,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Requests always go to the site the connection was opened for,
		// whatever Host header the client sends.
		host, _ := r.Context().Value(hostKey{}).(string)
		if host == "" {
			http.Error(w, "unknown site", http.StatusBadRequest)
			return
		}
		r.Host = host
		if p.Cosmetic != nil && host == cosmetic.AssetHost {
			p.Cosmetic.ServeAsset(w, r)
			return
		}
		if p.blocked(host) || p.Filter != nil && p.Filter(r, "https", host) {
			refuse()
		}
		rp.ServeHTTP(w, r)
	})
}

// isPage reports whether the browser is loading a page (or a frame in one),
// not a script, image or API call.
func isPage(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document", "iframe", "frame":
		return true
	case "":
		return strings.Contains(r.Header.Get("Accept"), "text/html")
	}
	return false
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	host := hostOnly(resp.Request.Host)
	if certs.Allowed(host) {
		if err := p.pruneYouTube(resp); err != nil {
			return err
		}
	}
	if p.Cosmetic != nil && resp.StatusCode == http.StatusOK && isPage(resp.Request) {
		mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		ce := resp.Header.Get("Content-Encoding")
		if mt == "text/html" && (ce == "" || ce == "identity") {
			p.Cosmetic.Inject(host, resp)
		}
	}
	return nil
}

// pruneYouTube removes ad data from YouTube's player responses and pages.
func (p *Proxy) pruneYouTube(resp *http.Response) error {
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
		if p.Pruned != nil {
			p.Pruned()
		}
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
// redirects to https). Blocked requests fail (see refuse).
func (p *Proxy) plainHTTP() http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			u := *pr.In.URL
			pr.Out.URL = &u
			pr.Out.Host = pr.In.URL.Host
		},
		Transport: p.Upstream,
		ErrorLog:  p.Log,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.blocked(r.URL.Hostname()) || p.Filter != nil && p.Filter(r, "http", r.URL.Host) {
			refuse()
		}
		rp.ServeHTTP(w, r)
	})
}

// refuse ends a blocked request by closing the connection without an
// answer, so the page sees a network error, as with a browser ad blocker.
// (An empty 403 also stops the ad, but scripts that check whether a request
// failed, like ad-block testers, see it as loaded.) It happens inside the
// decrypted connection, which the browser already opened through shoo, so
// macOS doesn't retry the request directly. The HTTP server recovers this
// panic and closes the connection quietly.
func refuse() { panic(http.ErrAbortHandler) }

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
