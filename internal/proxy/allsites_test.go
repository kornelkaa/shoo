package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"shoo/internal/certs"
	"shoo/internal/cosmetic"
	"shoo/internal/prune"
)

// setupAllSites runs the proxy the way shoo does now: every site decrypted,
// ad domains blocked, ad boxes hidden. All upstream traffic goes to one fake
// server, which counts the requests it gets.
func setupAllSites(t *testing.T) (*http.Client, *atomic.Int64) {
	t.Helper()
	hits := new(atomic.Int64)
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/page":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			io.WriteString(w, "<!doctype html><html><head><title>t</title></head><body>hi</body></html>")
		case "/youtubei/v1/player":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, playerJSON)
		default:
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, "var x=1;")
		}
	}))
	t.Cleanup(fake.Close)

	dir := t.TempDir()
	if err := certs.Generate(dir, false, nil); err != nil {
		t.Fatal(err)
	}
	ca, err := certs.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := cosmetic.Parse(strings.NewReader("##.ad-box\nexample.com##.example-ad\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := New(ca, prune.Default, log.New(io.Discard, "", 0))
	p.Decrypt = func(host string) bool { return host != "bank.example" }
	p.Blocked = func(host string) bool { return strings.HasSuffix(host, "ads.example") }
	p.Cosmetic = cosmetic.NewEngine(rules)
	p.Upstream = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", fake.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test only: fake server cert
	}
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	proxyURL, _ := url.Parse(ps.URL)
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}, hits
}

func fetch(t *testing.T, c *http.Client, u string, page bool) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	if page {
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Accept", "text/html,*/*")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestPagesGetHidingStylesheets(t *testing.T) {
	c, _ := setupAllSites(t)
	resp, body := fetch(t, c, "https://www.example.com/page", true)
	if !strings.Contains(body, `<head><link rel="stylesheet" href="https://assets.shoo.internal/g.css`) ||
		!strings.Contains(body, "s.css?h=www.example.com") || !strings.HasSuffix(body, "</html>") {
		t.Errorf("page = %q", body)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "style-src 'self' https://assets.shoo.internal") {
		t.Errorf("CSP = %q", csp)
	}
	// Scripts and other files are passed through unchanged.
	if _, body := fetch(t, c, "https://www.example.com/app.js", false); body != "var x=1;" {
		t.Errorf("script = %q", body)
	}
}

func TestStylesheetsServed(t *testing.T) {
	c, hits := setupAllSites(t)
	resp, body := fetch(t, c, "https://"+cosmetic.AssetHost+"/s.css?h=www.example.com&v=1", false)
	if resp.StatusCode != 200 || !strings.Contains(body, ".example-ad") || !strings.Contains(resp.Header.Get("Content-Type"), "text/css") {
		t.Errorf("s.css: %d %q", resp.StatusCode, body)
	}
	if _, body := fetch(t, c, "https://"+cosmetic.AssetHost+"/g.css?v=1", false); !strings.Contains(body, ".ad-box") {
		t.Errorf("g.css = %q", body)
	}
	if hits.Load() != 0 {
		t.Error("stylesheet requests must not leave the Mac")
	}
}

func TestAdDomainsAnsweredByProxy(t *testing.T) {
	c, hits := setupAllSites(t)
	for _, u := range []string{"https://cdn.ads.example/tag.js", "http://ads.example/pixel.gif"} {
		resp, body := fetch(t, c, u, false)
		if resp.StatusCode != http.StatusForbidden || body != "" {
			t.Errorf("%s: %d %q, want empty 403", u, resp.StatusCode, body)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("ad requests reached the site %d times", hits.Load())
	}
}

func TestYouTubeStillPruned(t *testing.T) {
	c, _ := setupAllSites(t)
	_, body := fetch(t, c, "https://www.youtube.com/youtubei/v1/player", false)
	if strings.Contains(body, "adPlacements") || !strings.Contains(body, "videoDetails") {
		t.Errorf("player = %q", body)
	}
}

func TestShouldDecrypt(t *testing.T) {
	dir := t.TempDir()
	if err := certs.Generate(dir, false, []string{"paypal.com"}); err != nil {
		t.Fatal(err)
	}
	ca, err := certs.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{
		CA:      ca,
		Decrypt: func(h string) bool { return h != "bank.example" },
		Blocked: func(h string) bool { return h == "ads.paypal.com" },
	}
	for host, want := range map[string]bool{
		"www.example.com": true,
		"bank.example":    false,
		"1.2.3.4":         false,
		"bad host":        false,
		// The CA can't sign for these, so they're tunneled (or, when
		// blocked, closed) instead of decrypted.
		"www.paypal.com": false,
		"ads.paypal.com": false,
	} {
		if got := p.shouldDecrypt(host); got != want {
			t.Errorf("shouldDecrypt(%q) = %v, want %v", host, got, want)
		}
	}
	p.rejected.Store("www.example.com", 0)
	if p.shouldDecrypt("www.example.com") {
		t.Error("a host whose app refused our certificate must be tunneled")
	}
	// Without Decrypt: YouTube only, as before.
	q := &Proxy{CA: ca}
	if !q.shouldDecrypt("www.youtube.com") || q.shouldDecrypt("www.example.com") {
		t.Error("default should be YouTube only")
	}
}
