package proxy

import (
	"compress/gzip"
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
	"testing"

	"shoo/internal/certs"
	"shoo/internal/prune"
)

const watchHTML = `<html><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"abc"},"adPlacements":[{"x":1}]};</script></html>`

const playerJSON = `{"videoDetails":{"videoId":"abc"},"adPlacements":[{"x":1}],"playerAds":[{}],"adSlots":[]}`

// setup starts a fake "YouTube" server, the proxy pointed at it, and a client
// that trusts only our CA and sends everything through the proxy.
func setup(t *testing.T) (*http.Client, *int) {
	c, n, _ := setupWithURL(t)
	return c, n
}

func setupWithURL(t *testing.T) (*http.Client, *int, string) {
	t.Helper()
	gotGzip := new(int)
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ctype := playerJSON, "application/json; charset=UTF-8"
		if r.URL.Path == "/watch" {
			body, ctype = watchHTML, "text/html; charset=utf-8"
		}
		w.Header().Set("Content-Type", ctype)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			*gotGzip++
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			io.WriteString(gz, body)
			gz.Close()
			return
		}
		io.WriteString(w, body)
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
	p := New(ca, prune.Default, log.New(io.Discard, "", 0))
	p.Addr = "127.0.0.1:8899"
	// Route "upstream YouTube" to the fake server.
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
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	return client, gotGzip, ps.URL
}

func get(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(`{}`))
	// Like a browser: ask for compression ourselves.
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ce := resp.Header.Get("Content-Encoding"); ce == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(gz)
		return string(b)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestPlayerAdsRemovedThroughProxy(t *testing.T) {
	c, gotGzip := setup(t)
	body := get(t, c, "https://www.youtube.com/youtubei/v1/player?prettyPrint=false")
	if strings.Contains(body, "adPlacements") || strings.Contains(body, "playerAds") || strings.Contains(body, "adSlots") {
		t.Fatalf("ads not removed: %s", body)
	}
	if !strings.Contains(body, `"videoId":"abc"`) {
		t.Fatalf("video data lost: %s", body)
	}
	if *gotGzip == 0 {
		t.Error("upstream should still be asked for gzip")
	}
}

func TestOtherPathsUntouched(t *testing.T) {
	c, _ := setup(t)
	body := get(t, c, "https://www.youtube.com/youtubei/v1/log_event")
	if body != playerJSON {
		t.Fatalf("non-matching path was modified: %s", body)
	}
}

func TestWatchPageAdsRemoved(t *testing.T) {
	c, _ := setup(t)
	req, _ := http.NewRequest("GET", "https://www.youtube.com/watch?v=abc", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	s := string(b)
	if strings.Contains(s, "adPlacements") || !strings.Contains(s, `"videoId":"abc"`) {
		t.Fatalf("got %s", s)
	}
}

func TestPACFile(t *testing.T) {
	_, _, proxyURL := setupWithURL(t)
	resp, err := http.Get(proxyURL + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	s := string(b)
	for _, want := range []string{"FindProxyForURL", `"PROXY 127.0.0.1:8899; DIRECT"`, `dnsDomainIs(host, ".youtube.com")`, `return "DIRECT"`} {
		if !strings.Contains(s, want) {
			t.Errorf("PAC missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "googlevideo") {
		t.Error("video stream must not be proxied")
	}
}
