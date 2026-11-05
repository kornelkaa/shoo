package sites

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const hostsSample = `# StevenBlack-style hosts file
127.0.0.1 localhost
::1 localhost
0.0.0.0 0.0.0.0
0.0.0.0 doubleclick.net
0.0.0.0 ad.doubleclick.net   # covered by parent
0.0.0.0 tracker.example.org
0.0.0.0 ads.youtube.com
0.0.0.0 r1---sn-abc.googlevideo.com
192.168.1.10 printer.home.lan
plain-list.example
0.0.0.0 BadCase.EXAMPLE.net.
0.0.0.0 not_a<domain>
`

func sampleList(t *testing.T, allowed ...string) *List {
	t.Helper()
	d, err := ParseHosts(strings.NewReader(hostsSample))
	if err != nil {
		t.Fatal(err)
	}
	return NewList(d, allowed)
}

func TestParseHosts(t *testing.T) {
	d, err := ParseHosts(strings.NewReader(hostsSample))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(d, ",")
	want := "doubleclick.net,ad.doubleclick.net,tracker.example.org,ads.youtube.com,r1---sn-abc.googlevideo.com,plain-list.example,badcase.example.net"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestBlocked(t *testing.T) {
	l := sampleList(t, "tracker.example.org")
	cases := map[string]bool{
		"doubleclick.net":                true,
		"securepubads.g.doubleclick.net": true, // subdomain of a blocked domain
		"DoubleClick.NET.":               true,
		"notdoubleclick.net":             false,
		"tracker.example.org":            false, // allowed by the user
		"x.tracker.example.org":          false,
		"badcase.example.net":            true,
		"example.net":                    false, // parent of a blocked domain is not blocked
		"apple.com":                      false,
		"ads.youtube.com":                false, // YouTube is never blocked
		"www.youtube.com":                false,
		"r1---sn-abc.googlevideo.com":    false,
		"youtubei.googleapis.com":        false,
		"printer.home.lan":               false,
		"i.ytimg.com":                    false,
		"www.youtube-nocookie.com":       false,
	}
	for host, want := range cases {
		if got := l.Blocked(host); got != want {
			t.Errorf("Blocked(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestPACContents(t *testing.T) {
	pac := PAC("127.0.0.1:8899", sampleList(t))
	for _, want := range []string{
		`var YT = ["youtube.com","youtubei.googleapis.com"]`,
		`return "PROXY 127.0.0.1:8899; DIRECT"`, // YouTube: same as the YouTube-only PAC
		`return "PROXY 127.0.0.1:8899";`,        // blocked: no DIRECT fallback
		`"doubleclick.net":1`,
		`"googlevideo.com":1`, // in KEEP
	} {
		if !strings.Contains(pac, want) {
			t.Errorf("PAC missing %q", want)
		}
	}
	for _, bad := range []string{`"ad.doubleclick.net"`, `"ads.youtube.com"`, `"r1---sn-abc.googlevideo.com"`} {
		if strings.Contains(pac, bad) {
			t.Errorf("PAC should not contain %s", bad)
		}
	}
}

// fakeYouTube records which requests reached the YouTube proxy.
type fakeYouTube struct{ got []string }

func (f *fakeYouTube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.got = append(f.got, r.Method+" "+r.Host)
	w.WriteHeader(299)
}

func TestHandlerRouting(t *testing.T) {
	yt := &fakeYouTube{}
	h := NewHandler(yt, "127.0.0.1:8899", sampleList(t), log.New(io.Discard, "", 0))
	srv := httptest.NewServer(h)
	defer srv.Close()

	connect := func(target string) int {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}

	if code := connect("securepubads.g.doubleclick.net:443"); code != http.StatusForbidden {
		t.Errorf("blocked CONNECT: got %d, want 403", code)
	}
	if code := connect("www.youtube.com:443"); code != 299 {
		t.Errorf("YouTube CONNECT: got %d, want it passed to the YouTube proxy", code)
	}
	if len(yt.got) != 1 || yt.got[0] != "CONNECT www.youtube.com:443" {
		t.Errorf("YouTube proxy got %v", yt.got)
	}

	resp, err := http.Get(srv.URL + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "FindProxyForURL") || !strings.Contains(string(b), "doubleclick.net") {
		t.Error("combined PAC not served")
	}

	resp, err = http.Get(srv.URL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"blocked":1`) {
		t.Errorf("stats = %s", b)
	}
}

func TestLoadAndAddDomain(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, BlocklistFile), []byte("0.0.0.0 ads.example.com\n"), 0o644)
	if err := AddDomain(dir, BlockFile, "extra.example.net"); err != nil {
		t.Fatal(err)
	}
	if err := AddDomain(dir, BlockFile, "extra.example.net"); err != nil { // no duplicate
		t.Fatal(err)
	}
	if err := AddDomain(dir, AllowFile, "ads.example.com"); err != nil {
		t.Fatal(err)
	}
	l, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Blocked("extra.example.net") || l.Blocked("ads.example.com") {
		t.Error("user block/allow files not applied")
	}
	b, _ := os.ReadFile(filepath.Join(dir, BlockFile))
	if strings.Count(string(b), "extra.example.net") != 1 {
		t.Errorf("duplicate entry: %q", b)
	}
}

func TestValidateDomain(t *testing.T) {
	if _, err := ValidateDomain("Ads.Example.com"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "com", "https://x.com/", "a b.com", "..x.com"} {
		if _, err := ValidateDomain(bad); err == nil {
			t.Errorf("ValidateDomain(%q) should fail", bad)
		}
	}
}

func TestUpdateMergesListsAndKeepsOldOnFailure(t *testing.T) {
	big := func(prefix string) string {
		var b strings.Builder
		for i := 0; i < minDomains; i++ {
			fmt.Fprintf(&b, "%s%d.example.com\n", prefix, i)
		}
		return b.String()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hosts":
			io.WriteString(w, "0.0.0.0 shared.example.com\n"+strings.ReplaceAll(big("a"), "\n", "\n0.0.0.0 "))
		case "/plain":
			io.WriteString(w, "shared.example.com\n"+big("b"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	n, err := Update(context.Background(), dir, []string{srv.URL + "/hosts", srv.URL + "/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if want := 2*minDomains + 1; n != want { // shared.example.com counted once
		t.Fatalf("saved %d domains, want %d", n, want)
	}
	l, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Blocked("a5.example.com") || !l.Blocked("b5.example.com") || !l.Blocked("shared.example.com") {
		t.Error("merged list incomplete")
	}

	if _, err := Update(context.Background(), dir, []string{srv.URL + "/plain", srv.URL + "/missing"}); err == nil {
		t.Fatal("a failed download should fail the update")
	}
	if l, _ := Load(dir); !l.Blocked("a5.example.com") {
		t.Error("old list should be kept when an update fails")
	}
}

func TestSourcesAndNeedsUpdate(t *testing.T) {
	dir := t.TempDir()
	if !needsUpdate(dir, time.Hour) {
		t.Error("missing list should need an update")
	}
	if Sources(dir) != nil {
		t.Error("no sources expected without a list")
	}
	os.WriteFile(filepath.Join(dir, BlocklistFile), []byte("# Source: https://a.example/list\n# Source: https://b.example/list\n# Downloaded: x\nads.example.com\n# Source: https://not-header\n"), 0o644)
	if got := strings.Join(Sources(dir), ","); got != "https://a.example/list,https://b.example/list" {
		t.Errorf("Sources = %s", got)
	}
	if needsUpdate(dir, time.Hour) {
		t.Error("fresh list should not need an update")
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	os.Chtimes(filepath.Join(dir, BlocklistFile), old, old)
	if !needsUpdate(dir, 7*24*time.Hour) {
		t.Error("8-day-old list should need an update")
	}
}
