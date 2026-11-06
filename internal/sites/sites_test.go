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
	l := sampleList(t)
	l.AddSkip([]string{"mybank.example"})
	pac := PAC("127.0.0.1:8899", l)
	for _, want := range []string{
		`return "PROXY 127.0.0.1:8899; DIRECT"`, // everything else: through shoo, direct if it's off
		`"googlevideo.com":1`,                   // never decrypted
		`"accounts.google.com":1`,
		`"otpbank.hu":1`,
		`"mybank.example":1`,
		`isPlainHostName(host)`,
	} {
		if !strings.Contains(pac, want) {
			t.Errorf("PAC missing %q", want)
		}
	}
	if strings.Contains(pac, "doubleclick") || len(pac) > 64<<10 {
		t.Errorf("PAC should not list ad domains (%d bytes)", len(pac))
	}
}

func TestDecrypt(t *testing.T) {
	l := sampleList(t)
	l.AddSkip([]string{"mybank.example"})
	for host, want := range map[string]bool{
		"www.dictionary.com":          true,
		"www.youtube.com":             true,
		"doubleclick.net":             true,
		"accounts.google.com":         false,
		"r1---sn-abc.googlevideo.com": false,
		"login.mybank.example":        false,
		"www.otpbank.hu":              false,
		"appleid.apple.com":           false,
	} {
		if got := l.Decrypt(host); got != want {
			t.Errorf("Decrypt(%q) = %v, want %v", host, got, want)
		}
	}
}

// fakeProxy records which requests reached the proxy.
type fakeProxy struct{ got []string }

func (f *fakeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.got = append(f.got, r.Method+" "+r.Host)
	w.WriteHeader(299)
}

func TestHandlerRouting(t *testing.T) {
	px := &fakeProxy{}
	h := NewHandler(px, "127.0.0.1:8899", sampleList(t), log.New(io.Discard, "", 0))
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

	// All proxy requests, ad domains included, go to the proxy, which
	// asks Blocked (refusing here would make macOS connect directly).
	for _, target := range []string{"securepubads.g.doubleclick.net:443", "www.youtube.com:443"} {
		if code := connect(target); code != 299 {
			t.Errorf("CONNECT %s: got %d, want it passed to the proxy", target, code)
		}
	}
	if len(px.got) != 2 {
		t.Errorf("proxy got %v", px.got)
	}
	if !h.Blocked("securepubads.g.doubleclick.net") || h.Blocked("www.youtube.com") || h.Decrypt("accounts.google.com") {
		t.Error("Blocked/Decrypt wrong")
	}

	resp, err := http.Get(srv.URL + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "FindProxyForURL") {
		t.Error("PAC not served")
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

// YouTube's page and API must stay decryptable, or its ad data can't be removed.
func TestYouTubeNeverSkipped(t *testing.T) {
	l := NewList(nil, nil)
	for _, h := range []string{"www.youtube.com", "youtubei.googleapis.com", "m.youtube.com"} {
		if !l.Decrypt(h) {
			t.Errorf("%s is on the never-decrypt list", h)
		}
	}
}

// A website that rebinds its name to 127.0.0.1 must not read the PAC file
// (it lists the user's own never-decrypt sites) or the stats.
func TestHandlerOnlyAnswersLocalNames(t *testing.T) {
	var passed int
	px := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passed++; w.WriteHeader(http.StatusBadRequest) })
	h := NewHandler(px, "127.0.0.1:8899", sampleList(t), log.New(io.Discard, "", 0))
	for _, path := range []string{"/proxy.pac", "/stats"} {
		for host, ok := range map[string]bool{"127.0.0.1:8899": true, "evil.example:8899": false} {
			r := httptest.NewRequest("GET", path, nil)
			r.Host = host
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if (w.Code == http.StatusOK) != ok {
				t.Errorf("%s with Host %s: %d", path, host, w.Code)
			}
		}
	}
	if passed != 2 {
		t.Errorf("%d foreign requests reached the proxy, want 2 (which refuses them)", passed)
	}
}
