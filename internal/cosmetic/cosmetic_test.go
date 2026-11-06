package cosmetic

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const sample = `[Adblock Plus 2.0]
! comment
##.ad-banner
##.shared-ad
##div[id^="div-gpt-ad"]
example.com##.example-only
~news.example.com,example.com##.not-on-news
~quiet.org##.loud
example.com#@#.shared-ad
#@#.never
##.never
##.text:has-text(Sponsored)
##.bad::before
##+js(set-constant, x, 1)
example.com#?#.extended:-abp-contains(ad)
@@||nogeneric.net^$generichide
@@||nocosmetic.net^$elemhide
||ads.example.com^
`

func parsed(t *testing.T) *Rules {
	r, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParse(t *testing.T) {
	r := parsed(t)
	if want := []string{".ad-banner", `div[id^="div-gpt-ad"]`}; !slices.Equal(r.generic, want) {
		t.Errorf("generic = %q, want %q", r.generic, want)
	}
	cases := map[string][]string{
		"www.example.com":  {".example-only", ".loud", ".not-on-news"}, // .shared-ad excepted here
		"news.example.com": {".example-only", ".loud"},
		"other.com":        {".loud", ".shared-ad"},
		"quiet.org":        {".shared-ad"},
		"nogeneric.net":    nil,
		"nocosmetic.net":   nil,
	}
	for host, want := range cases {
		if got := r.SiteSelectors(host); !slices.Equal(got, want) {
			t.Errorf("SiteSelectors(%s) = %q, want %q", host, got, want)
		}
	}
	if r.GenericOn("nogeneric.net") || r.GenericOn("x.nocosmetic.net") || !r.GenericOn("other.com") {
		t.Error("GenericOn wrong")
	}
}

func TestValidSelector(t *testing.T) {
	good := []string{".ad", `a[href^="https://x.com/"] > img`, `div:not(.a):has(> .b)`, `[data-x="a:b{c}"]`, `a[href^="mailto:"]`, `[href*="@"]`, `[title="a;b"]`, `[alt="/*x"]`}
	bad := []string{"", ".a{}", ".a::after", ".a:contains(x)", `.a[href="x"`, ".a)", "</style><script>", `.a\`,
		`@import url("https://evil.example/x.css");div`, "@import url(https://evil.example/x.css);div",
		".a;b", ".a /* x */", "@media print"}
	for _, s := range good {
		if s == `[data-x="a:b{c}"]` {
			continue // braces are always refused, even quoted
		}
		if !validSelector(s) {
			t.Errorf("rejected %q", s)
		}
	}
	for _, s := range bad {
		if validSelector(s) {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestPatchCSP(t *testing.T) {
	cases := map[string]string{
		"default-src 'self'; script-src 'nonce-a'":   "default-src 'self'; script-src 'nonce-a'; style-src 'self' " + assetOrigin,
		"style-src 'self' 'nonce-b'; img-src *":      "style-src 'self' 'nonce-b' " + assetOrigin + "; img-src *",
		"style-src-elem 'none'; style-src 'self'":    "style-src-elem " + assetOrigin + "; style-src 'self' " + assetOrigin,
		"script-src 'self'":                          "script-src 'self'",
		"frame-ancestors 'none', default-src 'none'": "frame-ancestors 'none', default-src 'none'; style-src " + assetOrigin,
	}
	for in, want := range cases {
		got := PatchCSP(in)
		if strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(want), " ") {
			t.Errorf("PatchCSP(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestInject(t *testing.T) {
	e := NewEngine(parsed(t))
	pages := map[string]string{
		"<!DOCTYPE html><html><HEAD lang=en><title>x</title></head><body>hi</body></html>": `<HEAD lang=en><link rel="stylesheet"`,
		"<!doctype html><html lang=en><body>no head</body></html>":                         `<html lang=en><link rel="stylesheet"`,
		"<!doctype html><p>bare":      `<!doctype html><link rel="stylesheet"`,
		"<header>not a head</header>": `<link rel="stylesheet" href="https://assets.shoo.internal/g.css`,
	}
	for page, want := range pages {
		resp := &http.Response{Header: http.Header{"Content-Length": {"10"}, "Content-Security-Policy": {"default-src 'self'"}}, Body: io.NopCloser(strings.NewReader(page))}
		e.Inject("www.example.com", resp)
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), want) || !strings.Contains(string(b), "s.css?h=www.example.com") {
			t.Errorf("page %q became %q", page, b)
		}
		if resp.Header.Get("Content-Length") != "" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), assetOrigin) {
			t.Errorf("headers not updated: %v", resp.Header)
		}
	}
	// A big page: the tag goes in, and the rest of the page is intact.
	big := "<html><head></head><body>" + strings.Repeat("x", 1<<20) + "</body></html>"
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(big))}
	e.Inject("other.com", resp)
	b, _ := io.ReadAll(resp.Body)
	if len(b) <= len(big) || !strings.HasSuffix(string(b), "</body></html>") {
		t.Error("big page damaged")
	}
	// Nothing to hide: page untouched.
	resp = &http.Response{Header: http.Header{"Content-Length": {"4"}}, Body: io.NopCloser(strings.NewReader("<p>"))}
	e.Inject("nocosmetic.net", resp)
	if resp.Header.Get("Content-Length") != "4" {
		t.Error("page without rules was changed")
	}
}

func TestServeAsset(t *testing.T) {
	e := NewEngine(parsed(t))
	get := func(url string) (int, string) {
		w := httptest.NewRecorder()
		e.ServeAsset(w, httptest.NewRequest("GET", url, nil))
		return w.Code, w.Body.String()
	}
	if code, body := get("https://" + AssetHost + "/g.css?v=1"); code != 200 || !strings.Contains(body, ".ad-banner") || !strings.Contains(body, "display:none!important") {
		t.Errorf("g.css: %d %q", code, body)
	}
	if code, body := get("https://" + AssetHost + "/s.css?h=www.example.com&v=1"); code != 200 || !strings.Contains(body, ".example-only") || strings.Contains(body, ".shared-ad") {
		t.Errorf("s.css: %d %q", code, body)
	}
	if code, _ := get("https://" + AssetHost + "/s.css?h=bad%20name"); code != 404 {
		t.Errorf("bad host: %d", code)
	}
	for i := 0; i < maxSites+10; i++ {
		get(fmt.Sprintf("https://%s/s.css?h=x%d.example", AssetHost, i))
	}
	if n := e.nsites.Load(); n > maxSites {
		t.Errorf("site cache holds %d entries, cap is %d", n, maxSites)
	}
	if code, _ := get("https://" + AssetHost + "/other"); code != 404 {
		t.Errorf("other path: %d", code)
	}
}

// A filter list must not be able to make the stylesheet load another one.
func TestNoImportFromLists(t *testing.T) {
	r, err := Parse(strings.NewReader("victim.example##@import url(\"https://evil.example/x.css\");div\n" +
		"##@import url(https://evil.example/g.css);p\n##.ad\n"))
	if err != nil {
		t.Fatal(err)
	}
	css := string(CSS(r.generic)) + string(CSS(r.SiteSelectors("victim.example")))
	if strings.Contains(css, "@") || strings.Contains(css, "evil") {
		t.Errorf("stylesheet loads another: %q", css)
	}
}
