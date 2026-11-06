package netfilter

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func rules(t *testing.T, lines ...string) *Rules {
	t.Helper()
	r, err := Parse(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// req is a request from a page on page (third-party if the sites differ).
func req(url, page, typ string) *Request {
	q := NewRequest(url, page, typ, false)
	q.ThirdParty = page != "" && siteOf(page) != siteOf(q.Host)
	return q
}

func TestPatterns(t *testing.T) {
	cases := []struct {
		rule, url string
		want      bool
	}{
		// "||": the host or a subdomain, label-aligned.
		{"||ads.example^", "https://ads.example/x.js", true},
		{"||ads.example^", "https://cdn.ads.example/x.js", true},
		{"||ads.example^", "https://badads.example/x.js", false},
		{"||ads.example^", "https://ads.example.com/x.js", false},
		{"||ads.example^", "https://ads.example:8443/x.js", true},
		{"||example.com/ads/", "https://www.example.com/ads/1.png", true},
		{"||example.com/ads/", "https://www.example.com/news/ads/1.png", false},
		{"||example.com^*/track", "https://example.com/a/b/track?x", true},
		// No anchor: anywhere.
		{"/banner/ad-", "https://x.example/img/banner/ad-1.gif", true},
		{"/banner/ad-", "https://x.example/img/banner/add.gif", false},
		{"-ad-300x250.", "https://x.example/i-ad-300x250.png", true},
		// '^' is a separator or the end, not a letter, digit or "_-.%".
		{"/ads^", "https://x.example/ads?x=1", true},
		{"/ads^", "https://x.example/ads", true},
		{"/ads^", "https://x.example/adsense", false},
		{"/ads^", "https://x.example/ads.js", false},
		// '*' with backtracking.
		{"/ad*/img*.gif", "https://x.example/adserve/a/img9.gif", true},
		{"/ad*/img*.gif", "https://x.example/adserve/a/img9.png", false},
		// "|" anchors.
		{"|https://ads.", "https://ads.example/", true},
		{"|https://ads.", "https://x.example/?u=https://ads.example", false},
		{".swf|", "https://x.example/movie.swf", true},
		{".swf|", "https://x.example/movie.swf?x", false},
		// Case-insensitive unless match-case.
		{"/AdBanner.", "https://x.example/adbanner.js", true},
		{"/AdBanner.$match-case", "https://x.example/adbanner.js", false},
		{"/AdBanner.$match-case", "https://x.example/AdBanner.js", true},
		// Regex.
		{`/\/ad[0-9]+\.js/`, "https://x.example/ad42.js", true},
		{`/\/ad[0-9]+\.js/`, "https://x.example/adx.js", false},
		{`/\.example\/[a-z]{12}\.js$/`, "https://x.example/abcdefghijkl.js", true},
	}
	for _, c := range cases {
		r := rules(t, c.rule)
		if r.Len() != 1 {
			t.Errorf("%s: not parsed", c.rule)
			continue
		}
		if got := r.Match(req(c.url, "x.example", "script")) != ""; got != c.want {
			t.Errorf("%s on %s = %v, want %v", c.rule, c.url, got, c.want)
		}
	}
}

func TestOptions(t *testing.T) {
	r := rules(t,
		"||tracker.example^$third-party",
		"||cdn.example/ads.js$script",
		"/promo/*$image,domain=news.example|~sports.news.example",
		"||widgets.example^$~third-party",
		"||everything.example^$~image",
	)
	cases := []struct {
		url, page, typ string
		want           bool
	}{
		{"https://tracker.example/p.gif", "news.example", "image", true},
		{"https://tracker.example/p.gif", "www.tracker.example", "image", false}, // first-party
		{"https://cdn.example/ads.js", "a.example", "script", true},
		{"https://cdn.example/ads.js", "a.example", "xmlhttprequest", false},
		{"https://img.example/promo/1.png", "news.example", "image", true},
		{"https://img.example/promo/1.png", "www.news.example", "image", true},
		{"https://img.example/promo/1.png", "sports.news.example", "image", false},
		{"https://img.example/promo/1.png", "other.example", "image", false},
		{"https://img.example/promo/1.png", "", "image", false}, // page unknown
		{"https://widgets.example/w.js", "widgets.example", "script", true},
		{"https://widgets.example/w.js", "other.example", "script", false},
		{"https://everything.example/a.js", "x.example", "script", true},
		{"https://everything.example/a.png", "x.example", "image", false},
		// Pages themselves are never blocked.
		{"https://tracker.example/", "", "document", false},
	}
	for _, c := range cases {
		if got := r.Match(req(c.url, c.page, c.typ)) != ""; got != c.want {
			t.Errorf("%s (%s from %q) = %v, want %v", c.url, c.typ, c.page, got, c.want)
		}
	}
}

func TestExceptionsAndImportant(t *testing.T) {
	r := rules(t,
		"||ads.example^",
		"@@||ads.example/needed.js",
		"||track.example^$important",
		"@@||track.example^",
		"||cdn.example/ad.js",
		"@@||cdn.example/ad.js$domain=good.example",
		"||blocked.example^",
		"@@||trusted-site.example^$document",
	)
	cases := []struct {
		url, page string
		want      bool
	}{
		{"https://ads.example/x.js", "a.example", true},
		{"https://ads.example/needed.js", "a.example", false},
		{"https://track.example/p.js", "a.example", true}, // $important beats @@
		{"https://cdn.example/ad.js", "a.example", true},
		{"https://cdn.example/ad.js", "good.example", false},
		{"https://blocked.example/x.js", "a.example", true},
		{"https://blocked.example/x.js", "trusted-site.example", false}, // page allowed
		{"https://blocked.example/x.js", "www.trusted-site.example", false},
	}
	for _, c := range cases {
		if got := r.Match(req(c.url, c.page, "script")) != ""; got != c.want {
			t.Errorf("%s from %s = %v, want %v", c.url, c.page, got, c.want)
		}
	}
}

func TestSkippedRules(t *testing.T) {
	for _, line := range []string{
		"! comment", "[Adblock Plus 2.0]", "",
		"example.com##.ad", "example.com#@#.ad", "example.com#?#.ad:has-text(x)", "example.com##+js(nobab)",
		"||ads.example^$redirect=noopjs",
		"||ads.example^$removeparam=utm_source",
		"||ads.example^$csp=script-src 'none'",
		"||ads.example^$denyallow=x.com",
		"||ads.example^$popup",
		"||ads.example^$document",
		"@@||site.example^$generichide",
		"*$script",                                  // every script everywhere
		"||ads.example^$domain=google.*",            // only unsupported page names
		"||ads.example^$domain=a.example|~google.*", // dropping ~google.* would widen it
		`/(?<=ad)x/`,                                // lookbehind: not in Go
	} {
		if r := rules(t, line); r.Len() != 0 {
			t.Errorf("%q should be skipped", line)
		}
	}
	// A rule limited to some pages may match every URL there.
	if r := rules(t, "*$script,domain=a.example"); r.Len() != 1 || r.Match(req("https://x.example/a.js", "a.example", "script")) == "" {
		t.Error("*$script,domain= should work")
	}
	// Supported entries of domain= are kept when others are dropped.
	r := rules(t, "||ads.example^$domain=a.example|google.*")
	if r.Match(req("https://ads.example/x", "a.example", "script")) == "" || r.Match(req("https://ads.example/x", "b.example", "script")) != "" {
		t.Error("domain=a.example|google.* should apply on a.example only")
	}
}

func TestBadfilter(t *testing.T) {
	r := rules(t, "||ads.example^$script,third-party", "||ads.example^$third-party,script,badfilter", "||other.example^")
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
	if r.Match(req("https://ads.example/x.js", "a.example", "script")) != "" {
		t.Error("$badfilter didn't cancel the rule")
	}
}

func TestIfBlocksSkipped(t *testing.T) {
	r := rules(t, "!#if env_firefox", "||firefox.example^", "!#endif", "||all.example^")
	if r.Len() != 1 || r.Match(req("https://firefox.example/x", "a.example", "script")) != "" {
		t.Error("rules inside !#if should be skipped")
	}
}

// The index must find exactly what trying every rule would.
func TestIndexAgreesWithBruteForce(t *testing.T) {
	lines := []string{
		"||ads.example^", "||a.b.example/x/", "/banner/*/img", "-ad-300x250.", "/ads^",
		"||cdn.example^*/track.js|", ".swf|", "|https://pop.", `/\/ad[0-9]+\./`,
		"_adbanner_", "&ad_type=", "/pixel?", "^ad_", "||x.example/*.gif$image",
	}
	urls := []string{
		"https://ads.example/1", "https://www.a.b.example/x/y", "https://q.example/banner/9/img.png",
		"https://q.example/i-ad-300x250.png", "https://q.example/ads?x", "https://cdn.example/a/track.js",
		"https://q.example/m.swf", "https://pop.example/", "https://q.example/ad7.js",
		"https://q.example/x_adbanner_1.png", "https://q.example/?a=1&ad_type=2", "https://q.example/pixel?id=1",
		"https://q.example/?ad_x", "https://x.example/a/b.gif", "https://nothing.example/plain",
	}
	var fs []*filter
	for _, l := range lines {
		if f, _ := parse(l); f != nil {
			fs = append(fs, f)
		} else {
			t.Fatalf("not parsed: %s", l)
		}
	}
	r := rules(t, lines...)
	for _, u := range urls {
		q := req(u, "page.example", "image")
		brute := false
		for _, f := range fs {
			if f.matchOptions(q) && f.matchURL(q) {
				brute = true
			}
		}
		if got := r.Match(q) != ""; got != brute {
			t.Errorf("%s: index says %v, trying every rule says %v", u, got, brute)
		}
	}
}

func TestFromHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "https://cdn.example/a.js?x=1", nil)
	r.Header.Set("Sec-Fetch-Dest", "script")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Referer", "https://www.news.example/story")
	q := FromHTTP(r, "https", "cdn.example")
	if q.URL != "https://cdn.example/a.js?x=1" || q.Type != "script" || q.PageHost != "www.news.example" || !q.ThirdParty {
		t.Errorf("got %+v", q)
	}

	// No Sec-Fetch-Site: compare registrable domains.
	r = httptest.NewRequest("GET", "https://static.bbc.co.uk/i.png", nil)
	r.Header.Set("Sec-Fetch-Dest", "image")
	r.Header.Set("Referer", "https://www.bbc.co.uk/")
	if q := FromHTTP(r, "https", "static.bbc.co.uk"); q.ThirdParty {
		t.Error("www.bbc.co.uk -> static.bbc.co.uk is first-party")
	}
	r.Header.Set("Referer", "https://www.other.co.uk/")
	if q := FromHTTP(r, "https", "static.bbc.co.uk"); !q.ThirdParty {
		t.Error("other.co.uk -> bbc.co.uk is third-party")
	}

	for dest, want := range map[string]string{
		"iframe": "subdocument", "style": "stylesheet", "empty": "xmlhttprequest",
		"video": "media", "font": "font", "document": "document", "worker": "script",
	} {
		r := httptest.NewRequest("GET", "https://a.example/", nil)
		r.Header.Set("Sec-Fetch-Dest", dest)
		if got := FromHTTP(r, "https", "a.example").Type; got != want {
			t.Errorf("Sec-Fetch-Dest %s = %s, want %s", dest, got, want)
		}
	}
}

func TestEngineSwap(t *testing.T) {
	e := NewEngine(nil)
	q := req("https://ads.example/x.js", "a.example", "script")
	if e.Match(q) != "" {
		t.Error("empty engine blocked")
	}
	e.SetRules(rules(t, "||ads.example^"))
	if e.Match(q) != "||ads.example^" {
		t.Error("new rules not used")
	}
}
