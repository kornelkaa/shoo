package ytextra

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Home page: a grid with a banner ad and an ad tile between videos.
const homeFeed = `{"contents":{"twoColumnBrowseResultsRenderer":{"tabs":[{"tabRenderer":{"content":{"richGridRenderer":{
  "masthead":{"adSlotRenderer":{"x":1}},
  "contents":[
    {"richItemRenderer":{"content":{"videoRenderer":{"videoId":"v1"}}}},
    {"richItemRenderer":{"content":{"adSlotRenderer":{"fulfillmentContent":{"fulfilledLayout":{"inFeedAdLayoutRenderer":{}}}}},"trackingParams":"t"}},
    {"richSectionRenderer":{"content":{"statementBannerRenderer":{}}}},
    {"richSectionRenderer":{"content":{"richShelfRenderer":{"contents":[{"richItemRenderer":{"content":{"videoRenderer":{"videoId":"v2"}}}}]}}}},
    {"richItemRenderer":{"content":{"videoRenderer":{"videoId":"v3"}}}}
  ]}}}}]}},
  "onResponseReceivedActions":[{"appendContinuationItemsAction":{}},{"adsControlFlowOpportunityReceivedCommand":{"adSlotAndLayoutMetadata":[]}}]}`

func TestHomeFeed(t *testing.T) {
	out, n := cleanJSON([]byte(homeFeed), false)
	s := string(out)
	if n != 4 { // banner, ad tile, statement banner, ads command
		t.Fatalf("removed %d, want 4: %s", n, s)
	}
	for _, bad := range []string{"adSlotRenderer", "statementBannerRenderer", "adsControlFlow", "masthead"} {
		if strings.Contains(s, bad) {
			t.Errorf("%s left", bad)
		}
	}
	for _, keep := range []string{`"v1"`, `"v2"`, `"v3"`, "richGridRenderer", "richShelfRenderer", "appendContinuationItemsAction"} {
		if !strings.Contains(s, keep) {
			t.Errorf("lost %s", keep)
		}
	}
}

func TestSearchAndSidebar(t *testing.T) {
	in := `{"results":[{"adSlotRenderer":{}},{"compactVideoRenderer":{"videoId":"a"}},{"searchPyvRenderer":{}},{"itemSectionRenderer":{"contents":[{"promotedSparklesWebRenderer":{}},{"videoRenderer":{"videoId":"b"}}]}}]}`
	out, n := cleanJSON([]byte(in), false)
	s := string(out)
	if n != 3 || !strings.Contains(s, `"a"`) || !strings.Contains(s, `"b"`) || strings.Contains(s, "Pyv") || strings.Contains(s, "promoted") {
		t.Fatalf("n=%d %s", n, s)
	}
}

func TestNoAdsUnchanged(t *testing.T) {
	in := []byte(`{"contents":[{"richItemRenderer":{"content":{"videoRenderer":{}}}}],  "x":1}`)
	out, n := cleanJSON(in, false)
	if n != 0 || string(out) != string(in) {
		t.Fatal("changed a response without ads")
	}
}

func TestHTMLPage(t *testing.T) {
	page := `<script>var ytInitialData = {"contents":[{"richItemRenderer":{"content":{"adSlotRenderer":{}}}},{"richItemRenderer":{"content":{"videoRenderer":{"title":"a </script> b"}}}}]};</script>` +
		`<script>if (window.ytInitialData == null) {}</script>`
	out, n := cleanHTML([]byte(page))
	s := string(out)
	if n != 1 || strings.Contains(s, "adSlotRenderer") || !strings.Contains(s, "a \\u003c/script\\u003e b") || !strings.Contains(s, "window.ytInitialData == null") {
		t.Fatalf("n=%d %s", n, s)
	}
}

type fixed struct {
	ctype, body string
}

func (f fixed) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {f.ctype}}, Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

func TestFeedCleanerOnlyFeeds(t *testing.T) {
	get := func(path, ctype, body string) string {
		fc := &FeedCleaner{Next: fixed{ctype, body}}
		req, _ := http.NewRequest("POST", "https://www.youtube.com"+path, nil)
		resp, err := fc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		if string(b) != body && resp.ContentLength != int64(len(b)) {
			t.Errorf("%s: Content-Length %d, body %d", path, resp.ContentLength, len(b))
		}
		return string(b)
	}
	if s := get("/youtubei/v1/browse", "application/json; charset=UTF-8", homeFeed); strings.Contains(s, "adSlotRenderer") {
		t.Error("browse not cleaned")
	}
	if s := get("/youtubei/v1/log_event", "application/json", homeFeed); s != homeFeed {
		t.Error("other paths must pass through unchanged")
	}
}

// Runs against a real home feed saved by ytblock-debug, if one exists on
// this Mac: every ad tile goes, every video tile stays.
func TestRealSavedHomeFeed(t *testing.T) {
	home, _ := os.UserHomeDir()
	files, _ := filepath.Glob(filepath.Join(home, "Library/Logs/ytblock-debug/*/responses/*browse*.json"))
	if len(files) == 0 {
		t.Skip("no saved feed")
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out, n := cleanJSON(body, false)
		if !json.Valid(out) {
			t.Fatalf("%s: invalid JSON after cleaning", f)
		}
		videosBefore := strings.Count(string(body), `"videoId"`)
		videosAfter := strings.Count(string(out), `"videoId"`)
		// Count ad objects, not the words: YouTube also lists renderer names as plain text.
		adsLeft := strings.Count(string(out), `"adSlotRenderer":{`) + strings.Count(string(out), `"inFeedAdLayoutRenderer":{`)
		t.Logf("%s: removed %d ad items; videoId mentions %d -> %d", filepath.Base(f), n, videosBefore, videosAfter)
		if n == 0 || adsLeft != 0 {
			t.Errorf("ads left: %d", adsLeft)
		}
		if videosAfter < videosBefore*9/10 {
			t.Errorf("too many video tiles lost: %d -> %d", videosBefore, videosAfter)
		}
	}
}
