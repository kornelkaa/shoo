package prune

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const samplePlayer = `{
  "playabilityStatus": {"status": "OK"},
  "streamingData": {"expiresInSeconds": "21540", "formats": [{"itag": 18, "contentLength": 12345678901234567890}]},
  "adPlacements": [{"adPlacementRenderer": {"config": {"kind": "AD_PLACEMENT_KIND_START"}}}],
  "playerAds": [{"playerLegacyDesktopWatchAdsRenderer": {}}],
  "adBreakHeartbeatParams": "Q0FB",
  "videoDetails": {"videoId": "dQw4w9WgXcQ", "title": "<Test & title>"},
  "nested": {"deeper": [{"adSlots": [{"adSlotRenderer": {}}], "keep": true}]}
}`

func TestJSONRemovesAdFields(t *testing.T) {
	out, n, err := Default.JSON([]byte(samplePlayer))
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("removed %d keys, want 4", n)
	}
	s := string(out)
	for _, k := range Default.Keys {
		if strings.Contains(s, `"`+k+`"`) {
			t.Errorf("%s still present", k)
		}
	}
	for _, keep := range []string{"dQw4w9WgXcQ", "12345678901234567890", "<Test & title>", `"keep":true`, "streamingData"} {
		if !strings.Contains(s, keep) {
			t.Errorf("lost %q", keep)
		}
	}
	if !json.Valid(out) {
		t.Error("output is not valid JSON")
	}
}

func TestJSONNoAdsReturnsOriginal(t *testing.T) {
	in := []byte(`{"videoDetails":{"videoId":"x"},  "z":1}`)
	out, n, err := Default.JSON(in)
	if err != nil || n != 0 || !bytes.Equal(in, out) {
		t.Fatalf("got n=%d err=%v out=%s", n, err, out)
	}
}

func TestJSONInvalidPassesThrough(t *testing.T) {
	in := []byte(`)]}'` + "\n{")
	out, _, err := Default.JSON(in)
	if err == nil || !bytes.Equal(in, out) {
		t.Fatal("invalid JSON should be returned unchanged with an error")
	}
}

func TestMatches(t *testing.T) {
	cases := map[string]bool{
		"/youtubei/v1/player":        true,
		"/youtubei/v1/next":          true,
		"/youtubei/v1/playerx":       false,
		"/youtubei/v1/log_event":     false,
		"/watch":                     false,
		"/youtubei/v1/browse/edit_x": true,
	}
	for p, want := range cases {
		if got := Default.Matches(p); got != want {
			t.Errorf("Matches(%q)=%v want %v", p, got, want)
		}
	}
}

const samplePage = `<html><head><script nonce="n">var ytInitialPlayerResponse = {"videoDetails":{"videoId":"abc","title":"a </script> b"},"adPlacements":[{"x":1}],"playerAds":[]};var meta = 1;</script>
<script>if (window.ytInitialPlayerResponse == null) {}</script>
<script>window["ytInitialData"] = {"contents":{"items":[{"adSlots":[1]},{"video":"v"}]}};</script>
<script>var ytInitialPlayerResponseX = {"adPlacements":[]};</script></head></html>`

func TestHTMLRemovesAdFields(t *testing.T) {
	out, n := Default.HTML([]byte(samplePage))
	s := string(out)
	if n != 3 {
		t.Fatalf("removed %d, want 3\n%s", n, s)
	}
	for _, want := range []string{
		`"videoId":"abc"`,
		`a \u003c/script\u003e b`, // escaped so it can't end the script tag
		`;var meta = 1;</script>`,
		`if (window.ytInitialPlayerResponse == null) {}`,
		`"video":"v"`,
		`var ytInitialPlayerResponseX = {"adPlacements":[]};`, // different variable: untouched
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "playerAds") || strings.Contains(s, "adSlots") {
		t.Errorf("ad fields left:\n%s", s)
	}
}

func TestHTMLWithoutAdsUnchanged(t *testing.T) {
	in := []byte(`<script>var ytInitialPlayerResponse = {"videoDetails":{}};</script>`)
	out, n := Default.HTML(in)
	if n != 0 || !bytes.Equal(in, out) {
		t.Fatalf("n=%d out=%s", n, out)
	}
}

func TestHTMLBrokenJSONUnchanged(t *testing.T) {
	in := []byte(`<script>var ytInitialPlayerResponse = {"adPlacements": [</script>`)
	out, n := Default.HTML(in)
	if n != 0 || !bytes.Equal(in, out) {
		t.Fatalf("n=%d out=%s", n, out)
	}
}
