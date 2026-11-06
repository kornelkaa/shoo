package ytextra

// Removes ad tiles from YouTube's home feed, search results and the
// next-videos sidebar. It sits between the YouTube proxy and YouTube (the
// proxy's Upstream), so the original YouTube code stays unchanged.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// adItemKeys mark a feed item, sidebar entry or command as an ad.
var adItemKeys = map[string]bool{
	"adSlotRenderer":                           true,
	"inFeedAdLayoutRenderer":                   true,
	"promotedSparklesWebRenderer":              true,
	"promotedVideoRenderer":                    true,
	"compactPromotedVideoRenderer":             true,
	"displayAdRenderer":                        true,
	"searchPyvRenderer":                        true,
	"statementBannerRenderer":                  true,
	"bannerPromoRenderer":                      true,
	"brandVideoShelfRenderer":                  true,
	"brandVideoSingletonRenderer":              true,
	"adsControlFlowOpportunityReceivedCommand": true,
}

// feedPaths are the responses that contain feeds.
var feedPaths = []string{"/youtubei/v1/browse", "/youtubei/v1/search", "/youtubei/v1/next", "/youtubei/v1/get_watch", "/youtubei/v1/guide"}

// feedHTMLVar holds the first page of the feed inside YouTube's HTML pages.
const feedHTMLVar = "ytInitialData"

// FeedCleaner wraps the YouTube proxy's connection to YouTube.
type FeedCleaner struct {
	Next http.RoundTripper
	Log  *log.Logger
}

func (f *FeedCleaner) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := f.Next.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return resp, nil // compressed: not a response the YouTube proxy edits either
	}
	ctype, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	isJSON := ctype == "application/json" && matchesAny(req.URL.Path, feedPaths)
	isHTML := ctype == "text/html"
	if !isJSON && !isHTML {
		return resp, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var out []byte
	var n int
	if isJSON {
		out, n = cleanJSON(body, false)
	} else {
		out, n = cleanHTML(body)
	}
	if n > 0 && f.Log != nil {
		f.Log.Printf("%s: removed %d ad tiles", req.URL.Path, n)
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return resp, nil
}

func matchesAny(path string, list []string) bool {
	for _, p := range list {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// cleanJSON removes ad items. Unchanged or unreadable input is returned as is.
func cleanJSON(body []byte, escapeHTML bool) ([]byte, int) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return body, 0
	}
	doc, n := removeAds(doc)
	if n == 0 {
		return body, 0
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(doc); err != nil {
		return body, 0
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), n
}

// removeAds drops list entries that are ads, and object fields whose value
// is an ad (e.g. the home page banner).
func removeAds(v any) (any, int) {
	n := 0
	switch t := v.(type) {
	case []any:
		kept := t[:0]
		for _, item := range t {
			if isAd(item, 0) {
				n++
				continue
			}
			item, c := removeAds(item)
			n += c
			kept = append(kept, item)
		}
		return kept, n
	case map[string]any:
		for k, child := range t {
			// Only fields that are an ad themselves, or the home page banner
			// slot holding an ad directly. Never a wrapper with other content.
			if adItemKeys[k] || (k == "masthead" && isAd(child, 3)) {
				delete(t, k)
				n++
				continue
			}
			var c int
			t[k], c = removeAds(child)
			n += c
		}
	}
	return v, n
}

// isAd reports whether v is an ad item: an object holding an ad key directly,
// or through a few wrapper levels like richItemRenderer → content → adSlotRenderer.
// Lists are not searched, so a shelf holding one ad among videos is not an ad.
func isAd(v any, depth int) bool {
	m, ok := v.(map[string]any)
	if !ok || depth > 3 {
		return false
	}
	for k, child := range m {
		if adItemKeys[k] {
			return true
		}
		if isWrapperKey(k) && isAd(child, depth+1) {
			return true
		}
	}
	return false
}

func isWrapperKey(k string) bool {
	return k == "content" || strings.HasSuffix(k, "Renderer")
}

// cleanHTML cleans the feed JSON assigned to ytInitialData in a page.
func cleanHTML(page []byte) ([]byte, int) {
	var out bytes.Buffer
	total := 0
	rest := page
	for {
		i := bytes.Index(rest, []byte(feedHTMLVar))
		if i < 0 {
			out.Write(rest)
			break
		}
		after := i + len(feedHTMLVar)
		start := assignmentStart(rest, after)
		if start < 0 {
			out.Write(rest[:after])
			rest = rest[after:]
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(rest[start:]))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			out.Write(rest[:start])
			rest = rest[start:]
			continue
		}
		end := start + int(dec.InputOffset())
		out.Write(rest[:start])
		// Escape <, > and & so the JSON can't end the <script> tag.
		cleaned, n := cleanJSON(rest[start:end], true)
		out.Write(cleaned)
		total += n
		rest = rest[end:]
	}
	if total == 0 {
		return page, 0
	}
	return out.Bytes(), total
}

// assignmentStart checks for ` = {` (optionally after `"]`, as in
// window["ytInitialData"] = {) and returns the index of `{`, or -1.
func assignmentStart(b []byte, p int) int {
	if p < len(b) && (b[p] == '"' || b[p] == '\'') {
		p++
	}
	if p < len(b) && b[p] == ']' {
		p++
	}
	for p < len(b) && (b[p] == ' ' || b[p] == '\t' || b[p] == '\n' || b[p] == '\r') {
		p++
	}
	if p >= len(b) || b[p] != '=' || (p+1 < len(b) && b[p+1] == '=') {
		return -1
	}
	p++
	for p < len(b) && (b[p] == ' ' || b[p] == '\t' || b[p] == '\n' || b[p] == '\r') {
		p++
	}
	if p >= len(b) || b[p] != '{' {
		return -1
	}
	return p
}
