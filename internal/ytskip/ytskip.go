// Package ytskip is a backup for YouTube ads that get past the ad removal.
//
// It adds a small script to YouTube pages. The script does nothing until the
// player actually shows an ad (the player gets the "ad-showing" class); then
// it mutes the ad, jumps to its end and presses Skip if there is one, and
// restores the sound afterwards. Ads removed by the YouTube code never start,
// so the script never acts on them.
//
// It sits next to the YouTube code (as a wrapper around proxy.Proxy.Upstream)
// and does not change it. Pages are already read in full by the proxy, so
// this adds no delay.
package ytskip

import (
	"shoo/internal/certs"

	"bytes"
	"io"
	"log"
	"mime"
	"net/http"
	"regexp"
	"strconv"
)

// Script runs in YouTube pages. It must not set HTML (YouTube enforces
// Trusted Types) and only reacts to an ad that is playing.
const Script = `(function () {
  if (window.__shooSkip) return;
  window.__shooSkip = true;
  var SKIP = '.ytp-skip-ad-button, .ytp-ad-skip-button, .ytp-ad-skip-button-modern';
  var CLOSE = '.ytp-ad-overlay-close-button';
  var inAd = false, wasMuted = false, video = null;
  function tick() {
    var player = document.querySelector('#movie_player.ad-showing, #movie_player.ad-interrupting');
    if (player) {
      var v = player.querySelector('video');
      if (!v) return;
      if (!inAd) { inAd = true; video = v; wasMuted = v.muted; }
      v.muted = true;
      if (isFinite(v.duration) && v.duration > 0 && v.currentTime < v.duration - 0.1) {
        v.currentTime = v.duration - 0.05;
      }
      var b = player.querySelector(SKIP);
      if (b) b.click();
    } else if (inAd) {
      inAd = false;
      if (video) video.muted = wasMuted;
      video = null;
    }
    var c = document.querySelector(CLOSE);
    if (c) c.click();
  }
  setInterval(tick, 250);
})();`

// maxPage is the largest page edited; bigger ones pass through unchanged.
const maxPage = 32 << 20

// Transport adds Script to YouTube HTML pages and passes everything else to
// Next unchanged.
type Transport struct {
	Next http.RoundTripper
	Log  *log.Logger
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !certs.Allowed(req.URL.Hostname()) {
		return t.Next.RoundTrip(req) // the proxy carries every site; only YouTube gets the script
	}
	resp, err := t.Next.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/html" {
		return resp, nil
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return resp, nil // the proxy only asks for plain pages; leave anything else alone
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPage+1))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) <= maxPage {
		body = Inject(body)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return resp, nil
}

var nonceRe = regexp.MustCompile(`<script[^>]*\snonce="([A-Za-z0-9+/=_-]+)"`)

// Inject puts Script right after <head>, with the nonce YouTube's own
// scripts use (its security policy only runs scripts carrying it). Pages
// without <head> or a nonce are returned unchanged.
func Inject(page []byte) []byte {
	m := nonceRe.FindSubmatch(page)
	i := bytes.Index(page, []byte("<head>"))
	if m == nil || i < 0 {
		return page
	}
	i += len("<head>")
	tag := []byte(`<script nonce="` + string(m[1]) + `">` + Script + `</script>`)
	out := make([]byte, 0, len(page)+len(tag))
	out = append(out, page[:i]...)
	out = append(out, tag...)
	return append(out, page[i:]...)
}
