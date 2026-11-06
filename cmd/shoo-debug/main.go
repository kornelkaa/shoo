// Command shoo-debug runs exactly like `shoo run`, using the same
// YouTube and other-site code unchanged, and also records what YouTube sends,
// to find out how ads get past the blocker.
//
// Use it temporarily in place of `shoo run` (same port), play videos until
// an ad gets through, then stop it with Ctrl+C. Results are written to
// ~/Library/Logs/shoo-debug/<time>/ and stay on this Mac.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ytblock/internal/certs"
	"ytblock/internal/proxy"
	"ytblock/internal/prune"
	"ytblock/internal/sites"
)

// adMarkers are names YouTube uses for ad instructions. Finding one of these
// in what Safari receives (after shoo's removal) means an ad can get through.
var adMarkers = []string{
	"adPlacements", "playerAds", "adSlots", "adBreakHeartbeatParams",
	"instreamVideoAdRenderer", "linearAdSequenceRenderer", "adBreakServiceRenderer",
	"playerLegacyDesktopWatchAdsRenderer", "adVideoId", "adSlotRenderer",
	"serverStitched", "ssap", "SSAP", "ssdai", "SSDAI",
	"enforcementMessageViewModel",
}

// adEventPaths are requests the player makes when an ad is actually shown.
var adEventPaths = []string{"/api/stats/ads", "/pagead/", "/ptracking", "ad_break", "get_midroll", "/api/stats/qoe?adformat"}

func main() {
	addr := flag.String("addr", "127.0.0.1:8899", "listen address (same as shoo)")
	flag.Parse()

	base, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}
	dataDir := filepath.Join(base, "shoo")
	home, _ := os.UserHomeDir()
	outDir := filepath.Join(home, "Library", "Logs", "shoo-debug", time.Now().Format("2006-01-02_15-04-05"))
	if err := os.MkdirAll(filepath.Join(outDir, "responses"), 0o700); err != nil {
		log.Fatal(err)
	}
	logFile, err := os.OpenFile(filepath.Join(outDir, "events.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	events := log.New(io.MultiWriter(os.Stderr, logFile), "", log.Ltime|log.Lmicroseconds)

	ca, err := certs.Load(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	// The YouTube proxy, exactly as shoo runs it; only its connection to
	// YouTube is wrapped so responses can be recorded.
	p := proxy.New(ca, prune.Default, events)
	p.Addr = *addr
	rec := &recorder{next: p.Upstream, rules: prune.Default, log: events, dir: filepath.Join(outDir, "responses")}
	p.Upstream = rec

	list, err := sites.Load(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	h := sites.NewHandler(p, *addr, list, events)

	var connects sync.Map // host -> *int64
	top := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && sites.IsYouTube(hostOnly(r.Host)) {
			v, _ := connects.LoadOrStore(hostOnly(r.Host), new(int64))
			n := atomic.AddInt64(v.(*int64), 1)
			events.Printf("CONNECT  %s (connection #%d through shoo)", r.Host, n)
		}
		h.ServeHTTP(w, r)
	})

	fmt.Fprintf(os.Stderr, "\nshoo-debug on %s\nRecording to %s\nPlay YouTube videos in Safari until an ad gets through, then press Ctrl+C.\n\n", *addr, outDir)
	srv := &http.Server{Addr: *addr, Handler: top, ReadHeaderTimeout: 30 * time.Second, ErrorLog: events}
	log.Fatal(srv.ListenAndServe())
}

// recorder sits between the YouTube proxy and YouTube. It logs every request
// and checks responses for ad data that shoo's removal would leave behind.
type recorder struct {
	next  http.RoundTripper
	rules prune.Rules
	log   *log.Logger
	dir   string
	n     atomic.Int64
}

func (rc *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rc.next.RoundTrip(req)
	where := req.URL.Host + req.URL.Path
	if err != nil {
		rc.log.Printf("ERROR    %s %s: %v", req.Method, where, err)
		return resp, err
	}
	n := rc.n.Add(1)
	ctype, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	enc := resp.Header.Get("Content-Encoding")
	tag := "        "
	if isAdEvent(req.URL) {
		tag = "AD-EVENT"
	}
	line := fmt.Sprintf("%s #%d %s %s%s -> %d %s", tag, n, req.Method, where, queryNames(req.URL), resp.StatusCode, ctype)
	if enc != "" {
		line += " (" + enc + ")"
	}

	isJSON := ctype == "application/json" && rc.rules.Matches(req.URL.Path)
	isHTML := ctype == "text/html"
	interesting := strings.HasPrefix(req.URL.Path, "/youtubei/") || req.URL.Path == "/watch" || strings.HasPrefix(req.URL.Path, "/shorts/")
	if resp.StatusCode != http.StatusOK || !interesting {
		rc.log.Print(line)
		return resp, nil
	}
	if enc != "" && enc != "identity" {
		rc.log.Print(line + "  [compressed, not inspected]")
		return resp, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		rc.log.Print(line + "  [read error: " + err.Error() + "]")
		return resp, nil
	}

	// What Safari will get: the same removal shoo does.
	after := body
	switch {
	case isJSON:
		after, _, _ = rc.rules.JSON(body)
	case isHTML:
		after, _ = rc.rules.HTML(body)
	}
	before, left := countMarkers(body), countMarkers(after)
	line += fmt.Sprintf("  %d KB  ad data: %s", len(body)/1024, describe(before))
	if isJSON || isHTML {
		line += "  after shoo: " + describe(left)
	} else {
		line += "  [NOT EDITED by shoo: " + ctype + "]"
	}
	if info := playerInfo(after); info != "" {
		line += "  " + info
	}

	save := len(left) > 0 || (!isJSON && !isHTML && strings.HasPrefix(req.URL.Path, "/youtubei/"))
	if save {
		name := fmt.Sprintf("%04d_%s.%s", n, strings.Trim(strings.ReplaceAll(req.URL.Path, "/", "_"), "_"), ext(ctype))
		if err := os.WriteFile(filepath.Join(rc.dir, name), after, 0o600); err == nil {
			line += "  saved: responses/" + name
		}
		line = strings.Replace(line, "        ", "LEAK?   ", 1)
	}
	rc.log.Print(line)
	return resp, nil
}

func countMarkers(b []byte) map[string]int {
	m := map[string]int{}
	for _, k := range adMarkers {
		if c := bytes.Count(b, []byte(`"`+k+`"`)); c > 0 {
			m[k] = c
		}
	}
	return m
}

func describe(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s×%d", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// playerInfo pulls a few facts out of a player response: which video, and
// whether it streams with SABR (where YouTube can stitch ads into the video).
func playerInfo(b []byte) string {
	var parts []string
	if i := bytes.Index(b, []byte(`"videoDetails":{"videoId":"`)); i >= 0 {
		rest := b[i+len(`"videoDetails":{"videoId":"`):]
		if j := bytes.IndexByte(rest, '"'); j > 0 && j < 20 {
			parts = append(parts, "video="+string(rest[:j]))
		}
	}
	if bytes.Contains(b, []byte(`"serverAbrStreamingUrl"`)) {
		parts = append(parts, "SABR=yes")
	}
	return strings.Join(parts, " ")
}

func isAdEvent(u *url.URL) bool {
	s := u.Path + "?" + u.RawQuery
	for _, p := range adEventPaths {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// queryNames lists query parameter names only, never their values.
func queryNames(u *url.URL) string {
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	var names []string
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	return "?" + strings.Join(names, "&")
}

func ext(ctype string) string {
	switch ctype {
	case "application/json":
		return "json"
	case "text/html":
		return "html"
	}
	return "bin"
}

func hostOnly(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		return hostport[:i]
	}
	return hostport
}
