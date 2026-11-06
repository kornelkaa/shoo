package cosmetic

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shoo/internal/certs"
)

// AssetHost is the name the proxy answers for itself to serve the hiding
// stylesheets. ".internal" is reserved for private use, so no real website
// can ever have this name.
const AssetHost = "assets.shoo.internal"

const assetOrigin = "https://" + AssetHost

// Engine links hiding stylesheets into pages and serves them.
type Engine struct {
	rules   atomic.Pointer[Rules]
	version atomic.Int64
	generic atomic.Pointer[[]byte]
	sites   sync.Map // host -> []byte (CSS for that site)
	nsites  atomic.Int64
}

// maxSites caps the per-site stylesheet cache. Any page can ask for
// s.css?h=<anything>, so without a cap it could grow without end.
const maxSites = 4096

// NewEngine returns an engine using rules (may be nil: no hiding).
func NewEngine(r *Rules) *Engine {
	e := &Engine{}
	e.SetRules(r)
	return e
}

// SetRules swaps in new rules.
func (e *Engine) SetRules(r *Rules) {
	if r == nil {
		r = &Rules{}
	}
	g := CSS(r.generic)
	e.rules.Store(r)
	e.generic.Store(&g)
	e.sites.Clear()
	e.nsites.Store(0)
	e.version.Store(time.Now().UnixNano())
}

// Rules returns the rules in use.
func (e *Engine) Rules() *Rules { return e.rules.Load() }

func (e *Engine) siteCSS(host string) []byte {
	if v, ok := e.sites.Load(host); ok {
		return v.([]byte)
	}
	css := CSS(e.rules.Load().SiteSelectors(host))
	if e.nsites.Add(1) > maxSites {
		e.sites.Clear()
		e.nsites.Store(1)
	}
	e.sites.Store(host, css)
	return css
}

// links returns the <link> tags for a page on host ("" if nothing to hide).
func (e *Engine) links(host string) string {
	v := strconv.FormatInt(e.version.Load(), 36)
	var b strings.Builder
	if e.rules.Load().GenericOn(host) {
		fmt.Fprintf(&b, `<link rel="stylesheet" href="%s/g.css?v=%s">`, assetOrigin, v)
	}
	if len(e.siteCSS(host)) > 0 {
		fmt.Fprintf(&b, `<link rel="stylesheet" href="%s/s.css?h=%s&amp;v=%s">`, assetOrigin, host, v)
	}
	return b.String()
}

// ServeAsset answers requests for AssetHost.
func (e *Engine) ServeAsset(w http.ResponseWriter, r *http.Request) {
	var css []byte
	switch r.URL.Path {
	case "/g.css":
		css = *e.generic.Load()
	case "/s.css":
		h := strings.ToLower(r.URL.Query().Get("h"))
		if !certs.ValidHost(h) {
			http.NotFound(w, r)
			return
		}
		css = e.siteCSS(h)
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	// The URL changes when the rules do, so browsers may keep it.
	w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
	w.Write(css)
}

// Inject links the hiding stylesheets into an HTML page from host. The body
// must not be compressed. It streams: only the start of the page is held
// back until <head> is found.
func (e *Engine) Inject(host string, resp *http.Response) {
	tags := e.links(strings.ToLower(host))
	if tags == "" {
		return
	}
	for _, key := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		vals := resp.Header.Values(key)
		for i, v := range vals {
			vals[i] = PatchCSP(v)
		}
	}
	resp.Body = &injectReader{src: resp.Body, tags: []byte(tags)}
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
}

// PatchCSP allows stylesheets from AssetHost in a Content-Security-Policy
// header value. Everything else in the policy stays as it was.
func PatchCSP(policy string) string {
	var out []string
	for _, p := range strings.Split(policy, ",") { // several policies
		out = append(out, patchOnePolicy(p))
	}
	return strings.Join(out, ",")
}

func patchOnePolicy(policy string) string {
	dirs := strings.Split(policy, ";")
	find := func(name string) int {
		for i, d := range dirs {
			f := strings.Fields(d)
			if len(f) > 0 && strings.EqualFold(f[0], name) {
				return i
			}
		}
		return -1
	}
	allow := func(i int) {
		var keep []string
		for _, f := range strings.Fields(dirs[i]) {
			if f != "'none'" {
				keep = append(keep, f)
			}
		}
		dirs[i] = " " + strings.Join(append(keep, assetOrigin), " ")
	}
	elem, style, def := find("style-src-elem"), find("style-src"), find("default-src")
	switch {
	case elem >= 0 || style >= 0:
		if elem >= 0 {
			allow(elem)
		}
		if style >= 0 {
			allow(style)
		}
	case def >= 0:
		// style-src falls back to default-src: add a style-src with the same
		// sources plus ours.
		f := strings.Fields(dirs[def])
		dirs = append(dirs, " style-src "+strings.Join(f[1:], " "))
		allow(len(dirs) - 1)
	default:
		return policy // stylesheets aren't restricted
	}
	return strings.Join(dirs, ";")
}

var (
	headRe = regexp.MustCompile(`(?i)<head(?:\s[^>]*)?>`)
	htmlRe = regexp.MustCompile(`(?i)<html(?:\s[^>]*)?>`)
	docRe  = regexp.MustCompile(`(?i)^\s*<!doctype[^>]*>`)
)

const maxHold = 256 << 10 // look this far for <head> before giving up

type injectReader struct {
	src  io.ReadCloser
	tags []byte
	out  io.Reader
}

func (r *injectReader) Read(p []byte) (int, error) {
	if r.out == nil {
		r.prepare()
	}
	return r.out.Read(p)
}

func (r *injectReader) Close() error { return r.src.Close() }

// prepare reads the start of the page and inserts the tags.
func (r *injectReader) prepare() {
	var held bytes.Buffer
	buf := make([]byte, 32<<10)
	var readErr error
	for held.Len() < maxHold {
		n, err := r.src.Read(buf)
		held.Write(buf[:n])
		if loc := headRe.FindIndex(held.Bytes()); loc != nil {
			r.out = io.MultiReader(bytes.NewReader(insertAt(held.Bytes(), loc[1], r.tags)), r.src)
			return
		}
		if err != nil {
			readErr = err
			break
		}
	}
	page := held.Bytes()
	at := 0
	if loc := htmlRe.FindIndex(page); loc != nil {
		at = loc[1]
	} else if loc := docRe.FindIndex(page); loc != nil {
		at = loc[1]
	}
	out := insertAt(page, at, r.tags)
	if readErr != nil {
		r.out = io.MultiReader(bytes.NewReader(out), errReader{readErr})
		return
	}
	r.out = io.MultiReader(bytes.NewReader(out), r.src)
}

func insertAt(b []byte, at int, tags []byte) []byte {
	out := make([]byte, 0, len(b)+len(tags))
	out = append(out, b[:at]...)
	out = append(out, tags...)
	return append(out, b[at:]...)
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
