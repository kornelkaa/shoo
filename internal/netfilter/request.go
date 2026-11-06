package netfilter

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Request is what the rules are checked against.
type Request struct {
	URL      string // full URL
	Host     string // lowercase, no port
	PageHost string // the page that made the request ("" if unknown)
	// ThirdParty: the request goes to a different site than the page's.
	ThirdParty bool
	Type       string // "script", "image", ... (a key of typeNames)

	typ                typeMask
	page               bool // checking a page against "@@...$document" rules
	lower              string
	hostStart, hostEnd int // the host inside lower
}

// NewRequest prepares a request for matching. URL must be absolute.
func NewRequest(rawURL, pageHost, typ string, thirdParty bool) *Request {
	q := &Request{URL: rawURL, PageHost: strings.ToLower(pageHost), ThirdParty: thirdParty, Type: typ}
	q.typ = typeNames[typ]
	if q.typ == 0 {
		q.typ, q.Type = tOther, "other"
	}
	q.lower = strings.ToLower(rawURL)
	if i := strings.Index(q.lower, "://"); i >= 0 {
		q.hostStart = i + 3
	}
	q.hostEnd = len(q.lower)
	if j := strings.IndexAny(q.lower[q.hostStart:], "/?#"); j >= 0 {
		q.hostEnd = q.hostStart + j
	}
	hostport := q.lower[q.hostStart:q.hostEnd]
	if at := strings.LastIndexByte(hostport, '@'); at >= 0 {
		q.hostStart += at + 1
		hostport = hostport[at+1:]
	}
	q.Host = hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		q.Host = h
		q.hostEnd = q.hostStart + len(h)
	}
	return q
}

// FromHTTP describes a request the proxy received for scheme://host. The
// request type comes from Sec-Fetch-Dest, the page from Referer or Origin,
// and third-party from Sec-Fetch-Site (all sent by Safari).
func FromHTTP(r *http.Request, scheme, host string) *Request {
	host = strings.ToLower(host)
	typ := requestType(r)
	page := headerHost(r.Header.Get("Referer"))
	if page == "" {
		page = headerHost(r.Header.Get("Origin"))
	}
	site := r.Header.Get("Sec-Fetch-Site")
	if typ == "document" || page == "" && (site == "same-origin" || site == "none") {
		page = host
	}
	var third bool
	switch site {
	case "cross-site":
		third = true
	case "same-site", "same-origin", "none":
	default:
		third = page != "" && siteOf(page) != siteOf(host)
	}
	return NewRequest(scheme+"://"+host+r.URL.RequestURI(), page, typ, third)
}

func requestType(r *http.Request) string {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return "websocket"
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document":
		return "document"
	case "iframe", "frame", "fencedframe":
		return "subdocument"
	case "script", "worker", "sharedworker", "serviceworker", "audioworklet", "paintworklet":
		return "script"
	case "image":
		return "image"
	case "style":
		return "stylesheet"
	case "font":
		return "font"
	case "audio", "video", "track":
		return "media"
	case "object", "embed":
		return "object"
	case "empty":
		if r.Header.Get("Ping-To") != "" || r.Header.Get("Content-Type") == "text/ping" {
			return "ping"
		}
		return "xmlhttprequest" // fetch() and XMLHttpRequest
	case "":
		// No Sec-Fetch-Dest (other apps, old browsers): guess.
		accept := r.Header.Get("Accept")
		switch {
		case strings.Contains(accept, "text/html") && r.Method == http.MethodGet:
			return "document"
		case strings.HasPrefix(accept, "image/"):
			return "image"
		case strings.HasPrefix(accept, "text/css"):
			return "stylesheet"
		case strings.HasSuffix(r.URL.Path, ".js"):
			return "script"
		}
	}
	return "other"
}

func headerHost(v string) string {
	if v == "" || v == "null" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// siteOf is the registrable domain ("bbc.co.uk" for "www.bbc.co.uk").
func siteOf(host string) string {
	if s, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return s
	}
	return host
}
