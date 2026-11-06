// Package netfilter blocks individual requests by URL, using the network
// rules of EasyList-style filter lists (EasyList, EasyPrivacy, uBlock
// Origin's lists), e.g. "||example.com/ads/*$script,third-party".
//
// Domain blocking (internal/sites) can only block whole sites. These rules
// can block one script or image on a site that is otherwise needed, and
// limit a rule to some request types or pages.
//
// Supported: "||" "|" "^" "*" patterns, /regex/ patterns, "@@" exceptions,
// and the options script, image, stylesheet (css), xmlhttprequest (xhr),
// subdocument (frame), media, font, object, ping, websocket, other, all,
// third-party (3p) / first-party (1p), domain= (from=), match-case,
// important, badfilter, and document on exceptions (a page where nothing
// is blocked). A rule with any other option (redirect=, removeparam=, csp=,
// denyallow=, ...) is skipped rather than applied half-way. Pages
// themselves (top-level documents) and popups are never blocked.
//
// This is shoo's own implementation of the filter syntax; no uBlock Origin
// code is used.
package netfilter

import (
	"regexp"
	"slices"
	"strings"
)

// typeMask is a set of request types.
type typeMask uint16

const (
	tScript typeMask = 1 << iota
	tImage
	tStylesheet
	tXHR
	tSubdocument
	tDocument
	tMedia
	tFont
	tObject
	tPing
	tWebsocket
	tOther
	tPopup

	allTypes = tPopup<<1 - 1
	// A rule without type options applies to these: not to pages or popups.
	defaultTypes = allTypes &^ (tDocument | tPopup)
)

var typeNames = map[string]typeMask{
	"script": tScript, "image": tImage, "stylesheet": tStylesheet, "css": tStylesheet,
	"xmlhttprequest": tXHR, "xhr": tXHR, "subdocument": tSubdocument, "frame": tSubdocument,
	"document": tDocument, "doc": tDocument, "media": tMedia, "font": tFont,
	"object": tObject, "ping": tPing, "beacon": tPing, "websocket": tWebsocket,
	"other": tOther, "popup": tPopup,
}

// cosmeticOptions only matter for element hiding (internal/cosmetic).
var cosmeticOptions = map[string]bool{
	"generichide": true, "ghide": true, "elemhide": true, "ehide": true,
	"specifichide": true, "shide": true,
}

type party uint8

const (
	anyParty party = iota
	firstParty
	thirdParty
)

// filter is one network rule.
type filter struct {
	raw       string
	exception bool
	important bool
	matchCase bool
	// docException: an "@@...$document" rule. Nothing is blocked on pages
	// it matches.
	docException bool
	types        typeMask
	party        party
	include      []string // $domain=: only on these pages (and subdomains)
	exclude      []string // $domain=~x: not on these pages

	re          *regexp.Regexp // /regex/ rules
	pattern     string         // the rest: literal text with '*' and '^'
	hostAnchor  bool           // "||": starts at a label of the host
	startAnchor bool           // "|": starts at the start of the URL
	endAnchor   bool           // trailing "|": ends at the end of the URL

	key string // identity for $badfilter
}

var cosmeticRe = regexp.MustCompile(`#@?[?$%]?#`)

var optionsRe = regexp.MustCompile(`^[a-zA-Z0-9~_,=|.*:-]+$`)

// parse reads one line. It returns nil for lines that aren't network rules
// and rules that use something unsupported. bad is set for $badfilter
// rules, whose key names the rule they cancel.
func parse(line string) (f *filter, bad bool) {
	if line == "" || line[0] == '!' || line[0] == '[' || cosmeticRe.MatchString(line) {
		return nil, false
	}
	f = &filter{raw: line}
	rest := line
	if strings.HasPrefix(rest, "@@") {
		f.exception = true
		rest = rest[2:]
	}

	// Options come after the last '$', unless that '$' is part of a regex.
	var opts []string
	if i := strings.LastIndexByte(rest, '$'); i >= 0 && optionsRe.MatchString(rest[i+1:]) {
		opts = strings.Split(rest[i+1:], ",")
		rest = rest[:i]
	}
	isRegex := len(rest) > 2 && rest[0] == '/' && rest[len(rest)-1] == '/'
	if !isRegex && strings.Contains(rest, "$") {
		return nil, false // options shoo can't read, like "$csp=script-src 'none'"
	}
	var posTypes, negTypes typeMask
	cosmeticOnly := len(opts) > 0
	var keyOpts []string
	for _, o := range opts {
		o = strings.ToLower(strings.TrimSpace(o))
		if o == "badfilter" {
			bad = true
			continue
		}
		keyOpts = append(keyOpts, o)
		if cosmeticOptions[o] {
			continue
		}
		cosmeticOnly = false
		neg := strings.HasPrefix(o, "~")
		name, value, _ := strings.Cut(strings.TrimPrefix(o, "~"), "=")
		if m, ok := typeNames[name]; ok && value == "" {
			if neg {
				negTypes |= m
			} else {
				posTypes |= m
			}
			continue
		}
		switch {
		case strings.Trim(name, "_") == "" && value == "":
			// "$_": a no-op used to make a rule unambiguous.
		case (name == "third-party" || name == "3p") && value == "":
			f.party = thirdParty
			if neg {
				f.party = firstParty
			}
		case (name == "first-party" || name == "1p") && value == "":
			f.party = firstParty
			if neg {
				f.party = thirdParty
			}
		case (name == "domain" || name == "from") && !neg:
			if !f.parseDomains(value) {
				return nil, false
			}
		case name == "match-case" && !neg && value == "":
			f.matchCase = true
		case name == "important" && !neg && value == "":
			f.important = true
		case name == "all" && !neg && value == "":
			posTypes |= allTypes
		default:
			return nil, false // redirect=, removeparam=, csp=, ...
		}
	}
	if cosmeticOnly {
		return nil, false // e.g. "@@||site^$generichide": for element hiding only
	}

	switch {
	case posTypes != 0:
		f.types = posTypes &^ negTypes
	default:
		f.types = defaultTypes &^ negTypes
	}
	if f.exception && f.types&tDocument != 0 {
		f.docException = true
	}
	f.types &^= tDocument | tPopup // pages and popups are never blocked
	if f.types == 0 && !f.docException {
		return nil, false
	}

	if !f.parsePattern(rest) {
		return nil, false
	}
	slices.Sort(keyOpts)
	f.key = rest + "$" + strings.Join(keyOpts, ",")
	if f.exception {
		f.key = "@@" + f.key
	}
	return f, bad
}

// parseDomains reads "a.com|~b.a.com". Entries shoo can't match (regexes,
// "google.*") are dropped, but if that would make the rule apply more
// widely than written, the rule is refused.
func (f *filter) parseDomains(value string) bool {
	hadInclude := false
	for _, d := range strings.Split(value, "|") {
		neg := strings.HasPrefix(d, "~")
		d = strings.TrimSuffix(strings.TrimPrefix(d, "~"), ".")
		if neg {
			if !plainDomain(d) {
				return false // dropping an exclusion would widen the rule
			}
			f.exclude = append(f.exclude, d)
			continue
		}
		hadInclude = true
		if plainDomain(d) {
			f.include = append(f.include, d)
		}
	}
	return !hadInclude || len(f.include) > 0
}

func plainDomain(d string) bool {
	if d == "" {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func (f *filter) parsePattern(p string) bool {
	if len(p) > 2 && p[0] == '/' && p[len(p)-1] == '/' {
		expr := p[1 : len(p)-1]
		if !f.matchCase {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr) // Go has no lookarounds: such rules are skipped
		if err != nil {
			return false
		}
		f.re = re
		return true
	}
	switch {
	case strings.HasPrefix(p, "||"):
		f.hostAnchor, p = true, p[2:]
	case strings.HasPrefix(p, "|"):
		f.startAnchor, p = true, p[1:]
	}
	if strings.HasSuffix(p, "|") {
		f.endAnchor, p = true, p[:len(p)-1]
	}
	if strings.HasPrefix(p, "*") {
		f.hostAnchor, f.startAnchor = false, false
	}
	if !f.endAnchor {
		p = strings.TrimRight(p, "*")
	}
	if !f.hostAnchor && !f.startAnchor {
		p = strings.TrimLeft(p, "*")
	}
	if !f.matchCase {
		p = strings.ToLower(p)
	}
	f.pattern = p
	// A rule that matches every URL is only accepted when limited to
	// some pages ("*$script,domain=example.com").
	if strings.Trim(p, "*^") == "" && len(f.include) == 0 && !f.docException {
		return false
	}
	return true
}
