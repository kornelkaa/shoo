package netfilter

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"shoo/internal/filterlist"
)

// index finds the rules that could match a URL without trying them all:
// "||host^" rules are looked up by host, others by one word ("token") of
// their pattern that every matching URL must contain.
type index struct {
	byHost  map[string][]*filter
	byToken map[string][]*filter
	rest    []*filter // no usable token (regexes, very short patterns)
}

func newIndex() *index {
	return &index{byHost: map[string][]*filter{}, byToken: map[string][]*filter{}}
}

// Common words that would make huge buckets.
var stopTokens = map[string]bool{
	"http": true, "https": true, "www": true, "com": true, "net": true, "org": true,
	"js": true, "html": true, "php": true, "jpg": true, "png": true, "gif": true,
}

func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '%'
}

func (ix *index) add(f *filter) {
	if f.re == nil && f.hostAnchor && !f.endAnchor {
		if h, ok := strings.CutSuffix(f.pattern, "^"); ok && plainDomain(h) && strings.Contains(h, ".") {
			ix.byHost[h] = append(ix.byHost[h], f)
			return
		}
	}
	if tok := bestToken(f); tok != "" {
		ix.byToken[tok] = append(ix.byToken[tok], f)
		return
	}
	ix.rest = append(ix.rest, f)
}

// bestToken is the longest word of f's pattern that a matching URL must
// contain whole: not next to a '*', and not at an unanchored end (where
// the URL's word could be longer).
func bestToken(f *filter) string {
	if f.re != nil {
		return ""
	}
	p := strings.ToLower(f.pattern)
	best := ""
	for i := 0; i < len(p); {
		if !isTokenChar(p[i]) {
			i++
			continue
		}
		j := i
		for j < len(p) && isTokenChar(p[j]) {
			j++
		}
		leftOK := i > 0 && p[i-1] != '*' || i == 0 && (f.hostAnchor || f.startAnchor)
		rightOK := j < len(p) && p[j] != '*' || j == len(p) && f.endAnchor
		if tok := p[i:j]; leftOK && rightOK && len(tok) > len(best) && !stopTokens[tok] {
			best = tok
		}
		i = j
	}
	return best
}

// find returns the first rule in ix that matches q.
func (ix *index) find(q *Request) *filter {
	check := func(fs []*filter, urlChecked bool) *filter {
		for _, f := range fs {
			if f.matchOptions(q) && (urlChecked || f.matchURL(q)) {
				return f
			}
		}
		return nil
	}
	// "||example.com^" matches example.com and its subdomains.
	for h := q.Host; h != ""; {
		if f := check(ix.byHost[h], true); f != nil {
			return f
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	var seen []string
	s := q.lower
	for i := 0; i < len(s); {
		if !isTokenChar(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isTokenChar(s[j]) {
			j++
		}
		tok := s[i:j]
		i = j
		if fs := ix.byToken[tok]; fs != nil && !containsStr(seen, tok) {
			seen = append(seen, tok)
			if f := check(fs, false); f != nil {
				return f
			}
		}
	}
	return check(ix.rest, false)
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Rules is a parsed set of network rules.
type Rules struct {
	block, important, allow, docAllow *index
	n                                 int
}

// Len is the number of rules in use.
func (r *Rules) Len() int {
	if r == nil {
		return 0
	}
	return r.n
}

// Parse reads filter lists. Element-hiding rules and unsupported network
// rules are skipped.
func Parse(rd io.Reader) (*Rules, error) {
	var all []*filter
	cancelled := map[string]bool{}
	err := filterlist.Scan(rd, func(line string) {
		f, bad := parse(line)
		switch {
		case f == nil:
		case bad:
			cancelled[f.key] = true
		default:
			all = append(all, f)
		}
	})
	if err != nil {
		return nil, err
	}
	r := &Rules{block: newIndex(), important: newIndex(), allow: newIndex(), docAllow: newIndex()}
	seen := map[string]bool{}
	for _, f := range all {
		if cancelled[f.key] || seen[f.key] {
			continue
		}
		seen[f.key] = true
		r.n++
		switch {
		case f.docException:
			r.docAllow.add(f)
			if f.types != 0 {
				r.allow.add(f)
			}
		case f.exception:
			r.allow.add(f)
		case f.important:
			r.important.add(f)
		default:
			r.block.add(f)
		}
	}
	return r, nil
}

// Match returns the rule that blocks q, or "" if q may load.
func (r *Rules) Match(q *Request) string {
	if r == nil || q.typ&defaultTypes == 0 {
		return "" // pages themselves are never blocked
	}
	if q.PageHost != "" && pageAllowed(r.docAllow, q.PageHost) {
		return ""
	}
	if f := r.important.find(q); f != nil {
		return f.raw
	}
	f := r.block.find(q)
	if f == nil || r.allow.find(q) != nil {
		return ""
	}
	return f.raw
}

// pageAllowed reports whether an "@@...$document" rule covers the page.
func pageAllowed(ix *index, page string) bool {
	q := NewRequest("https://"+page+"/", page, "document", false)
	q.page = true
	return ix.find(q) != nil
}

// Engine holds the rules in use; they can be swapped while it runs.
type Engine struct{ rules atomic.Pointer[Rules] }

// NewEngine returns an engine using r (may be nil: nothing blocked).
func NewEngine(r *Rules) *Engine {
	e := &Engine{}
	e.SetRules(r)
	return e
}

// SetRules swaps in new rules.
func (e *Engine) SetRules(r *Rules) {
	if r == nil {
		r = &Rules{block: newIndex(), important: newIndex(), allow: newIndex(), docAllow: newIndex()}
	}
	e.rules.Store(r)
}

// Rules returns the rules in use.
func (e *Engine) Rules() *Rules { return e.rules.Load() }

// Match returns the rule that blocks q, or "".
func (e *Engine) Match(q *Request) string { return e.rules.Load().Match(q) }

// Load parses the filter lists saved in dir (file name: listFile). A
// missing file means no rules.
func Load(dir, listFile string) (*Rules, error) {
	f, err := os.Open(filepath.Join(dir, listFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}
