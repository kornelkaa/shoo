package netfilter

import "strings"

// isSep reports whether c is a separator for '^': anything but a letter,
// digit, or one of "_-.%".
func isSep(c byte) bool {
	return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '-' || c == '.' || c == '%')
}

// matchHere reports whether pattern p matches s from its start: a prefix
// of s, or all of s when end is set. '*' matches any run of characters,
// '^' a separator or the end of s.
func matchHere(p, s string, end bool) bool {
	pi, si := 0, 0
	starP, starS := -1, 0
	for {
		if pi == len(p) {
			if !end || si == len(s) {
				return true
			}
		} else {
			switch c := p[pi]; {
			case c == '*':
				starP, starS = pi, si
				pi++
				continue
			case c == '^' && si == len(s):
				pi++
				continue
			case c == '^' && isSep(s[si]):
				pi++
				si++
				continue
			case c != '^' && si < len(s) && s[si] == c:
				pi++
				si++
				continue
			}
		}
		// Mismatch: let the last '*' take one more character.
		if starP < 0 || starS >= len(s) {
			return false
		}
		starS++
		si, pi = starS, starP+1
	}
}

// matchURL reports whether f's pattern matches the request.
func (f *filter) matchURL(q *Request) bool {
	url := q.lower
	if f.matchCase {
		url = q.URL
	}
	if f.re != nil {
		return f.re.MatchString(url)
	}
	p := f.pattern
	switch {
	case f.hostAnchor:
		// Start at the host or after any '.' in it.
		for i := q.hostStart; i < q.hostEnd; i++ {
			if (i == q.hostStart || url[i-1] == '.') && matchHere(p, url[i:], f.endAnchor) {
				return true
			}
		}
		return false
	case f.startAnchor:
		return matchHere(p, url, f.endAnchor)
	}
	// Anywhere in the URL. Jump between places where the leading literal
	// text occurs instead of trying every position.
	lit := p
	if i := strings.IndexAny(p, "*^"); i >= 0 {
		lit = p[:i]
	}
	if lit == p && !f.endAnchor {
		return strings.Contains(url, p)
	}
	for i := 0; i <= len(url); {
		if lit != "" {
			j := strings.Index(url[i:], lit)
			if j < 0 {
				return false
			}
			i += j
		}
		if matchHere(p, url[i:], f.endAnchor) {
			return true
		}
		i++
	}
	return false
}

// matchOptions checks the request type, party and page.
func (f *filter) matchOptions(q *Request) bool {
	if q.page {
		if !f.docException {
			return false
		}
	} else if f.types&q.typ == 0 {
		return false
	}
	switch f.party {
	case firstParty:
		if q.ThirdParty {
			return false
		}
	case thirdParty:
		if !q.ThirdParty {
			return false
		}
	}
	if len(f.include) > 0 && !onDomains(q.PageHost, f.include) {
		return false
	}
	return len(f.exclude) == 0 || !onDomains(q.PageHost, f.exclude)
}

// onDomains reports whether host is one of domains or a subdomain of one.
func onDomains(host string, domains []string) bool {
	if host == "" {
		return false
	}
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, d) && host[len(host)-len(d)-1] == '.' {
			return true
		}
	}
	return false
}
