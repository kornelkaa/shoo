// Package cosmetic hides ad elements (and the empty boxes they leave) on web
// pages, using the element-hiding rules of EasyList-style filter lists
// ("example.com##.ad-banner"). The rules become CSS that the proxy links into
// every page it decrypts.
package cosmetic

import (
	"io"
	"regexp"
	"sort"
	"strings"

	"shoo/internal/filterlist"
)

// rule is one element-hiding rule.
type rule struct {
	sel     string
	include []string // domains it applies to (empty: every site)
	exclude []string // domains it doesn't apply to ("~example.com")
}

// Rules is a parsed set of element-hiding rules.
type Rules struct {
	generic    []string            // on every site, no exceptions anywhere
	scoped     []rule              // every site except some, or excepted somewhere
	byDomain   map[string][]rule   // site-specific rules, by each included domain
	exceptions map[string][]string // domain -> selectors not to hide there ("#@#")
	noGeneric  map[string]bool     // $generichide / $elemhide: no generic rules there
	noCosmetic map[string]bool     // $elemhide / $document: no rules at all there
	count      int
}

// Len is the number of hiding rules.
func (r *Rules) Len() int { return r.count }

// genericHideRe matches "@@||site^$generichide" exceptions. The site may be
// an entity ("www.google.*") and may be followed by a path
// ("@@||www.google.*/search?$generichide"). shoo decides per site, not per
// page, so an exception for some pages applies to the whole site: that only
// hides less there.
var genericHideRe = regexp.MustCompile(`^@@\|\|([a-z0-9-]+(?:\.[a-z0-9-]+)*(?:\.\*)?)(?:[\^/][^$]*)?\$(.*)$`)

// Parse reads EasyList-style lists. Only plain CSS element hiding is used;
// network rules, scriptlets and extended/procedural selectors are skipped.
func Parse(r io.Reader) (*Rules, error) {
	type pending struct {
		sel              string
		include, exclude []string
	}
	var all []pending
	exceptions := map[string][]string{} // "" = everywhere
	noGeneric, noCosmetic := map[string]bool{}, map[string]bool{}

	var lines []string
	if err := filterlist.Scan(r, func(l string) { lines = append(lines, l) }); err != nil {
		return nil, err
	}
	for _, line := range lines {
		if m := genericHideRe.FindStringSubmatch(strings.ToLower(line)); m != nil {
			for _, opt := range strings.Split(m[2], ",") {
				switch opt {
				case "generichide", "ghide":
					noGeneric[m[1]] = true
				case "elemhide", "ehide", "document", "doc":
					noCosmetic[m[1]] = true
				}
			}
			continue
		}
		domains, sel, isException, ok := splitRule(line)
		if !ok || !validSelector(sel) {
			continue
		}
		inc, exc := parseDomains(domains)
		if isException {
			if len(inc) == 0 {
				exceptions[""] = append(exceptions[""], sel)
			}
			for _, d := range inc {
				exceptions[d] = append(exceptions[d], sel)
			}
			continue
		}
		all = append(all, pending{sel, inc, exc})
	}

	everywhereExc := map[string]bool{}
	for _, s := range exceptions[""] {
		everywhereExc[s] = true
	}
	delete(exceptions, "")
	exceptedSomewhere := map[string]bool{}
	for _, sels := range exceptions {
		for _, s := range sels {
			exceptedSomewhere[s] = true
		}
	}

	out := &Rules{byDomain: map[string][]rule{}, exceptions: exceptions, noGeneric: noGeneric, noCosmetic: noCosmetic}
	seenGeneric := map[string]bool{}
	for _, p := range all {
		if everywhereExc[p.sel] {
			continue
		}
		out.count++
		switch {
		case len(p.include) == 0 && len(p.exclude) == 0 && !exceptedSomewhere[p.sel]:
			if !seenGeneric[p.sel] {
				seenGeneric[p.sel] = true
				out.generic = append(out.generic, p.sel)
			}
		case len(p.include) == 0:
			out.scoped = append(out.scoped, rule{sel: p.sel, exclude: p.exclude})
		default:
			ru := rule{sel: p.sel, include: p.include, exclude: p.exclude}
			for _, d := range p.include {
				out.byDomain[d] = append(out.byDomain[d], ru)
			}
		}
	}
	return out, nil
}

// splitRule splits "domains##selector" / "domains#@#selector".
func splitRule(line string) (domains, sel string, exception, ok bool) {
	if i := strings.Index(line, "#@#"); i >= 0 {
		return line[:i], strings.TrimSpace(line[i+3:]), true, true
	}
	i := strings.Index(line, "##")
	if i < 0 {
		return "", "", false, false
	}
	sel = strings.TrimSpace(line[i+2:])
	// "##+js(...)" scriptlets and "##^" HTML filters aren't CSS.
	if strings.HasPrefix(sel, "+js(") || strings.HasPrefix(sel, "^") {
		return "", "", false, false
	}
	// Other markers (#?#, #$#, #%#) contain "#" before the second "#".
	if i > 0 && strings.ContainsAny(line[:i], "#$%?@") {
		return "", "", false, false
	}
	return line[:i], sel, false, true
}

func parseDomains(s string) (include, exclude []string) {
	for _, d := range strings.Split(strings.ToLower(s), ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		neg := strings.HasPrefix(d, "~")
		d = strings.TrimPrefix(d, "~")
		if strings.ContainsAny(strings.TrimSuffix(d, ".*"), "/*|") {
			continue // regex domains aren't supported; entities ("google.*") are
		}
		if neg {
			exclude = append(exclude, d)
		} else {
			include = append(include, d)
		}
	}
	return include, exclude
}

// Pseudo-classes Safari understands. Selectors using anything else
// (procedural filters like :has-text, :-abp-contains, :upward, :style) are
// skipped, because one unknown selector would invalidate its whole CSS rule.
var knownPseudo = map[string]bool{
	"not": true, "is": true, "where": true, "has": true,
	"nth-child": true, "nth-last-child": true, "nth-of-type": true, "nth-last-of-type": true,
	"first-child": true, "last-child": true, "only-child": true,
	"first-of-type": true, "last-of-type": true, "only-of-type": true,
	"empty": true, "root": true, "link": true, "visited": true, "checked": true,
	"disabled": true, "enabled": true, "target": true, "lang": true,
}

var pseudoRe = regexp.MustCompile(`:([a-zA-Z-]+)`)

// validSelector rejects selectors that aren't plain CSS or could break out
// of the generated stylesheet. '@', ';' and "/*" are allowed only inside
// quoted attribute values (e.g. [href^="mailto:"], [title="a;b"]).
func validSelector(sel string) bool {
	if sel == "" || len(sel) > 1000 || strings.ContainsAny(sel, "{}\\\n\r") || strings.Contains(sel, "</") || strings.Contains(sel, "::") {
		return false
	}
	// Balanced brackets and quotes; pseudo-classes outside quotes only.
	depthRound, depthSquare := 0, 0
	var quote byte
	var outside strings.Builder
	for i := 0; i < len(sel); i++ {
		c := sel[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
			continue
		case '@', ';':
			// "@import url(...);" would load a stylesheet from anywhere.
			return false
		case '/':
			if i+1 < len(sel) && sel[i+1] == '*' {
				return false // a comment could swallow the rules after it
			}
		case '(':
			depthRound++
		case ')':
			depthRound--
		case '[':
			depthSquare++
		case ']':
			depthSquare--
		}
		if depthRound < 0 || depthSquare < 0 {
			return false
		}
		if depthSquare == 0 {
			outside.WriteByte(c)
		}
	}
	if quote != 0 || depthRound != 0 || depthSquare != 0 {
		return false
	}
	for _, m := range pseudoRe.FindAllStringSubmatch(outside.String(), -1) {
		if !knownPseudo[strings.ToLower(m[1])] {
			return false
		}
	}
	return true
}

// suffixes returns host and its parent domains, plus each of them with its
// ending replaced by "*" so entity rules match ("www.google.*" matches
// www.google.com and www.google.co.uk):
// a.b.c -> a.b.c, b.c, c, a.b.*, a.*, b.*.
func suffixes(host string) []string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var out, entities []string
	for h := host; h != ""; {
		out = append(out, h)
		for j := len(h) - 1; j > 0; j-- {
			if h[j] == '.' {
				entities = append(entities, h[:j]+".*")
			}
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return append(out, entities...)
}

func matchesAny(host string, domains []string) bool {
	for _, s := range suffixes(host) {
		for _, d := range domains {
			if s == d {
				return true
			}
		}
	}
	return false
}

// GenericOn reports whether the shared generic stylesheet applies on host.
func (r *Rules) GenericOn(host string) bool {
	for _, s := range suffixes(host) {
		if r.noGeneric[s] || r.noCosmetic[s] {
			return false
		}
	}
	return len(r.generic) > 0
}

// SiteSelectors returns the selectors for host that aren't in the generic
// stylesheet: site-specific rules and generic rules with exceptions.
func (r *Rules) SiteSelectors(host string) []string {
	sfx := suffixes(host)
	excepted := map[string]bool{}
	noGeneric := false
	for _, s := range sfx {
		if r.noCosmetic[s] {
			return nil
		}
		noGeneric = noGeneric || r.noGeneric[s]
		for _, sel := range r.exceptions[s] {
			excepted[sel] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	add := func(ru rule) {
		if excepted[ru.sel] || seen[ru.sel] || matchesAny(host, ru.exclude) {
			return
		}
		seen[ru.sel] = true
		out = append(out, ru.sel)
	}
	for _, s := range sfx {
		for _, ru := range r.byDomain[s] {
			add(ru)
		}
	}
	if !noGeneric {
		for _, ru := range r.scoped {
			add(ru)
		}
	}
	sort.Strings(out)
	return out
}

// CSS turns selectors into rules that hide matching elements. Selectors are
// grouped to keep the stylesheet small (Safari still indexes each one).
func CSS(selectors []string) []byte {
	const group = 40
	var b strings.Builder
	for i := 0; i < len(selectors); i += group {
		end := min(i+group, len(selectors))
		b.WriteString(strings.Join(selectors[i:end], ",\n"))
		b.WriteString("{display:none!important}\n")
	}
	return []byte(b.String())
}
