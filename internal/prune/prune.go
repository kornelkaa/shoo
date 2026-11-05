// Package prune removes ad-related fields from YouTube JSON responses.
package prune

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Rules says which responses to edit and which keys to delete from them.
// Later this will be loaded from a signed rules file so it can be updated
// without reinstalling.
type Rules struct {
	// Paths are URL paths whose JSON responses get pruned.
	Paths []string `json:"paths"`
	// Keys are deleted wherever they appear in the JSON tree.
	Keys []string `json:"keys"`
	// HTMLVars are JavaScript variables in YouTube pages that hold JSON,
	// e.g. `var ytInitialPlayerResponse = {...};`.
	HTMLVars []string `json:"html_vars"`
}

// Default is the built-in rule set.
var Default = Rules{
	Paths: []string{
		"/youtubei/v1/player",
		"/youtubei/v1/next",
		"/youtubei/v1/browse",
		"/youtubei/v1/search",
	},
	Keys: []string{
		"adPlacements",
		"adSlots",
		"playerAds",
		"adBreakHeartbeatParams",
	},
	HTMLVars: []string{
		"ytInitialPlayerResponse",
		"ytInitialData",
	},
}

// Matches reports whether responses for this URL path should be pruned.
func (r Rules) Matches(path string) bool {
	for _, p := range r.Paths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// JSON deletes every key in r.Keys from body. It returns the new body and how
// many keys were removed. If nothing was removed, or body isn't valid JSON,
// the original bytes are returned unchanged.
func (r Rules) JSON(body []byte) ([]byte, int, error) {
	return r.prune(body, false)
}

// HTML prunes the JSON assigned to each of r.HTMLVars inside a page. Pages
// it can't parse are returned unchanged.
func (r Rules) HTML(page []byte) ([]byte, int) {
	total := 0
	for _, name := range r.HTMLVars {
		var n int
		page, n = r.pruneVar(page, name)
		total += n
	}
	return page, total
}

func (r Rules) pruneVar(page []byte, name string) ([]byte, int) {
	var out bytes.Buffer
	total := 0
	rest := page
	for {
		i := bytes.Index(rest, []byte(name))
		if i < 0 {
			out.Write(rest)
			break
		}
		after := i + len(name)
		start := jsonStart(rest, after)
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
		// Escape <, > and & so the JSON can't close the <script> tag.
		if pruned, n, err := r.prune(rest[start:end], true); err == nil && n > 0 {
			out.Write(pruned)
			total += n
		} else {
			out.Write(rest[start:end])
		}
		rest = rest[end:]
	}
	if total == 0 {
		return page, 0
	}
	return out.Bytes(), total
}

// jsonStart checks that the text at pos looks like ` = {` (optionally after
// `"]` for `window["name"] = {`) and returns the index of the `{`, or -1.
func jsonStart(b []byte, pos int) int {
	p := pos
	if p < len(b) && (b[p] == '"' || b[p] == '\'') {
		p++
	}
	if p < len(b) && b[p] == ']' {
		p++
	}
	p = skipSpace(b, p)
	if p >= len(b) || b[p] != '=' {
		return -1
	}
	p++
	if p < len(b) && b[p] == '=' { // a comparison, not an assignment
		return -1
	}
	p = skipSpace(b, p)
	if p >= len(b) || b[p] != '{' {
		return -1
	}
	return p
}

func skipSpace(b []byte, p int) int {
	for p < len(b) && (b[p] == ' ' || b[p] == '\t' || b[p] == '\n' || b[p] == '\r') {
		p++
	}
	return p
}

func (r Rules) prune(body []byte, escapeHTML bool) ([]byte, int, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep large integers exact
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return body, 0, err
	}

	keys := make(map[string]bool, len(r.Keys))
	for _, k := range r.Keys {
		keys[k] = true
	}
	removed := walk(doc, keys)
	if removed == 0 {
		return body, 0, nil
	}

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(doc); err != nil {
		return body, 0, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), removed, nil
}

func walk(v any, keys map[string]bool) int {
	n := 0
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if keys[k] {
				delete(t, k)
				n++
				continue
			}
			n += walk(child, keys)
		}
	case []any:
		for _, child := range t {
			n += walk(child, keys)
		}
	}
	return n
}
