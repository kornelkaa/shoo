// Package filterlist reads EasyList-style filter lists line by line.
//
// uBlock Origin's lists use preprocessor directives: "!#if env_xxx" ...
// "!#endif" blocks meant for particular browsers, and "!#include file".
// Rules inside !#if blocks are skipped (they target other browsers or
// features shoo doesn't have), and includes aren't followed.
package filterlist

import (
	"bufio"
	"io"
	"strings"
)

// Scan calls fn with each rule line (trimmed), skipping blank lines,
// comments, "[Adblock Plus]" headers and !#if blocks.
func Scan(r io.Reader, fn func(line string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	depth := 0 // nesting of !#if blocks
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "!#if"):
			depth++
			continue
		case strings.HasPrefix(line, "!#endif"):
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth > 0 || line == "" || line[0] == '!' || line[0] == '[' {
			continue
		}
		fn(line)
	}
	return sc.Err()
}
