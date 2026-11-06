// Package sites blocks ads on websites other than YouTube by refusing
// connections to known ad and tracker domains. Nothing is decrypted.
//
// YouTube is handled entirely by the existing YouTube code (internal/proxy);
// this package never blocks or changes YouTube traffic.
package sites

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"shoo/internal/certs"
)

// File names inside the data directory.
const (
	BlocklistFile = "blocklist.txt" // downloaded list (update-lists)
	BlockFile     = "block.txt"     // domains the user added
	AllowFile     = "allow.txt"     // domains the user never wants blocked
)

// protected domains are never blocked, so YouTube keeps working exactly as
// the YouTube code expects: the site, its API, video stream, and images.
var protected = append([]string{
	"youtube.com",
	"youtube-nocookie.com",
	"googlevideo.com",
	"ytimg.com",
	"ggpht.com",
	"youtubei.googleapis.com",
}, certs.AllowedDomains...)

// IsYouTube reports whether host belongs to YouTube and must be left alone.
func IsYouTube(host string) bool {
	return inSuffixSet(toSet(protected), normalize(host))
}

// List decides which hosts are blocked.
type List struct {
	blocked map[string]struct{}
	allowed map[string]struct{}
	prot    map[string]struct{}
}

// NewList builds a list. Blocking a domain also blocks its subdomains;
// allowed and YouTube domains always win.
func NewList(blocked, allowed []string) *List {
	l := &List{blocked: map[string]struct{}{}, allowed: map[string]struct{}{}, prot: toSet(protected)}
	for _, d := range blocked {
		if d = normalize(d); validDomain(d) {
			l.blocked[d] = struct{}{}
		}
	}
	for _, d := range allowed {
		if d = normalize(d); validDomain(d) {
			l.allowed[d] = struct{}{}
		}
	}
	return l
}

// Blocked reports whether connections to host should be refused.
func (l *List) Blocked(host string) bool {
	host = normalize(host)
	if inSuffixSet(l.prot, host) || inSuffixSet(l.allowed, host) {
		return false
	}
	return inSuffixSet(l.blocked, host)
}

// Len is the number of blocked entries.
func (l *List) Len() int { return len(l.blocked) }

// Blocked domains for the PAC file: sorted, without entries already covered
// by a blocked parent domain, and without YouTube domains.
func (l *List) pacBlocked() []string {
	var out []string
	for d := range l.blocked {
		if inSuffixSet(l.prot, d) {
			continue
		}
		if i := strings.IndexByte(d, '.'); i >= 0 && inSuffixSet(l.blocked, d[i+1:]) {
			continue // parent already blocked
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func (l *List) pacAllowed() []string   { return sortedKeys(l.allowed) }
func (l *List) pacProtected() []string { return sortedKeys(l.prot) }

// Load reads the downloaded list and the user's block/allow files from dir.
// Missing files are treated as empty.
func Load(dir string) (*List, error) {
	var blocked, allowed []string
	for _, f := range []string{BlocklistFile, BlockFile} {
		d, err := readDomainsFile(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		blocked = append(blocked, d...)
	}
	allowed, err := readDomainsFile(filepath.Join(dir, AllowFile))
	if err != nil {
		return nil, err
	}
	return NewList(blocked, allowed), nil
}

func readDomainsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseHosts(f)
}

// ParseHosts reads a hosts-format list ("0.0.0.0 ads.example.com") or a plain
// list with one domain per line. Comments and localhost entries are skipped.
func ParseHosts(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if isSinkAddress(fields[0]) {
			fields = fields[1:]
		} else if len(fields) > 1 {
			continue // a hosts line pointing somewhere real; not a block entry
		}
		for _, d := range fields {
			if d = normalize(d); validDomain(d) && !isLocalName(d) {
				out = append(out, d)
			}
		}
	}
	return out, sc.Err()
}

// ValidateDomain checks a domain typed by the user.
func ValidateDomain(d string) (string, error) {
	d = normalize(d)
	if !validDomain(d) {
		return "", fmt.Errorf("%q is not a domain name like ads.example.com", d)
	}
	return d, nil
}

func isSinkAddress(s string) bool {
	switch s {
	case "0.0.0.0", "127.0.0.1", "::", "::1", "0":
		return true
	}
	return false
}

func isLocalName(d string) bool {
	switch d {
	case "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0":
		return true
	}
	return false
}

func normalize(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// validDomain allows letters, digits, '-', '_' and '.', with at least one dot.
func validDomain(d string) bool {
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	for _, c := range d {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// inSuffixSet reports whether host or any parent domain of it is in set.
func inSuffixSet(set map[string]struct{}, host string) bool {
	for h := host; h != ""; {
		if _, ok := set[h]; ok {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return false
}

func toSet(list []string) map[string]struct{} {
	s := make(map[string]struct{}, len(list))
	for _, d := range list {
		s[normalize(d)] = struct{}{}
	}
	return s
}

func sortedKeys(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
