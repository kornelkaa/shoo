// Package sites decides what the proxy does with each website: which ad and
// tracker domains are blocked, and which sites are never decrypted (logins,
// banks, Apple services, ...). It also makes the PAC file that sends
// browsers through the proxy.
//
// YouTube's own domains are never blocked.
package sites

import (
	"bufio"
	_ "embed"
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
	SkipFile      = "skip.txt"      // domains the user never wants decrypted
)

//go:embed exclusions.txt
var exclusionsTxt string

// Exclusions are the built-in sites that are never decrypted.
func Exclusions() []string {
	d, _ := ParseHosts(strings.NewReader(exclusionsTxt + "\n" + platformExclusions))
	return d
}

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

// youtubeAds are YouTube's ad-only hosts: blocked like any ad domain (if a
// list has them), though they're under youtube.com. Nothing YouTube's pages
// or player need is served from them.
var youtubeAds = toSet([]string{"ads.youtube.com"})

// IsYouTube reports whether host belongs to YouTube and must be left alone.
func IsYouTube(host string) bool {
	host = normalize(host)
	return inSuffixSet(toSet(protected), host) && !inSuffixSet(youtubeAds, host)
}

// protectedHost reports whether host is one of YouTube's own hosts.
func (l *List) protectedHost(host string) bool {
	return inSuffixSet(l.prot, host) && !inSuffixSet(youtubeAds, host)
}

// List decides which hosts are blocked.
type List struct {
	blocked map[string]struct{}
	allowed map[string]struct{}
	prot    map[string]struct{}
	skip    map[string]struct{} // never decrypted
}

// NewList builds a list. Blocking a domain also blocks its subdomains;
// allowed and YouTube domains always win.
func NewList(blocked, allowed []string) *List {
	l := &List{blocked: map[string]struct{}{}, allowed: map[string]struct{}{}, prot: toSet(protected), skip: toSet(Exclusions())}
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
	if l.protectedHost(host) || inSuffixSet(l.allowed, host) {
		return false
	}
	return inSuffixSet(l.blocked, host)
}

// Exempt reports whether host must never be blocked, not even one URL of
// it: YouTube (handled by its own code) and domains the user allowed.
func (l *List) Exempt(host string) bool {
	host = normalize(host)
	return l.protectedHost(host) || inSuffixSet(l.allowed, host)
}

// Decrypt reports whether the proxy may decrypt host (to block ads in it and
// hide ad boxes), i.e. it isn't on the never-decrypt list.
func (l *List) Decrypt(host string) bool {
	return !inSuffixSet(l.skip, normalize(host))
}

// AddSkip adds domains that are never decrypted.
func (l *List) AddSkip(domains []string) {
	for _, d := range domains {
		if d = normalize(d); validDomain(d) {
			l.skip[d] = struct{}{}
		}
	}
}

// Len is the number of blocked entries.
func (l *List) Len() int { return len(l.blocked) }

func (l *List) pacSkip() []string { return sortedKeys(l.skip) }

// SkipDomains are all never-decrypted domains: built-in and the user's own.
func (l *List) SkipDomains() []string { return sortedKeys(l.skip) }

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
	skip, err := readDomainsFile(filepath.Join(dir, SkipFile))
	if err != nil {
		return nil, err
	}
	l := NewList(blocked, allowed)
	l.AddSkip(skip)
	return l, nil
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
